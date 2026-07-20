"""Command-execution ingest via the Linux audit log.

Closes the biggest blind spot: Shallots did not see commands as they ran (the
process/posture scans are polls, so short-lived commands slipped between samples).
This tails auditd's EXECVE records - every exec, in real time - reassembles the
command line, and scores it with the lexicon ranker. Only the suspicious tail
(score >= emit threshold) becomes an alert; the benign 99% is counted and dropped,
so capturing everything does not flood the DB. That suppression-at-source is what
makes execve capture viable on a small box.

Requires an auditd execve rule keyed "shallots_exec" (see setup/audit/
shallots-exec.rules). No rule -> nothing to read -> harmless no-op.
"""
from __future__ import annotations

import asyncio
import binascii
import logging
import os
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from shallots.config import ExecMonConfig

from shallots.ai.lexicon_ranker import LexiconRanker
from shallots.store.models import Alert, now_iso

log = logging.getLogger(__name__)

_AUDIT_ID = re.compile(r"audit\((\d+\.\d+):(\d+)\)")
_FIELD = re.compile(r"(\w+)=((?:\"[^\"]*\")|(?:\S+))")

# comm names we never care about scoring (the monitor's own plumbing + ultra-common
# shell builtins that auditd still logs). Keeps the counted-and-dropped path cheap.
_IGNORE_COMM = {"auditctl", "ausearch", "auditd"}


def _unq(v: str) -> str:
    return v[1:-1] if len(v) >= 2 and v[0] == '"' and v[-1] == '"' else v


def _decode_arg(v: str) -> str:
    """EXECVE args are quoted when printable, hex-encoded otherwise."""
    if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
        return v[1:-1]
    if v and len(v) % 2 == 0 and re.fullmatch(r"[0-9A-Fa-f]+", v):
        try:
            return binascii.unhexlify(v).decode("utf-8", "replace")
        except (binascii.Error, ValueError):
            return v
    return v


def parse_exec_events(lines: list[str]) -> list[dict]:
    """Correlate SYSCALL + EXECVE records (same audit id) into exec events.

    Pure function over log lines so it is unit-testable without auditd. Returns
    dicts: {ts, serial, pid, ppid, uid, auid, comm, exe, key, cmdline}.
    """
    syscalls: dict[str, dict] = {}
    execves: dict[str, list[str]] = {}
    for ln in lines:
        m = _AUDIT_ID.search(ln)
        if not m:
            continue
        serial = m.group(2)
        fields = {k: _unq(val) for k, val in _FIELD.findall(ln)}
        if "type=SYSCALL" in ln or fields.get("type") == "SYSCALL":
            if fields.get("key") in ("shallots_exec", '"shallots_exec"') or fields.get("syscall") in ("59", "322"):
                syscalls[serial] = {
                    "ts": m.group(1), "serial": serial,
                    "pid": fields.get("pid", ""), "ppid": fields.get("ppid", ""),
                    "uid": fields.get("uid", ""), "auid": fields.get("auid", ""),
                    "comm": fields.get("comm", ""), "exe": fields.get("exe", ""),
                    "success": fields.get("success", "yes"), "key": fields.get("key", ""),
                }
        elif "type=EXECVE" in ln or fields.get("type") == "EXECVE":
            args = []
            i = 0
            raw = dict(_FIELD.findall(ln))
            while f"a{i}" in raw:
                args.append(_decode_arg(raw[f"a{i}"]))
                i += 1
            execves[serial] = args

    events = []
    for serial, sc in syscalls.items():
        args = execves.get(serial, [])
        sc["cmdline"] = " ".join(args) if args else sc.get("exe", "")
        events.append(sc)
    return events


class ExecLogIngestor:
    def __init__(self, config: "ExecMonConfig", queue: asyncio.Queue,
                 ranker: LexiconRanker | None = None) -> None:
        self.cfg = config
        self.queue = queue
        self.ranker = ranker or (
            LexiconRanker.from_file(config.lexicon_path,
                                    escalate_threshold=config.escalate_threshold,
                                    investigate_threshold=config.investigate_threshold)
            if config.lexicon_path else
            LexiconRanker(escalate_threshold=config.escalate_threshold,
                          investigate_threshold=config.investigate_threshold))
        self._offset = 0
        self._inode = None
        self.scanned = 0     # total execs seen (for stats/"we watched N commands")
        self.emitted = 0     # alerts raised

    async def run(self) -> None:
        path = self.cfg.audit_log_path
        log.info("ExecLog ingestor watching %s (emit >= score %d)", path, self.cfg.emit_min_score)
        while True:
            try:
                await self._tail_once(path)
            except asyncio.CancelledError:
                return
            except Exception:
                log.exception("ExecLog ingestor: read cycle failed")
            try:
                await asyncio.sleep(self.cfg.poll_seconds)
            except asyncio.CancelledError:
                return

    async def _tail_once(self, path: str) -> None:
        if not os.path.exists(path):
            return
        st = os.stat(path)
        if self._inode is not None and st.st_ino != self._inode:
            self._offset = 0                       # rotated
        self._inode = st.st_ino
        if st.st_size < self._offset:
            self._offset = 0                       # truncated
        if st.st_size == self._offset:
            return
        with open(path, "r", errors="replace") as f:
            f.seek(self._offset)
            chunk = f.read()
            self._offset = f.tell()
        lines = chunk.splitlines()
        for ev in parse_exec_events(lines):
            if ev.get("success") == "no":
                continue
            comm = ev.get("comm", "")
            if comm in _IGNORE_COMM:
                continue
            self.scanned += 1
            cmd = ev.get("cmdline", "")
            ctx = {
                "writable_path": ev.get("exe", "").startswith(("/tmp/", "/dev/shm/", "/var/tmp/")),
                "service_account": ev.get("auid") in ("4294967295", "-1", ""),  # no login uid
            }
            res = self.ranker.score(cmd, context=ctx)
            if res.score < self.cfg.emit_min_score:
                continue                            # benign: counted and dropped
            verdict = self.ranker.verdict(res)
            severity = {"escalate": "critical", "investigate": "medium"}.get(verdict, "low")
            await self.queue.put(Alert(
                timestamp=now_iso(),
                source="auditd",
                source_ref=f"exec:{ev.get('serial','')}",
                severity=severity,
                title=f"Suspicious command: {comm or 'exec'}",
                description=f"{cmd}  (uid={ev.get('uid')} ppid={ev.get('ppid')} exe={ev.get('exe')})",
                category="execution",
                signature_id=hash(tuple(res.tags)) & 0x7FFFFFFF,
                raw=f'{{"cmdline": {cmd!r}, "lexicon_score": {res.score}, "tags": {res.tags}}}',
                ai_reasoning=f"lexicon score {res.score}: {res.top_reason} [{', '.join(res.tags)}]",
            ))
            self.emitted += 1
            log.info("ExecLog: emitted %s alert (score=%d): %s", severity, res.score, cmd[:80])
