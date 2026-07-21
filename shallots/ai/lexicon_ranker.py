"""Lexicon ranker - cheap, deterministic suspicion scoring for command lines.

The idea (borrowed from difficulty-routing lexicons): keep a dictionary of
suspicious tokens/patterns, each with a weight, and score a piece of text by
summing the weights of what it matches, then adjusting for context (who ran it,
from where, how rare it is). No LLM in the hot path - every command can be scored
in microseconds, so you can capture EVERY execution and only escalate the small
suspicious tail. This is what makes execve capture viable without drowning.

It is evidence-of-badness scoring, not proof. A high score means "a human (or the
AI tier) should look," not "confirmed malicious." Tuned suppression-first: benign
commands score ~0 and get suppressed; the sketchy ones cross the threshold.

The default lexicon covers the classic Linux/Windows attacker command shapes:
reverse shells, download-and-execute, encoding/obfuscation, credential access,
discovery, defense evasion, and persistence. Operators can extend/override it via
a JSON file (see shallots/data/exec_lexicon.json and LexiconRanker.from_file).
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class LexTerm:
    pattern: str              # regex, matched case-insensitively against the text
    weight: int               # points added when it matches
    tag: str                  # MITRE-ish bucket: reverse_shell, download_exec, ...
    desc: str = ""            # human-readable "why this is suspicious"
    _rx: re.Pattern | None = field(default=None, repr=False, compare=False)

    def compile(self) -> "LexTerm":
        self._rx = re.compile(self.pattern, re.IGNORECASE)
        return self


# ---------------------------------------------------------------------------
# Default lexicon. Weights are additive; ~40 is the default escalate threshold.
# A single unambiguous attacker primitive (reverse shell, curl|bash) should be
# able to cross it alone; softer signals need to stack.
# ---------------------------------------------------------------------------
_DEFAULT: list[dict[str, Any]] = [
    # --- reverse shells / bind shells (unambiguous) ---
    {"pattern": r"/dev/(tcp|udp)/", "weight": 45, "tag": "reverse_shell", "desc": "bash /dev/tcp network redirect"},
    {"pattern": r"\bnc(?:at)?\b[^|;&]*\s-[a-z]*e\b", "weight": 45, "tag": "reverse_shell", "desc": "netcat -e command exec"},
    {"pattern": r"\bnc(?:at)?\b[^|;&]*\s-[a-z]*c\b", "weight": 35, "tag": "reverse_shell", "desc": "ncat -c command exec"},
    {"pattern": r"(sh|bash)\s+-i\b.*(>&|2>&1).*(tcp|/dev/)", "weight": 45, "tag": "reverse_shell", "desc": "interactive shell redirected to socket"},
    {"pattern": r"socat\b.*\bexec:", "weight": 45, "tag": "reverse_shell", "desc": "socat exec reverse shell"},
    {"pattern": r"python[0-9.]*\s+-c[^\n]*socket[^\n]*(connect|pty)", "weight": 42, "tag": "reverse_shell", "desc": "python socket reverse shell one-liner"},
    {"pattern": r"pty\.spawn", "weight": 20, "tag": "reverse_shell", "desc": "python pty.spawn (shell upgrade)"},
    # --- download and execute ---
    {"pattern": r"(curl|wget|fetch)\b[^\n|;&]*\|\s*(sh|bash|python|perl|node|zsh)", "weight": 45, "tag": "download_exec", "desc": "pipe remote script straight into an interpreter"},
    {"pattern": r"(curl|wget)\b[^\n]*(-o|-O|--output)[^\n]*/(tmp|dev/shm|var/tmp)/", "weight": 30, "tag": "download_exec", "desc": "download into a world-writable dir"},
    {"pattern": r"\b(certutil|bitsadmin)\b.*(urlcache|transfer|/download)", "weight": 40, "tag": "download_exec", "desc": "Windows LOLBin download"},
    {"pattern": r"\bIEX\b|Invoke-Expression|Invoke-WebRequest|DownloadString|DownloadFile", "weight": 35, "tag": "download_exec", "desc": "PowerShell download/exec"},
    # --- encoding / obfuscation ---
    {"pattern": r"\bbase64\b[^\n]*(-d|--decode)", "weight": 25, "tag": "obfuscation", "desc": "base64 decode (payload staging)"},
    {"pattern": r"echo\s+[A-Za-z0-9+/]{40,}={0,2}\s*\|\s*base64", "weight": 30, "tag": "obfuscation", "desc": "base64 blob decoded then likely run"},
    {"pattern": r"powershell[^\n]*\s-e(nc(odedcommand)?)?\s+[A-Za-z0-9+/]{20,}", "weight": 40, "tag": "obfuscation", "desc": "PowerShell -EncodedCommand"},
    {"pattern": r"\b(xxd|hexdump)\b.*-r", "weight": 15, "tag": "obfuscation", "desc": "hex decode"},
    {"pattern": r"eval\s*\(?\s*\$\(", "weight": 20, "tag": "obfuscation", "desc": "eval of command substitution"},
    # --- staging in writable dirs + make executable ---
    {"pattern": r"chmod\s+[0-7]*[157][0-7]*\s+/(tmp|dev/shm|var/tmp)/", "weight": 30, "tag": "staging", "desc": "chmod +x a file in a writable dir"},
    {"pattern": r"chmod\s+\+x\s+/(tmp|dev/shm|var/tmp|home)/", "weight": 28, "tag": "staging", "desc": "chmod +x in writable dir"},
    {"pattern": r"^/?(tmp|dev/shm|var/tmp)/\.?[a-z0-9_.-]+\s*$", "weight": 22, "tag": "staging", "desc": "executing a binary straight out of a writable dir"},
    # --- credential access ---
    {"pattern": r"\b(cat|less|cp|scp)\b[^\n]*/etc/shadow\b", "weight": 40, "tag": "cred_access", "desc": "reading /etc/shadow"},
    {"pattern": r"\bgetent\s+shadow\b", "weight": 38, "tag": "cred_access", "desc": "getent shadow (hash dump)"},
    {"pattern": r"(mimikatz|lsass|procdump[^\n]*lsass|sekurlsa)", "weight": 45, "tag": "cred_access", "desc": "LSASS/mimikatz credential dumping"},
    {"pattern": r"(\.aws/credentials|\.ssh/id_(rsa|ed25519)|\.docker/config\.json|\.kube/config)", "weight": 22, "tag": "cred_access", "desc": "reading a secrets file"},
    {"pattern": r"history\s+-c|rm\s+[^\n]*\.bash_history|unset\s+HISTFILE", "weight": 30, "tag": "defense_evasion", "desc": "clearing shell history"},
    # --- defense evasion / anti-forensics ---
    {"pattern": r"(iptables|nft|ufw)\b[^\n]*(flush|-F|disable)", "weight": 20, "tag": "defense_evasion", "desc": "flushing/disabling the firewall"},
    {"pattern": r"systemctl\s+(stop|disable|mask)\s+(auditd|wazuh|falcon|osquery|clamav|argus|shallot)", "weight": 42, "tag": "defense_evasion", "desc": "stopping a security agent"},
    {"pattern": r"(setenforce\s+0|selinux=disabled|apparmor.*teardown)", "weight": 22, "tag": "defense_evasion", "desc": "disabling MAC (SELinux/AppArmor)"},
    {"pattern": r"\btouch\b[^\n]*-[a-z]*t\b|timestomp", "weight": 15, "tag": "defense_evasion", "desc": "timestamp manipulation"},
    # --- persistence ---
    # crontab -l (list) and -r (remove) don't add anything; only -e (edit),
    # -u user -e, or replacing from a file add an entry. The old bare
    # "crontab\s+-" matched -l too, flagging every routine "crontab -l"
    # check (e.g. an unrelated tool inspecting its own schedule) as a
    # persistence attempt.
    {"pattern": r"(crontab\s+(?!-l\b|-r\b)\S|>>\s*/etc/cron|/etc/cron\.[a-z]+/)", "weight": 22, "tag": "persistence", "desc": "adding a cron entry"},
    {"pattern": r"(>>\s*~?/\.(bashrc|profile|zshrc)|/etc/rc\.local|LD_PRELOAD=)", "weight": 22, "tag": "persistence", "desc": "shell/loader persistence"},
    {"pattern": r"(useradd|adduser)\b[^\n]*(-u\s*0|-o|--uid\s*0)|usermod\b[^\n]*sudo", "weight": 35, "tag": "persistence", "desc": "creating a uid-0 / sudo user"},
    {"pattern": r"authorized_keys", "weight": 18, "tag": "persistence", "desc": "writing an SSH authorized_keys entry"},
    # --- discovery (soft signals; need to stack) ---
    {"pattern": r"\b(whoami|id|hostname|uname\s+-a)\b", "weight": 4, "tag": "discovery", "desc": "basic host recon"},
    {"pattern": r"\b(nmap|masscan)\b", "weight": 18, "tag": "discovery", "desc": "network scanning tool"},
    {"pattern": r"\b(ss|netstat)\b[^\n]*-[a-z]*(tnlp|antp)", "weight": 6, "tag": "discovery", "desc": "listing listeners"},
    {"pattern": r"cat\s+/etc/(passwd|hosts)\b", "weight": 6, "tag": "discovery", "desc": "reading passwd/hosts"},
    # --- privilege escalation attempts ---
    {"pattern": r"sudo\s+-l\b|pkexec\b|find\b[^\n]*-perm[^\n]*(4000|-u=s)", "weight": 12, "tag": "priv_esc", "desc": "SUID / sudo enumeration"},
    {"pattern": r"(unshare|nsenter)\b[^\n]*(--mount|--pid|-r|/bin/sh)", "weight": 20, "tag": "priv_esc", "desc": "namespace escape primitive"},
]


@dataclass
class ScoreResult:
    score: int
    hits: list[dict[str, Any]]           # [{tag, weight, desc, match}]
    tags: list[str]

    @property
    def top_reason(self) -> str:
        if not self.hits:
            return ""
        best = max(self.hits, key=lambda h: h["weight"])
        return best["desc"] or best["tag"]


class LexiconRanker:
    """Scores text (a command line, a log message) against the suspicion lexicon.

    Context multipliers make the same command more suspicious in the wrong place:
    a shell spawned by a webserver, a command from a service account, or a
    first-ever-seen invocation all bump the score.
    """

    def __init__(self, terms: list[LexTerm] | None = None,
                 escalate_threshold: int = 40, investigate_threshold: int = 15) -> None:
        self.terms = [t.compile() for t in (terms or [LexTerm(**d) for d in _DEFAULT])]
        self.escalate_threshold = escalate_threshold
        self.investigate_threshold = investigate_threshold

    @classmethod
    def from_file(cls, path: str | Path, **kw) -> "LexiconRanker":
        """Load a lexicon JSON (list of {pattern,weight,tag,desc}); falls back to
        the built-in defaults if the file is missing or unreadable."""
        try:
            data = json.loads(Path(path).read_text())
            terms = [LexTerm(pattern=d["pattern"], weight=int(d["weight"]),
                             tag=d.get("tag", "custom"), desc=d.get("desc", "")) for d in data]
            return cls(terms=terms, **kw)
        except (OSError, ValueError, KeyError):
            return cls(**kw)

    def score(self, text: str, context: dict[str, Any] | None = None) -> ScoreResult:
        text = text or ""
        hits: list[dict[str, Any]] = []
        total = 0
        seen_tags: set[str] = set()
        for t in self.terms:
            m = t._rx.search(text) if t._rx else None
            if m:
                total += t.weight
                seen_tags.add(t.tag)
                hits.append({"tag": t.tag, "weight": t.weight, "desc": t.desc,
                             "match": m.group(0)[:80]})

        # Cross-tactic bonus: hits spanning >=2 different tactics (e.g. download
        # AND persistence) is a chain, not one noisy match.
        if len(seen_tags) >= 2:
            total = int(total * 1.25)

        # Context multipliers (all optional).
        if context:
            # parent process is a network-facing service = shell from a daemon
            parent = str(context.get("parent_comm", "")).lower()
            if parent in {"nginx", "apache2", "httpd", "php-fpm", "node", "sshd", "postgres", "mysqld"}:
                total = int(total * 1.4)
            # running as a service/non-login user doing shell-y things
            if context.get("service_account"):
                total = int(total * 1.2)
            # never-seen-before command on this host
            if context.get("first_seen"):
                total = int(total * 1.15)
            # executable lives in a world-writable dir
            if context.get("writable_path"):
                total += 12

        return ScoreResult(score=total, hits=hits, tags=sorted(seen_tags))

    def verdict(self, result: ScoreResult) -> str:
        """Map a score to a triage verdict (suppress|investigate|escalate)."""
        if result.score >= self.escalate_threshold:
            return "escalate"
        if result.score >= self.investigate_threshold:
            return "investigate"
        return "suppress"
