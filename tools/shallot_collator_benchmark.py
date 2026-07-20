#!/usr/bin/env python3
"""Benchmark whether downstream collator cards help an upstream agent.

The benchmark uses curated noisy windows. Raw mode gives the upstream model only
the alert batch. Collated mode gives downstream scout/collator cards with local
fleet facts and candidate reasons. The score is alert-level precision/recall
against explicit window labels, so this tests the pipeline claim directly:
does a cheap/local collator reduce noise and preserve missed signals for a
stronger upstream reviewer?
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


REPO = Path("/home/user/security-shallots")

SYSTEM = """You are an upstream Security Shallots reviewer.
Your job is not to decide benign or malicious. Your job is to pick which items
should remain visible for higher-tier review because they may be missed by
ordinary alert handling.

Constraints:
- You have a strict review budget.
- Return only valid JSON.
- Select an alert only if the provided input contains a concrete reason it might
  be missed otherwise.
- Be conservative: high severity alone is not enough, and scary words alone are
  not enough.
- A port number, IP address, or single low-detail event is not enough unless the
  input also provides local role, baseline, source-integrity, or rarity context.
- Do not invent local network roles or baselines that are not in the input."""


@dataclass(frozen=True)
class Scenario:
    id: str
    description: str
    budget: int
    expected_ids: tuple[str, ...]
    alerts: tuple[dict[str, Any], ...]
    collator_cards: tuple[dict[str, Any], ...]


def alert(
    id: str,
    title: str,
    source: str = "suricata",
    severity: str = "medium",
    verdict: str = "suppress",
    src_ip: str = "",
    dst_ip: str = "",
    dst_port: int = 0,
    category: str = "Misc activity",
    proto: str = "TCP",
    extra: str = "",
) -> dict[str, Any]:
    return {
        "id": id,
        "source": source,
        "severity": severity,
        "verdict": verdict,
        "title": title,
        "category": category,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "proto": proto,
        "extra": extra,
    }


SCENARIOS: tuple[Scenario, ...] = (
    Scenario(
        id="context_required_allowed_ssh",
        description="A bland allowed-flow alert needs corpus facts to become a missed-signal candidate.",
        budget=2,
        expected_ids=("flow-ssh-host01",),
        alerts=(
            alert("flow-web-1", "Allowed outbound TCP session", source="syslog", severity="low", verdict="suppress", src_ip="192.168.0.172", dst_ip="172.64.41.3", dst_port=443, category="firewall/session"),
            alert("flow-dns-1", "Allowed outbound UDP session", source="syslog", severity="low", verdict="suppress", src_ip="192.168.0.172", dst_ip="8.8.8.8", dst_port=53, category="firewall/session", proto="UDP"),
            alert("flow-ssh-host01", "Allowed outbound TCP session", source="syslog", severity="low", verdict="suppress", src_ip="192.168.0.172", dst_ip="192.168.2.177", dst_port=22, category="firewall/session"),
            alert("flow-web-2", "Allowed outbound TCP session", source="syslog", severity="low", verdict="suppress", src_ip="192.168.0.125", dst_ip="140.82.112.3", dst_port=443, category="firewall/session"),
            alert("flow-dns-2", "Allowed outbound UDP session", source="syslog", severity="low", verdict="suppress", src_ip="192.168.0.224", dst_ip="192.168.0.172", dst_port=53, category="firewall/session", proto="UDP"),
        ),
        collator_cards=(
            {
                "alert_id": "flow-ssh-host01",
                "score": 4,
                "mechanical_reasons": ["internal_management_port:22", "first_seen_src_dst_port_tuple_30d", "control_plane_host_egress"],
                "local_facts": [
                    "192.168.0.172 is Host01, the Security Shallots control-plane host.",
                    "192.168.2.177 is outside the normal 192.168.0.0/24 home segment.",
                    "Port 22 is a management port.",
                    "This src/dst/port tuple is first-seen in the 30-day baseline.",
                ],
                "note": "The raw event is bland, but local role and rarity make it a candidate missed signal.",
            },
        ),
    ),
    Scenario(
        id="context_required_single_router_mismatch",
        description="A single low-severity syslog line needs known-source corpus context.",
        budget=2,
        expected_ids=("router-single-mismatch",),
        alerts=(
            alert("router-single-mismatch", "Syslog [user]", source="syslog", severity="low", verdict="suppress", src_ip="192.168.0.55", category="syslog/user", proto=""),
            alert("syslog-normal-1", "System log forwarded", source="syslog", severity="low", verdict="suppress", src_ip="192.168.0.212", category="syslog/info", proto=""),
            alert("syslog-normal-2", "DHCP lease renewed", source="syslog", severity="low", verdict="suppress", src_ip="192.168.0.1", category="syslog/info", proto=""),
        ),
        collator_cards=(
            {
                "alert_id": "router-single-mismatch",
                "score": 3,
                "mechanical_reasons": ["router_syslog_source_mismatch", "known_noise_pattern_wrong_source"],
                "local_facts": [
                    "D-Link router Syslog [user] messages are expected only from 192.168.0.1.",
                    "Routine Syslog [user] messages from 192.168.0.1 are known noise.",
                    "This message used that known router-noise pattern but arrived from 192.168.0.55.",
                ],
                "note": "The alert title is routine; the source mismatch is the signal.",
            },
        ),
    ),
    Scenario(
        id="context_required_control_plane_rmm",
        description="A common RMM DNS signature becomes relevant only when local role and baseline are known.",
        budget=2,
        expected_ids=("rmm-control-plane-single",),
        alerts=(
            alert("rmm-control-plane-single", "ET INFO Remote Monitoring and Management Tool in DNS Lookup", src_ip="192.168.0.172", dst_ip="8.8.8.8", dst_port=53, proto="UDP"),
            alert("doh-single", "ET INFO Observed Cloudflare DNS over HTTPS Domain", src_ip="192.168.0.172", dst_ip="172.64.41.3", dst_port=443),
            alert("tunnel-single", "ET INFO DNS Query to Cloudflare Tunneling Domain", src_ip="192.168.0.224", dst_ip="192.168.0.172", dst_port=53, proto="UDP"),
        ),
        collator_cards=(
            {
                "alert_id": "rmm-control-plane-single",
                "score": 3,
                "mechanical_reasons": ["suppressed_but_rare", "control_plane_host_rmm_lookup"],
                "local_facts": [
                    "192.168.0.172 is Host01, the Security Shallots control-plane host.",
                    "RMM DNS lookups from workstations are common in this fleet.",
                    "RMM DNS lookup originating from Host01 is rare in the 30-day baseline.",
                ],
                "note": "Common signature, uncommon local role/source combination.",
            },
        ),
    ),
    Scenario(
        id="ssh_buried_in_suppressed_noise",
        description="Suppressed Suricata noise contains one outbound SSH management-port candidate from the security node.",
        budget=2,
        expected_ids=("ssh-1",),
        alerts=(
            alert("dns-1", "ET INFO Observed Cloudflare DNS over HTTPS Domain", src_ip="192.168.0.172", dst_ip="172.64.41.3", dst_port=443),
            alert("dns-2", "ET INFO DNS Query to Cloudflare Tunneling Domain", src_ip="192.168.0.224", dst_ip="192.168.0.172", dst_port=53, proto="UDP"),
            alert("rmm-1", "ET INFO Remote Monitoring and Management Tool in DNS Lookup", src_ip="192.168.0.129", dst_ip="192.168.0.172", dst_port=53, proto="UDP"),
            alert("stream-1", "SURICATA STREAM 3way handshake SYN/ACK ignored TFO data", src_ip="8.8.8.8", dst_ip="192.168.0.172", dst_port=44584, category="Generic Protocol Command Decode"),
            alert("syslog-1", "Syslog [user]", source="syslog", severity="low", src_ip="192.168.0.1", proto=""),
            alert("ssh-1", "ET SCAN Potential SSH Scan OUTBOUND", severity="high", src_ip="192.168.0.172", dst_ip="192.168.2.177", dst_port=22, category="Attempted Information Leak"),
            alert("dns-3", "ET INFO Observed Cloudflare DNS over HTTPS Domain", src_ip="192.168.0.172", dst_ip="162.159.61.3", dst_port=443),
            alert("rmm-2", "ET INFO Remote Monitoring and Management Tool in DNS Lookup", src_ip="192.168.0.212", dst_ip="192.168.0.172", dst_port=53, proto="UDP"),
        ),
        collator_cards=(
            {
                "alert_id": "ssh-1",
                "score": 3,
                "mechanical_reasons": ["internal_management_port:22", "suppressed_but_rare", "host01_local_suricata_scope"],
                "local_facts": [
                    "192.168.0.172 is Host01, the Security Shallots control-plane host.",
                    "Host01 Suricata sees Host01's own traffic only, not the whole LAN.",
                    "Port 22 is an internal management port.",
                    "This src/dst/port tuple is rare in the 30-day baseline.",
                ],
                "note": "Keep visible as a candidate missed signal; no malicious/benign verdict.",
            },
        ),
    ),
    Scenario(
        id="router_source_mismatch",
        description="Many routine D-Link syslog lines contain one source mismatch that raw logs make easy to gloss over.",
        budget=2,
        expected_ids=("router-mismatch",),
        alerts=(
            alert("router-1", "Syslog [user]", source="syslog", severity="low", src_ip="192.168.0.1", proto="", extra="D-Link COVR routine user notice"),
            alert("router-2", "Syslog [user]", source="syslog", severity="low", src_ip="192.168.0.1", proto="", extra="D-Link COVR routine user notice"),
            alert("router-3", "Syslog [user]", source="syslog", severity="low", src_ip="192.168.0.1", proto="", extra="D-Link COVR routine user notice"),
            alert("router-mismatch", "Syslog [user]", source="syslog", severity="low", src_ip="192.168.0.55", proto="", extra="D-Link COVR formatted message but not from the known router IP"),
            alert("router-4", "Syslog [user]", source="syslog", severity="low", src_ip="192.168.0.1", proto="", extra="D-Link COVR routine user notice"),
            alert("router-5", "Syslog [user]", source="syslog", severity="low", src_ip="192.168.0.1", proto="", extra="D-Link COVR routine user notice"),
        ),
        collator_cards=(
            {
                "alert_id": "router-mismatch",
                "score": 2,
                "mechanical_reasons": ["router_syslog_source_mismatch", "unknown_router_emitter"],
                "local_facts": [
                    "Expected D-Link router syslog source is 192.168.0.1.",
                    "The message uses the router syslog pattern but arrived from 192.168.0.55.",
                    "Routine D-Link Syslog [user] from 192.168.0.1 is known noise.",
                ],
                "note": "Keep visible because the source does not match the known router.",
            },
        ),
    ),
    Scenario(
        id="rmm_from_security_node",
        description="RMM DNS lookups are common, but one comes from the security control-plane host and is rare.",
        budget=2,
        expected_ids=("rmm-host01",),
        alerts=(
            alert("rmm-workstation-1", "ET INFO Remote Monitoring and Management Tool in DNS Lookup", src_ip="192.168.0.129", dst_ip="192.168.0.172", dst_port=53, proto="UDP"),
            alert("rmm-workstation-2", "ET INFO Remote Monitoring and Management Tool in DNS Lookup", src_ip="192.168.0.212", dst_ip="192.168.0.172", dst_port=53, proto="UDP"),
            alert("rmm-host01", "ET INFO Remote Monitoring and Management Tool in DNS Lookup", src_ip="192.168.0.172", dst_ip="8.8.8.8", dst_port=53, proto="UDP"),
            alert("doh-1", "ET INFO Observed Cloudflare DNS over HTTPS Domain", src_ip="192.168.0.172", dst_ip="172.64.41.3", dst_port=443),
            alert("tunnel-1", "ET INFO DNS Query to Cloudflare Tunneling Domain", src_ip="192.168.0.224", dst_ip="192.168.0.172", dst_port=53, proto="UDP"),
        ),
        collator_cards=(
            {
                "alert_id": "rmm-host01",
                "score": 3,
                "mechanical_reasons": ["suppressed_but_rare", "host01_local_suricata_scope", "control_plane_host_rmm_lookup"],
                "local_facts": [
                    "192.168.0.172 is Host01, the Security Shallots control-plane host.",
                    "The same RMM lookup from workstations is common background noise.",
                    "A direct outbound lookup from Host01 to public DNS is rare in this baseline.",
                ],
                "note": "Keep visible as a context-dependent candidate; no verdict.",
            },
        ),
    ),
    Scenario(
        id="pure_stream_noise",
        description="Generic protocol decode and DNS noise only; downstream collator should emit no candidate cards.",
        budget=2,
        expected_ids=(),
        alerts=(
            alert("stream-a", "SURICATA STREAM 3way handshake SYN/ACK ignored TFO data", src_ip="8.8.8.8", dst_ip="192.168.0.172", dst_port=44584, category="Generic Protocol Command Decode"),
            alert("stream-b", "SURICATA STREAM excessive retransmissions", src_ip="192.168.0.172", dst_ip="192.168.0.212", dst_port=8000, category="Generic Protocol Command Decode"),
            alert("doh-a", "ET INFO Observed Cloudflare DNS over HTTPS Domain", src_ip="192.168.0.172", dst_ip="172.64.41.3", dst_port=443),
            alert("syslog-a", "Syslog [user]", source="syslog", severity="low", src_ip="192.168.0.1", proto="", extra="Known D-Link router source"),
            alert("rmm-a", "ET INFO Remote Monitoring and Management Tool in DNS Lookup", src_ip="192.168.0.129", dst_ip="192.168.0.172", dst_port=53, proto="UDP"),
        ),
        collator_cards=(),
    ),
    Scenario(
        id="canary_and_maintenance_noise",
        description="High-looking maintenance/canary events that should not become missed-signal candidates.",
        budget=2,
        expected_ids=(),
        alerts=(
            alert("canary-1", "Security Shallots test detection canary", source="syslog", severity="low", verdict="pending", src_ip="127.0.0.1", proto="", extra="local pipeline test with redacted token"),
            alert("persist-1", "Persistence surface changed", source="argus", severity="high", verdict="suppress", category="persistence", extra="Known myapp proxy cron maintenance diff"),
            alert("agent-offline-1", "Agent offline: host01", source="argus", severity="critical", verdict="suppress", category="agent_health", src_ip="192.168.0.172", proto="", extra="Known interview pause / operator maintenance window"),
            alert("router-noise", "Syslog [user]", source="syslog", severity="low", src_ip="192.168.0.1", proto="", extra="Known D-Link router source"),
        ),
        collator_cards=(),
    ),
)


def extract_json(text: str) -> dict[str, Any]:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, re.S)
        if not match:
            return {"selected_alert_ids": [], "ignored_alert_ids": [], "rationale": f"parse_error: {text[:200]}"}
        return json.loads(match.group(0))


def call_claude(prompt: str, model: str) -> tuple[dict[str, Any], float]:
    start = time.perf_counter()
    proc = subprocess.run(
        ["claude", "-p", prompt, "--model", model, "--output-format", "json"],
        check=True,
        text=True,
        capture_output=True,
        timeout=240,
    )
    elapsed = time.perf_counter() - start
    outer = json.loads(proc.stdout)
    result = outer.get("result", "")
    return extract_json(result), elapsed


def task_for(scenario: Scenario, mode: str) -> dict[str, Any]:
    if mode == "raw":
        return {
            "scenario_id": scenario.id,
            "scenario": scenario.description,
            "mode": mode,
            "review_budget_max_selected": scenario.budget,
            "input_type": "raw_alert_batch_no_local_corpus",
            "alerts": tuple(raw_alert_view(a) for a in scenario.alerts),
        }
    return {
        "scenario_id": scenario.id,
        "scenario": scenario.description,
        "mode": mode,
        "review_budget_max_selected": scenario.budget,
        "input_type": "downstream_collator_cards_with_local_facts",
        "collator_cards": scenario.collator_cards,
        "raw_alerts_for_lookup_only": scenario.alerts,
    }


def raw_alert_view(a: dict[str, Any]) -> dict[str, Any]:
    """Fields an upstream model would get from a plain alert feed."""
    return {
        key: a.get(key)
        for key in (
            "id",
            "source",
            "severity",
            "verdict",
            "title",
            "category",
            "src_ip",
            "dst_ip",
            "dst_port",
            "proto",
        )
    }


def batch_prompt() -> str:
    tasks = [
        task_for(scenario, mode)
        for scenario in SCENARIOS
        for mode in ("raw", "collated")
    ]
    schema = {
        "decisions": [
            {
                "scenario_id": "string",
                "mode": "raw|collated",
                "selected_alert_ids": ["alert id strings"],
                "ignored_alert_ids": ["alert id strings"],
                "rationale": "short reason",
            }
        ]
    }
    return (
        f"{SYSTEM}\n\n"
        "Evaluate every task independently. Do not use collated facts from one "
        "task when evaluating raw mode for the same scenario.\n\n"
        f"Return JSON matching this schema:\n{json.dumps(schema, indent=2)}\n\n"
        f"Tasks:\n{json.dumps(tasks, indent=2, sort_keys=True)}"
    )


def normalize_ids(value: Any) -> set[str]:
    if not isinstance(value, list):
        return set()
    return {str(v) for v in value}


def score(expected: set[str], selected: set[str]) -> dict[str, Any]:
    tp = len(expected & selected)
    fp = len(selected - expected)
    fn = len(expected - selected)
    precision = tp / (tp + fp) if (tp + fp) else (1.0 if not expected else 0.0)
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
    }


def aggregate(rows: list[dict[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {"results": rows}
    for mode in ("raw", "collated"):
        subset = [r for r in rows if r["mode"] == mode]
        tp = sum(r["score"]["tp"] for r in subset)
        fp = sum(r["score"]["fp"] for r in subset)
        fn = sum(r["score"]["fn"] for r in subset)
        precision = tp / (tp + fp) if (tp + fp) else 1.0
        recall = tp / (tp + fn) if (tp + fn) else 1.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
        out[f"{mode}_tp"] = tp
        out[f"{mode}_fp"] = fp
        out[f"{mode}_fn"] = fn
        out[f"{mode}_precision"] = round(precision, 3)
        out[f"{mode}_recall"] = round(recall, 3)
        out[f"{mode}_f1"] = round(f1, 3)
        out[f"{mode}_selected"] = sum(len(r["selected"]) for r in subset)
        out[f"{mode}_avg_latency_sec"] = round(sum(r["latency_sec"] for r in subset) / len(subset), 3)
    out["delta_precision"] = round(out["collated_precision"] - out["raw_precision"], 3)
    out["delta_recall"] = round(out["collated_recall"] - out["raw_recall"], 3)
    out["delta_f1"] = round(out["collated_f1"] - out["raw_f1"], 3)
    out["noise_reduction_selected"] = out["raw_selected"] - out["collated_selected"]
    out["false_positive_reduction"] = out["raw_fp"] - out["collated_fp"]
    raw_review_items = sum(len(scenario.alerts) for scenario in SCENARIOS)
    collated_review_items = sum(len(scenario.collator_cards) for scenario in SCENARIOS)
    out["raw_review_items"] = raw_review_items
    out["collated_review_items"] = collated_review_items
    out["review_item_reduction"] = raw_review_items - collated_review_items
    out["review_item_reduction_pct"] = round(
        (raw_review_items - collated_review_items) / raw_review_items,
        3,
    ) if raw_review_items else 0.0
    return out


def run(model: str) -> dict[str, Any]:
    output, elapsed = call_claude(batch_prompt(), model)
    decisions = output.get("decisions") if isinstance(output, dict) else None
    if not isinstance(decisions, list):
        decisions = []
    by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for decision in decisions:
        if isinstance(decision, dict):
            by_key[(str(decision.get("scenario_id")), str(decision.get("mode")))] = decision

    rows: list[dict[str, Any]] = []
    for scenario in SCENARIOS:
        expected = set(scenario.expected_ids)
        for mode in ("raw", "collated"):
            decision = by_key.get((scenario.id, mode), {})
            selected = normalize_ids(decision.get("selected_alert_ids"))
            rows.append(
                {
                    "scenario": scenario.id,
                    "mode": mode,
                    "expected": sorted(expected),
                    "selected": sorted(selected),
                    "score": score(expected, selected),
                    "latency_sec": round(elapsed, 3),
                    "rationale": decision.get("rationale"),
                }
            )
    summary = aggregate(rows)
    summary["upstream_model"] = model
    summary["scenarios"] = len(SCENARIOS)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", default="opus")
    parser.add_argument("--out", type=Path, default=REPO / "data" / "collator_benchmark.json")
    args = parser.parse_args()

    summary = run(args.model)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps({k: v for k, v in summary.items() if k != "results"}, indent=2, sort_keys=True))
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
