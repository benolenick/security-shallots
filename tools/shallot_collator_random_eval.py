#!/usr/bin/env python3
"""Randomized benchmark for the edge-collator architecture.

This creates noisy alert windows where the target candidate requires local
fleet context to justify preservation. Raw mode gets only plain alert fields.
Collated modes get structured downstream cards with different ablations.
"""

from __future__ import annotations

import argparse
import json
import random
import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


REPO = Path("/home/user/security-shallots")

SYSTEM = """You are an upstream Security Shallots reviewer.
Your job is not to decide benign or malicious. Your job is to pick which alert
IDs should remain visible for higher-tier review because they may be missed by
ordinary alert handling.

Constraints:
- Return only valid JSON matching the requested schema.
- Select only alert IDs with concrete provided evidence.
- High severity, scary words, port number, or IP address alone are insufficient.
- Local role, source-integrity, baseline rarity, or fleet-corpus context can make
  a bland alert worth preserving.
- Do not invent local roles, baselines, or normal behavior not present in input."""


NOISE_TITLES = [
    ("n{n}", "ET INFO Observed Cloudflare DNS over HTTPS Domain", "suricata", "medium", "Misc activity", 443, "TCP"),
    ("n{n}", "ET INFO DNS Query to Cloudflare Tunneling Domain", "suricata", "medium", "Misc activity", 53, "UDP"),
    ("n{n}", "ET INFO Remote Monitoring and Management Tool in DNS Lookup", "suricata", "medium", "Misc activity", 53, "UDP"),
    ("n{n}", "SURICATA STREAM 3way handshake SYN/ACK ignored TFO data", "suricata", "medium", "Generic Protocol Command Decode", 44584, "TCP"),
    ("n{n}", "Syslog [user]", "syslog", "low", "syslog/user", 0, ""),
    ("n{n}", "Allowed outbound TCP session", "syslog", "low", "firewall/session", 443, "TCP"),
]

TARGET_TYPES = [
    "allowed_ssh_from_control_plane",
    "router_source_mismatch",
    "control_plane_rmm",
    "rare_management_tuple",
]


@dataclass(frozen=True)
class Scenario:
    id: str
    target_type: str
    expected_ids: tuple[str, ...]
    alerts: tuple[dict[str, Any], ...]
    collator_cards: tuple[dict[str, Any], ...]


def alert(
    id: str,
    title: str,
    source: str,
    severity: str,
    verdict: str,
    category: str,
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    proto: str,
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
    }


def make_noise(rng: random.Random, idx: int) -> dict[str, Any]:
    _, title, source, severity, category, dst_port, proto = rng.choice(NOISE_TITLES)
    src_ip = rng.choice(["192.168.0.172", "192.168.0.125", "192.168.0.129", "192.168.0.212", "192.168.0.224", "192.168.0.1"])
    dst_ip = rng.choice(["192.168.0.172", "8.8.8.8", "8.8.4.4", "172.64.41.3", "162.159.61.3", "192.168.0.1"])
    if source == "syslog":
        dst_ip = ""
        dst_port = 0
        proto = ""
    return alert(
        id=f"noise-{idx}",
        title=title,
        source=source,
        severity=severity,
        verdict="suppress",
        category=category,
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_port=dst_port,
        proto=proto,
    )


def target_for(kind: str) -> tuple[dict[str, Any], dict[str, Any]]:
    if kind == "allowed_ssh_from_control_plane":
        a = alert("target", "Allowed outbound TCP session", "syslog", "low", "suppress", "firewall/session", "192.168.0.172", "192.168.2.177", 22, "TCP")
        card = {
            "alert_id": "target",
            "score": 4,
            "mechanical_reasons": ["internal_management_port:22", "first_seen_src_dst_port_tuple_30d", "control_plane_host_egress"],
            "local_facts": [
                "192.168.0.172 is Host01, the Security Shallots control-plane host.",
                "192.168.2.177 is outside the normal 192.168.0.0/24 home segment.",
                "Port 22 is a management port.",
                "This source/destination/port tuple is first-seen in the 30-day baseline.",
            ],
        }
    elif kind == "router_source_mismatch":
        a = alert("target", "Syslog [user]", "syslog", "low", "suppress", "syslog/user", "192.168.0.55", "", 0, "")
        card = {
            "alert_id": "target",
            "score": 3,
            "mechanical_reasons": ["router_syslog_source_mismatch", "known_noise_pattern_wrong_source"],
            "local_facts": [
                "D-Link router Syslog [user] messages are expected only from 192.168.0.1.",
                "Routine Syslog [user] messages from 192.168.0.1 are known noise.",
                "This message used that known router-noise pattern but arrived from 192.168.0.55.",
            ],
        }
    elif kind == "control_plane_rmm":
        a = alert("target", "ET INFO Remote Monitoring and Management Tool in DNS Lookup", "suricata", "medium", "suppress", "Misc activity", "192.168.0.172", "8.8.8.8", 53, "UDP")
        card = {
            "alert_id": "target",
            "score": 3,
            "mechanical_reasons": ["suppressed_but_rare", "control_plane_host_rmm_lookup"],
            "local_facts": [
                "192.168.0.172 is Host01, the Security Shallots control-plane host.",
                "RMM DNS lookups from workstations are common in this fleet.",
                "RMM DNS lookup originating from Host01 is rare in the 30-day baseline.",
            ],
        }
    else:
        a = alert("target", "Allowed outbound TCP session", "syslog", "low", "suppress", "firewall/session", "192.168.0.125", "192.168.0.172", 8855, "TCP")
        card = {
            "alert_id": "target",
            "score": 3,
            "mechanical_reasons": ["internal_management_port:8855", "first_seen_src_dst_port_tuple_30d", "shallots_webhook_path"],
            "local_facts": [
                "Port 8855 is the Security Shallots Argus webhook listener.",
                "192.168.0.172 is Host01, the Security Shallots control-plane host.",
                "This source/destination/port tuple is first-seen in the 30-day baseline.",
            ],
        }
    card["note"] = "Non-judgmental candidate card: preserve for higher-tier review; no verdict."
    return a, card


def false_card(rng: random.Random, alerts: list[dict[str, Any]], idx: int) -> dict[str, Any]:
    a = rng.choice(alerts)
    return {
        "alert_id": a["id"],
        "score": 1,
        "mechanical_reasons": ["weak_noise_sample"],
        "local_facts": ["This is a low-confidence decoy card inserted to test upstream precision."],
        "note": f"Decoy card {idx}; should not be selected without stronger evidence.",
    }


def generate_scenarios(
    count: int,
    alerts_per: int,
    seed: int,
    false_card_rate: float,
    collator_drop_rate: float,
) -> list[Scenario]:
    rng = random.Random(seed)
    scenarios: list[Scenario] = []
    for i in range(count):
        kind = rng.choice(TARGET_TYPES + ["pure_noise"])
        alerts = [make_noise(rng, j) for j in range(alerts_per)]
        cards: list[dict[str, Any]] = []
        expected: tuple[str, ...] = ()
        if kind != "pure_noise":
            target, card = target_for(kind)
            pos = rng.randrange(len(alerts) + 1)
            alerts.insert(pos, target)
            expected = ("target",)
            if rng.random() >= collator_drop_rate:
                cards.append(card)
        if false_card_rate > 0:
            for j in range(max(1, int(false_card_rate * len(alerts)))):
                if rng.random() < false_card_rate:
                    cards.append(false_card(rng, [a for a in alerts if a["id"] != "target"], j))
        scenarios.append(
            Scenario(
                id=f"s{i:03d}_{kind}",
                target_type=kind,
                expected_ids=expected,
                alerts=tuple(alerts),
                collator_cards=tuple(cards),
            )
        )
    return scenarios


def raw_alert_view(a: dict[str, Any]) -> dict[str, Any]:
    return {k: a.get(k) for k in ("id", "source", "severity", "verdict", "title", "category", "src_ip", "dst_ip", "dst_port", "proto")}


def task_for(s: Scenario, mode: str) -> dict[str, Any]:
    if mode == "raw":
        return {
            "scenario_id": s.id,
            "target_type_hidden": "hidden",
            "mode": mode,
            "input_type": "raw_alert_batch_no_local_corpus",
            "review_budget_max_selected": 2,
            "alerts": [raw_alert_view(a) for a in s.alerts],
        }
    cards = s.collator_cards
    if mode == "reasons_only":
        cards = tuple({k: c[k] for k in ("alert_id", "score", "mechanical_reasons", "note") if k in c} for c in cards)
    elif mode == "facts_only":
        cards = tuple({k: c[k] for k in ("alert_id", "score", "local_facts", "note") if k in c} for c in cards)
    elif mode == "shortlist_raw":
        ids = {str(c.get("alert_id")) for c in cards}
        return {
            "scenario_id": s.id,
            "target_type_hidden": "hidden",
            "mode": mode,
            "input_type": "same_shortlist_raw_alerts_without_collator_enrichment",
            "review_budget_max_selected": 2,
            "alerts": [raw_alert_view(a) for a in s.alerts if a["id"] in ids],
        }
    elif mode == "random_shortlist":
        rng = random.Random(f"{s.id}:random_shortlist")
        count = max(1, len(cards))
        sample = rng.sample(list(s.alerts), k=min(count, len(s.alerts)))
        return {
            "scenario_id": s.id,
            "target_type_hidden": "hidden",
            "mode": mode,
            "input_type": "random_shortlist_same_item_count_as_collator",
            "review_budget_max_selected": 2,
            "alerts": [raw_alert_view(a) for a in sample],
        }
    return {
        "scenario_id": s.id,
        "target_type_hidden": "hidden",
        "mode": mode,
        "input_type": "downstream_collator_cards",
        "review_budget_max_selected": 2,
        "selection_constraint": "selected_alert_ids must come from collator_cards only; raw_alerts_for_lookup_only is context, not a candidate list",
        "collator_cards": cards,
        "raw_alerts_for_lookup_only": [raw_alert_view(a) for a in s.alerts],
    }


def allowed_ids_for(s: Scenario, mode: str) -> set[str]:
    if mode == "raw":
        return {str(a["id"]) for a in s.alerts}
    if mode == "shortlist_raw":
        return {str(c.get("alert_id")) for c in s.collator_cards}
    if mode == "random_shortlist":
        rng = random.Random(f"{s.id}:random_shortlist")
        count = max(1, len(s.collator_cards))
        sample = rng.sample(list(s.alerts), k=min(count, len(s.alerts)))
        return {str(a["id"]) for a in sample}
    return {str(c.get("alert_id")) for c in s.collator_cards}


def prompt_for(scenarios: list[Scenario], modes: list[str]) -> str:
    tasks = [task_for(s, mode) for s in scenarios for mode in modes]
    schema = {
        "decisions": [
            {
                "scenario_id": "string",
        "mode": "raw|collated|reasons_only|facts_only|shortlist_raw|random_shortlist",
                "selected_alert_ids": ["alert id strings"],
                "rationale": "short reason",
            }
        ]
    }
    return (
        f"{SYSTEM}\n\n"
        "Evaluate every task independently. Do not let collated/facts modes inform raw mode.\n"
        f"Return JSON matching this schema:\n{json.dumps(schema, indent=2)}\n\n"
        f"Tasks:\n{json.dumps(tasks, indent=2, sort_keys=True)}"
    )


def extract_json(text: str) -> dict[str, Any]:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, re.S)
        if not match:
            return {"decisions": []}
        return json.loads(match.group(0))


def call_claude(prompt: str, model: str, timeout: int) -> tuple[dict[str, Any], float]:
    start = time.perf_counter()
    proc = subprocess.run(
        ["claude", "-p", "--model", model, "--output-format", "json"],
        check=True,
        text=True,
        input=prompt,
        capture_output=True,
        timeout=timeout,
    )
    elapsed = time.perf_counter() - start
    return extract_json(json.loads(proc.stdout).get("result", "")), elapsed


def metric(expected: set[str], selected: set[str]) -> dict[str, Any]:
    tp = len(expected & selected)
    fp = len(selected - expected)
    fn = len(expected - selected)
    precision = tp / (tp + fp) if (tp + fp) else (1.0 if not expected else 0.0)
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = (2 * precision * recall / (precision + recall)) if precision + recall else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "precision": precision, "recall": recall, "f1": f1}


def summarize(results: list[dict[str, Any]], scenarios: list[Scenario], modes: list[str]) -> dict[str, Any]:
    out: dict[str, Any] = {"results": results}
    expected_positive = [s for s in scenarios if s.expected_ids]
    collator_hit = [
        s for s in expected_positive
        if set(s.expected_ids) & {str(c.get("alert_id")) for c in s.collator_cards}
    ]
    out["collator_stage"] = {
        "expected_positive_scenarios": len(expected_positive),
        "cards_emitted": sum(len(s.collator_cards) for s in scenarios),
        "true_candidate_cards": len(collator_hit),
        "collator_recall": round(len(collator_hit) / len(expected_positive), 3) if expected_positive else 1.0,
    }
    for mode in modes:
        subset = [r for r in results if r["mode"] == mode]
        tp = sum(r["score"]["tp"] for r in subset)
        fp = sum(r["score"]["fp"] for r in subset)
        fn = sum(r["score"]["fn"] for r in subset)
        precision = tp / (tp + fp) if (tp + fp) else 1.0
        recall = tp / (tp + fn) if (tp + fn) else 1.0
        f1 = (2 * precision * recall / (precision + recall)) if precision + recall else 0.0
        if mode == "raw":
            review_items = sum(len(s.alerts) for s in scenarios)
        elif mode in ("shortlist_raw", "random_shortlist"):
            review_items = sum(max(1, len(s.collator_cards)) for s in scenarios)
        else:
            review_items = sum(len(s.collator_cards) for s in scenarios)
        out[mode] = {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "precision": round(precision, 3),
            "recall": round(recall, 3),
            "f1": round(f1, 3),
            "selected": sum(len(r["selected"]) for r in subset),
            "review_items": review_items,
        }
    if "raw" in out and "collated" in out:
        out["deltas"] = {
            "recall": round(out["collated"]["recall"] - out["raw"]["recall"], 3),
            "f1": round(out["collated"]["f1"] - out["raw"]["f1"], 3),
            "review_item_reduction": out["raw"]["review_items"] - out["collated"]["review_items"],
            "review_item_reduction_pct": round((out["raw"]["review_items"] - out["collated"]["review_items"]) / out["raw"]["review_items"], 3),
        }
        out["end_to_end"] = {
            "pipeline_recall": out["collated"]["recall"],
            "upstream_conditional_recall_on_emitted_true_cards": round(
                out["collated"]["tp"] / out["collator_stage"]["true_candidate_cards"],
                3,
            ) if out["collator_stage"]["true_candidate_cards"] else 1.0,
            "collator_stage_recall": out["collator_stage"]["collator_recall"],
            "raw_recall": out["raw"]["recall"],
        }
    return out


def run(args: argparse.Namespace) -> dict[str, Any]:
    modes = args.modes.split(",")
    scenarios = generate_scenarios(
        args.scenarios,
        args.alerts_per_scenario,
        args.seed,
        args.false_card_rate,
        args.collator_drop_rate,
    )
    response, elapsed = call_claude(prompt_for(scenarios, modes), args.model, args.timeout)
    decisions = response.get("decisions") if isinstance(response, dict) else []
    by_key = {
        (str(d.get("scenario_id")), str(d.get("mode"))): d
        for d in decisions
        if isinstance(d, dict)
    }
    rows = []
    for s in scenarios:
        expected = set(s.expected_ids)
        for mode in modes:
            d = by_key.get((s.id, mode), {})
            selected = {str(x) for x in d.get("selected_alert_ids", []) if isinstance(x, str)}
            selected &= allowed_ids_for(s, mode)
            rows.append(
                {
                    "scenario": s.id,
                    "target_type": s.target_type,
                    "collator_emitted_expected": bool(set(s.expected_ids) & {str(c.get("alert_id")) for c in s.collator_cards}),
                    "mode": mode,
                    "expected": sorted(expected),
                    "selected": sorted(selected),
                    "score": metric(expected, selected),
                    "rationale": d.get("rationale"),
                }
            )
    summary = summarize(rows, scenarios, modes)
    summary.update(
        {
            "model": args.model,
            "scenario_count": args.scenarios,
            "alerts_per_scenario": args.alerts_per_scenario,
            "seed": args.seed,
            "false_card_rate": args.false_card_rate,
            "collator_drop_rate": args.collator_drop_rate,
            "modes": modes,
            "latency_sec": round(elapsed, 3),
        }
    )
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", default="sonnet")
    parser.add_argument("--scenarios", type=int, default=24)
    parser.add_argument("--alerts-per-scenario", type=int, default=20)
    parser.add_argument("--seed", type=int, default=17)
    parser.add_argument("--false-card-rate", type=float, default=0.0)
    parser.add_argument("--collator-drop-rate", type=float, default=0.0)
    parser.add_argument("--modes", default="raw,collated,shortlist_raw,random_shortlist,reasons_only,facts_only")
    parser.add_argument("--timeout", type=int, default=360)
    parser.add_argument("--out", type=Path, default=REPO / "data" / "collator_random_eval.json")
    args = parser.parse_args()

    summary = run(args)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps({k: v for k, v in summary.items() if k != "results"}, indent=2, sort_keys=True))
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
