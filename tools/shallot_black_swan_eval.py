#!/usr/bin/env python3
"""Black-swan style Scout simulation.

This is a bounded offline battery. It does not claim to generate real unknown
unknowns; it tests classes of out-of-distribution events against the current
Scout surfacing logic and records which ones are caught or missed.
"""

from __future__ import annotations

import argparse
import asyncio
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from shallots.ai.scout import ScoutWorker
from shallots.config import ScoutConfig, load_config


ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "data" / "black_swan"


class CountOnlyDB:
    """Minimal DB shim for Scout scoring."""

    def __init__(self, common_titles: set[str] | None = None) -> None:
        self.common_titles = common_titles or set()

    async def count_alerts_matching(self, **kwargs: Any) -> int:
        title = str(kwargs.get("title") or "")
        if title in self.common_titles:
            return 25
        return 1

    async def execute_sql(self, *_args: Any, **_kwargs: Any) -> list[dict[str, Any]]:
        return []


@dataclass(frozen=True)
class Scenario:
    name: str
    description: str
    should_surface: bool
    alert: dict[str, Any]
    expected_reason: str


def alert(
    *,
    id: str,
    source: str,
    severity: str = "low",
    verdict: str = "suppress",
    title: str,
    description: str = "",
    src_ip: str = "",
    dst_ip: str = "",
    dst_port: int = 0,
    proto: str = "TCP",
    category: str = "",
    signature_id: int = 0,
) -> dict[str, Any]:
    return {
        "id": id,
        "source": source,
        "severity": severity,
        "verdict": verdict,
        "title": title,
        "description": description,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "proto": proto,
        "category": category,
        "signature_id": signature_id,
    }


def scenarios() -> list[Scenario]:
    return [
        Scenario(
            name="unknown_sensor_ordinary_port",
            description="A new/unknown collector source emits an otherwise bland alert.",
            should_surface=True,
            expected_reason="unknown_collector_source",
            alert=alert(
                id="bs-unknown-source",
                source="new-edr-probe",
                title="Endpoint behavioral note",
                description="New collector emitted a process/network note.",
                src_ip="192.168.0.204",
                dst_ip="192.168.0.172",
                dst_port=443,
            ),
        ),
        Scenario(
            name="external_to_internal_management",
            description="An external IP touches an internal management port.",
            should_surface=True,
            expected_reason="external_to_internal_management_port",
            alert=alert(
                id="bs-external-rdp",
                source="suricata",
                title="Allowed inbound TCP session",
                src_ip="203.0.113.55",
                dst_ip="192.168.0.172",
                dst_port=3389,
            ),
        ),
        Scenario(
            name="internal_control_plane_management",
            description="Internal host touches Host01 management/API port.",
            should_surface=True,
            expected_reason="internal_management_port",
            alert=alert(
                id="bs-internal-mgmt",
                source="argus",
                title="Internal session opened",
                src_ip="192.168.0.204",
                dst_ip="192.168.0.172",
                dst_port=8844,
                category="network/session",
            ),
        ),
        Scenario(
            name="router_pattern_wrong_source",
            description="Known D-Link router syslog pattern appears from a non-router source.",
            should_surface=True,
            expected_reason="router_syslog_source_mismatch",
            alert=alert(
                id="bs-router-spoof",
                source="syslog",
                title="DLink Syslog [user]",
                src_ip="192.168.0.55",
                proto="",
                category="syslog/user",
            ),
        ),
        Scenario(
            name="control_plane_rmm_dns",
            description="Common RMM DNS signature appears from Host01/control-plane.",
            should_surface=True,
            expected_reason="host01/control-plane rarity",
            alert=alert(
                id="bs-rmm-host01",
                source="suricata",
                title="ET INFO Remote Monitoring and Management Tool in DNS Lookup",
                severity="medium",
                src_ip="192.168.0.172",
                dst_ip="8.8.8.8",
                dst_port=53,
                proto="UDP",
                category="Misc activity",
            ),
        ),
        Scenario(
            name="novel_non_mgmt_exfil_shape",
            description="Rare high-byte outbound session on an ordinary allowed port.",
            should_surface=True,
            expected_reason="requires volume/process baseline not present in Scout",
            alert=alert(
                id="bs-exfil-443",
                source="argus",
                title="Large outbound transfer completed",
                description="Process backup-helper sent 18GB to a first-seen external host over HTTPS.",
                src_ip="192.168.0.172",
                dst_ip="8.8.8.8",
                dst_port=443,
                category="network/volume",
            ),
        ),
        Scenario(
            name="living_off_land_allowed_https",
            description="Suspicious process semantics over ordinary HTTPS.",
            should_surface=True,
            expected_reason="requires process semantics not present in Scout scoring",
            alert=alert(
                id="bs-lolbin-https",
                source="argus",
                title="Allowed outbound TCP session",
                description="powershell opened an outbound HTTPS session to a first-seen host.",
                src_ip="192.168.0.129",
                dst_ip="1.1.1.1",
                dst_port=443,
                category="process/network",
            ),
        ),
        Scenario(
            name="new_tld_black_swan_dns",
            description="Future-bad TLD/domain signal is currently only an INFO DNS/TLD shape.",
            should_surface=True,
            expected_reason="INFO DNS/TLD novelty is intentionally damped",
            alert=alert(
                id="bs-tld-info",
                source="suricata",
                title="ET INFO Observed DNS Query to .zip TLD",
                severity="medium",
                src_ip="192.168.0.224",
                dst_ip="192.168.0.172",
                dst_port=53,
                proto="UDP",
                category="Misc activity",
            ),
        ),
        Scenario(
            name="ordinary_port_control",
            description="Bland first-seen ordinary-port event should not surface.",
            should_surface=False,
            expected_reason="ordinary novelty should stay below threshold",
            alert=alert(
                id="bs-control-8080",
                source="argus",
                title="Internal session opened",
                src_ip="192.168.0.204",
                dst_ip="192.168.0.172",
                dst_port=8080,
                category="network/session",
            ),
        ),
        Scenario(
            name="hidden_synthetic_canary_control",
            description="Known synthetic canary should not surface even on a management port.",
            should_surface=False,
            expected_reason="known synthetic marker",
            alert=alert(
                id="bs-hidden-canary",
                source="argus",
                title="Argus canary internal session argus-scout-canary-1784359999-deadbeef port 8844",
                description="Synthetic fleet canary token=argus-scout-canary-1784359999-deadbeef",
                src_ip="192.168.0.204",
                dst_ip="192.168.0.172",
                dst_port=8844,
                category="edge_canary/session",
            ),
        ),
    ]


async def run(args: argparse.Namespace) -> dict[str, Any]:
    cfg = load_config(args.config).scout if Path(args.config).exists() else ScoutConfig()
    db = CountOnlyDB()
    worker = ScoutWorker(cfg, db, ROOT)
    rows = []
    for scenario in scenarios():
        score, reasons = await worker._score_alert(scenario.alert)
        surfaced = score >= cfg.min_score
        rows.append(
            {
                "name": scenario.name,
                "description": scenario.description,
                "should_surface": scenario.should_surface,
                "surfaced": surfaced,
                "pass": surfaced == scenario.should_surface,
                "score": score,
                "min_score": cfg.min_score,
                "reasons": reasons,
                "expected_reason": scenario.expected_reason,
                "alert": scenario.alert,
            }
        )
    positives = [r for r in rows if r["should_surface"]]
    negatives = [r for r in rows if not r["should_surface"]]
    tp = sum(1 for r in positives if r["surfaced"])
    fn = sum(1 for r in positives if not r["surfaced"])
    tn = sum(1 for r in negatives if not r["surfaced"])
    fp = sum(1 for r in negatives if r["surfaced"])
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    return {
        "status": "ok" if all(r["pass"] for r in rows) else "has_expected_or_unexpected_misses",
        "scenario_count": len(rows),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "rows": rows,
        "interpretation": (
            "Current Scout catches black-swan shapes that violate known mechanical invariants "
            "such as management-plane exposure, unknown source, or router-source mismatch. "
            "It misses black-swan shapes that require semantic volume/process understanding "
            "or deliberately damped INFO DNS/TLD novelty."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="config.yaml")
    parser.add_argument("--out", type=Path, default=OUT_DIR / "black_swan_eval.json")
    args = parser.parse_args()
    result = asyncio.run(run(args))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({k: v for k, v in result.items() if k != "rows"}, indent=2, sort_keys=True))
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
