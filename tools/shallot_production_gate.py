#!/usr/bin/env python3
"""Production readiness gate for Security Shallots."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.shallot_gate_eval import evaluate_gate
from tools.shallot_security_snapshot import load_snapshot


def _print_text(result: dict[str, Any]) -> None:
    print(f"production gate: {result['status']}")
    print("blockers:")
    for item in result["blockers"]:
        print(f"  - {item}")
    if not result["blockers"]:
        print("  - none")
    print("warnings:")
    for item in result["warnings"]:
        print(f"  - {item}")
    if not result["warnings"]:
        print("  - none")
    print("next actions:")
    for item in result["next_actions"]:
        print(f"  - {item}")
    if not result["next_actions"]:
        print("  - none")
    print("remediation commands:")
    for item in result.get("remediation_commands", []):
        print(f"  $ {item}")
    if not result.get("remediation_commands"):
        print("  - none")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-c", "--config", default="config.yaml")
    parser.add_argument("--hours", type=float, default=1.0)
    parser.add_argument("--expected-log-sources", default="docs/NETWORK_LOG_SOURCES.yaml")
    parser.add_argument("--strict-warnings", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    snapshot = load_snapshot(
        config=args.config,
        hours=args.hours,
        expected_log_sources=args.expected_log_sources,
    )
    result = evaluate_gate(snapshot, strict_warnings=args.strict_warnings)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        _print_text(result)
    if result["blockers"]:
        return 2
    if args.strict_warnings and result["warnings"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
