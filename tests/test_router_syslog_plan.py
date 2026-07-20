"""Router syslog setup plan tests."""

from __future__ import annotations

from tools.shallot_router_syslog_plan import build_plan, load_sources


def test_load_sources_reads_expected_manifest_entries(tmp_path) -> None:
    manifest = tmp_path / "sources.yaml"
    manifest.write_text(
        """
sources:
  - name: main_gateway
    type: syslog
    expected: true
    src_ips: [192.168.0.1]
    hostnames: [dlink, covr]
    note: Configure this.
  - name: disabled_source
    expected: false
"""
    )

    sources = load_sources(str(manifest))

    assert [src["name"] for src in sources] == ["main_gateway"]


def test_build_plan_uses_shallots_target_and_gate_verification() -> None:
    plan = build_plan(
        [
            {
                "name": "main_gateway",
                "type": "syslog",
                "src_ips": ["192.168.0.1"],
                "hostnames": ["dlink"],
                "note": "Configure remote syslog.",
            }
        ],
        target="192.168.0.172",
        port=514,
    )

    src = plan["sources"][0]
    assert plan["target"] == "192.168.0.172"
    assert plan["port"] == 514
    assert plan["target_preflight"] == {
        "status": "not_probed",
        "target": "192.168.0.172",
        "port": 514,
        "checks": {},
        "next_step": "Run with --probe from the operator network before changing router syslog settings.",
    }
    assert ".venv/bin/python tools/shallot_syslog_canary.py --timeout 30" in plan["receiver_preflight_commands"]
    assert src["source_ips"] == ["192.168.0.1"]
    assert src["admin_urls"] == ["http://192.168.0.1/", "https://192.168.0.1/"]
    assert any("D-Link/COVR" in hint for hint in src["ui_hints"])
    assert any("192.168.0.172" in step and "514" in step for step in src["router_steps"])
    assert (
        ".venv/bin/python tools/shallot_alert_assess.py --hours 1 --summary-json --expected-log-sources docs/NETWORK_LOG_SOURCES.yaml"
        in src["verify_commands"]
    )
    assert ".venv/bin/python tools/shallot_production_gate.py" in src["verify_commands"]
    assert any("fresh syslog event" in item for item in src["success_criteria"])
    assert any(
        "network:expected_syslog_missing:main_gateway" in item
        for item in src["success_criteria"]
    )
    assert any("shallot_syslog_canary remains ok" in item for item in src["success_criteria"])
    assert src["reachability"] == []
    assert src["fingerprints"] == {}
    assert src["diagnosis"] == "not_probed"
    assert any(option["name"] == "keep_expected_gap" for option in src["fallback_options"])
    assert any("syslog-capable gateway" in option["action"] for option in src["fallback_options"])
    assert any("Mirror the gateway/uplink port" in option["action"] for option in src["fallback_options"])


def test_build_plan_includes_sagemcom_gap_guidance() -> None:
    plan = build_plan(
        [
            {
                "name": "isp_wifi_gateway",
                "type": "syslog",
                "src_ips": ["192.168.2.1"],
                "hostnames": ["sagemcom"],
            }
        ]
    )

    src = plan["sources"][0]
    assert src["admin_urls"] == ["http://192.168.2.1/", "https://192.168.2.1/"]
    assert any("If no remote syslog option exists" in hint for hint in src["ui_hints"])
    assert any(option["name"] == "segment_endpoint_coverage" for option in src["fallback_options"])


def test_build_plan_probe_marks_reachable_ui_missing_syslog(monkeypatch) -> None:
    monkeypatch.setattr("tools.shallot_router_syslog_plan._tcp_open", lambda host, port: True)
    monkeypatch.setattr("tools.shallot_router_syslog_plan._ping_ok", lambda host: True)
    monkeypatch.setattr(
        "tools.shallot_router_syslog_plan._route_to",
        lambda host: f"{host} dev eth0 src 192.168.0.172",
    )
    monkeypatch.setattr(
        "tools.shallot_router_syslog_plan._curl_probe",
        lambda url: "<html><head><title>D-LINK</title><script>window.TPL_VER = \"7.3.28\"</script></head></html>",
    )
    monkeypatch.setattr(
        "tools.shallot_router_syslog_plan._cert_probe",
        lambda host: {"subject": "C = TW, O = D-Link Corporation", "issuer": "C = TW, O = D-Link Corporation"},
    )

    plan = build_plan(
        [
            {
                "name": "main_gateway",
                "type": "syslog",
                "src_ips": ["192.168.0.1"],
                "hostnames": ["dlink"],
            }
        ],
        probe=True,
    )

    src = plan["sources"][0]
    assert plan["target_preflight"]["status"] == "reachable"
    assert plan["target_preflight"]["checks"] == {
        "route": "192.168.0.172 dev eth0 src 192.168.0.172",
        "ping": True,
        "tcp_syslog": True,
        "tcp_api_8844": True,
    }
    assert src["reachability"] == [
        {
            "ip": "192.168.0.1",
            "tcp80": True,
            "tcp443": True,
            "route": "192.168.0.1 dev eth0 src 192.168.0.172",
        }
    ]
    assert src["diagnosis"] == "management_ui_reachable_syslog_not_forwarding"
    assert "192.168.0.172:514" in src["next_step"]
    assert src["fingerprints"]["192.168.0.1"]["title"] == "D-LINK"
    assert src["fingerprints"]["192.168.0.1"]["template_version"] == "7.3.28"
    assert "D-Link Corporation" in src["fingerprints"]["192.168.0.1"]["cert_subject"]


def test_build_plan_probe_marks_target_routed_but_unreachable(monkeypatch) -> None:
    monkeypatch.setattr("tools.shallot_router_syslog_plan._tcp_open", lambda host, port: False)
    monkeypatch.setattr("tools.shallot_router_syslog_plan._ping_ok", lambda host: False)
    monkeypatch.setattr(
        "tools.shallot_router_syslog_plan._route_to",
        lambda host: f"{host} dev eth0 src 192.168.0.212",
    )
    monkeypatch.setattr("tools.shallot_router_syslog_plan._curl_probe", lambda url: "")
    monkeypatch.setattr("tools.shallot_router_syslog_plan._cert_probe", lambda host: {})

    plan = build_plan(
        [
            {
                "name": "main_gateway",
                "type": "syslog",
                "src_ips": ["192.168.0.1"],
                "hostnames": ["dlink"],
            }
        ],
        target="192.168.0.172",
        probe=True,
    )

    assert plan["target_preflight"] == {
        "status": "routed_but_unreachable",
        "target": "192.168.0.172",
        "port": 514,
        "checks": {
            "route": "192.168.0.172 dev eth0 src 192.168.0.212",
            "ping": False,
            "tcp_syslog": False,
            "tcp_api_8844": False,
        },
        "next_step": "Restore the Shallots receiver host at 192.168.0.172 before pointing routers at it.",
    }
