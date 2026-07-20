from tools.shallot_rule_canary import CASES, PYTHON_UNUSUAL_EGRESS_ENDPOINTS, run_cases


def test_rule_canary_cases_all_match_expected_rules() -> None:
    result = run_cases()

    assert result["status"] == "ok"
    assert result["failed"] == 0
    assert result["passed"] == len(result["cases"])
    assert result["coverage"]["total_cases"] == len(result["cases"])
    assert result["coverage"]["positive_cases"] > result["coverage"]["quiet_cases"]
    assert result["coverage"]["sources"]["argus"]["cases"] >= 1
    assert result["coverage"]["sources"]["syslog"]["cases"] >= 1
    assert result["coverage_guardrails"]["quiet"]["minimum_cases"] == 13
    assert result["coverage_guardrails"]["quiet"]["headroom_cases"] == 6
    assert result["coverage_guardrails"]["sources"]["minimum_cases"]["suricata"] == 2
    assert result["coverage_guardrails"]["sources"]["headroom_cases"] == {
        "argus": 28,
        "suricata": 1,
        "syslog": 36,
    }
    assert "syslog.management_service_change" in result["coverage"]["covered_rule_ids"]
    assert "syslog.admin_account_change" in result["coverage"]["covered_rule_ids"]
    assert "syslog.logging_disabled" in result["coverage"]["covered_rule_ids"]
    assert "syslog.config_restore" in result["coverage"]["covered_rule_ids"]
    assert "syslog.factory_reset" in result["coverage"]["covered_rule_ids"]
    assert "syslog.time_config_change" in result["coverage"]["covered_rule_ids"]
    assert "syslog.exposure_change" in result["coverage"]["covered_rule_ids"]
    assert all("source" in item for item in result["cases"])


def test_argus_python_unusual_egress_examples_are_generated() -> None:
    case_names = {case.name for case in CASES}

    assert all(name in case_names for name, _, _ in PYTHON_UNUSUAL_EGRESS_ENDPOINTS)
