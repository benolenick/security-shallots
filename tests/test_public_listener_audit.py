from tools.shallot_public_listener_audit import (
    Listener,
    build_summary,
    classify_listener,
    parse_active_clients,
    parse_ss_listeners,
)


def test_parse_ss_listeners_keeps_only_world_bound_listeners() -> None:
    raw = "\n".join(
        [
            'tcp LISTEN 0 4096 0.0.0.0:8001 0.0.0.0:* users:(("python",pid=12,fd=4))',
            'tcp LISTEN 0 4096 127.0.0.1:9100 0.0.0.0:* users:(("python",pid=13,fd=4))',
            'tcp LISTEN 0 4096 [::]:8002 [::]:* users:(("VLLM::Worker",pid=14,fd=4))',
        ]
    )

    listeners = parse_ss_listeners(raw)

    assert [(item.bind, item.port, item.process) for item in listeners] == [
        ("0.0.0.0", 8001, "python"),
        ("::", 8002, "VLLM::Worker"),
    ]


def test_build_summary_flags_unexpected_world_bound_dev_listeners() -> None:
    raw = "\n".join(
        [
            'tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=4))',
            'tcp LISTEN 0 4096 0.0.0.0:8001 0.0.0.0:* users:(("python",pid=12,fd=4))',
            'tcp LISTEN 0 4096 *:8002 *:* users:(("VLLM::Worker",pid=14,fd=4))',
        ]
    )

    summary = build_summary(raw)

    assert summary["status"] == "watch"
    assert summary["unexpected_count"] == 2
    assert summary["warnings"] == [
        "public_listener:8001:python:dev_or_model_port_world_bound,dev_or_model_process_world_bound",
        "public_listener:8002:VLLM::Worker:dev_or_model_port_world_bound,dev_or_model_process_world_bound",
    ]


def test_build_summary_flags_world_bound_ollama_even_without_process_owner() -> None:
    raw = 'tcp LISTEN 0 4096 *:11434 *:*'

    summary = build_summary(raw)

    assert summary["status"] == "watch"
    assert summary["unexpected_count"] == 1
    assert summary["warnings"] == [
        "public_listener:11434:ollama:dev_or_model_port_world_bound",
    ]
    assert summary["unexpected"][0]["service"] == "ollama"
    assert "authenticated proxy" in summary["unexpected"][0]["action"]


def test_parse_active_clients_for_listener_port() -> None:
    raw = "\n".join(
        [
            "ESTAB 0 0 [::ffff:192.168.0.172]:11434 [::ffff:192.168.0.224]:56212",
            "ESTAB 0 0 127.0.0.1:11434 127.0.0.1:54896",
            "ESTAB 0 0 192.168.0.172:8844 192.168.0.212:60000",
            "ESTAB 0 0 [::ffff:192.168.0.172]:11434 [::ffff:192.168.0.212]:56518",
        ]
    )

    assert parse_active_clients(raw, 11434) == ["192.168.0.212", "192.168.0.224"]


def test_build_summary_accepts_reviewed_allowed_ports() -> None:
    raw = 'tcp LISTEN 0 4096 0.0.0.0:8001 0.0.0.0:* users:(("python",pid=12,fd=4))'

    summary = build_summary(raw, allowed_ports={8001: "reviewed_model_server"})

    assert summary["status"] == "ok"
    assert summary["unexpected"] == []


def test_reviewed_listener_requires_matching_command_line() -> None:
    reviewed = Listener(
        proto="tcp",
        bind="0.0.0.0",
        port=8600,
        process="python3",
        pid="12",
        cmdline="/usr/bin/python3 /home/user/wall/server.py",
        raw='tcp LISTEN 0 4096 0.0.0.0:8600 0.0.0.0:* users:(("python3",pid=12,fd=4))',
    )
    unexpected = Listener(
        proto="tcp",
        bind="0.0.0.0",
        port=8600,
        process="python3",
        pid="13",
        cmdline="/usr/bin/python3 /tmp/random-dev-server.py",
        raw='tcp LISTEN 0 4096 0.0.0.0:8600 0.0.0.0:* users:(("python3",pid=13,fd=4))',
    )

    assert classify_listener(reviewed, allowed_ports={}) is None
    assert classify_listener(unexpected, allowed_ports={})["reason"] == (
        "dev_or_model_port_world_bound,dev_or_model_process_world_bound"
    )
