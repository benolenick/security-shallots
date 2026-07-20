from __future__ import annotations

import argparse
import asyncio
import os
import subprocess
import sys
from pathlib import Path

from .config import load_config
from .core import (
    StateStore,
    clear_disarm_state,
    issue_disarm_code,
    pid_alive,
    stop_pid,
    verify_disarm_code,
    is_timelocked,
    check_timelock,
    extend_timelock,
    release_timelock,
    get_timelock_info,
    set_pin,
    check_pin,
    has_pin,
    validate_pin_format,
)
from .daemon import ArgusDaemon
from .hooks import install_lock_hooks, remove_lock_hooks
from .sinks import SmsSink


def _state_path() -> Path:
    return (Path.home() / ".argus" / "state.json").resolve()


def _prompt_gui(title: str, prompt: str, mask: bool = False) -> str:
    try:
        import tkinter as tk
        from tkinter import simpledialog

        root = tk.Tk()
        root.withdraw()
        kwargs = {"show": "*"} if mask else {}
        val = simpledialog.askstring(title, prompt, **kwargs)
        root.destroy()
        return (val or "").strip()
    except Exception:
        if mask:
            import getpass
            try:
                return getpass.getpass(f"{prompt} ").strip()
            except Exception:
                pass
        return input(f"{prompt} ").strip()


def cmd_check_config(args: argparse.Namespace) -> int:
    _ = load_config(args.config)
    print(f"config-ok path={Path(args.config).resolve()}")
    return 0


def _start_monitor_process(config_path: str) -> int:
    cmd = [sys.executable, "-m", "argus", "--config", str(Path(config_path).resolve()), "run-monitor"]
    creationflags = 0
    if os.name == "nt":
        creationflags = 0x00000008 | 0x00000200  # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
    proc = subprocess.Popen(cmd, close_fds=True, creationflags=creationflags)
    return int(proc.pid)


def cmd_on(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    state_store = StateStore(str(_state_path()))
    st = state_store.load()

    if st.get("enabled") and pid_alive(st.get("monitor_pid")):
        print("Argus already on.")
        return 0

    pid = _start_monitor_process(args.config)
    st["enabled"] = True
    st["monitor_pid"] = pid
    st["current_state"] = "ARMED_HOME"
    state_store.mark_poll(st)
    state_store.save(st)
    print(f"Argus ON (monitor pid={pid})")
    return 0


def cmd_off(_: argparse.Namespace) -> int:
    state_store = StateStore(str(_state_path()))
    st = state_store.load()

    # Release timelock if active (off is an authorized override)
    if st.get("timelock_active"):
        release_timelock(st)
        print("TimeLock released. Network restored.")

    stop_pid(st.get("monitor_pid"))
    st["enabled"] = False
    st["monitor_pid"] = None
    st["current_state"] = "DISARMED"
    clear_disarm_state(st)
    state_store.save(st)
    print("Argus OFF")
    return 0


def cmd_status(_: argparse.Namespace) -> int:
    state_store = StateStore(str(_state_path()))
    st = state_store.load()
    print(f"enabled={bool(st.get('enabled', False))}")
    print(f"monitor_pid={st.get('monitor_pid')}")
    print(f"monitor_alive={pid_alive(st.get('monitor_pid'))}")
    print(f"current_state={st.get('current_state')}")
    print(f"last_poll_utc={st.get('last_poll_utc')}")
    print(f"pin_configured={has_pin(st)}")

    # TimeLock status
    tl = get_timelock_info(st)
    if tl["active"]:
        mins = tl["remaining_seconds"] // 60
        secs = tl["remaining_seconds"] % 60
        print(f"timelock=ACTIVE ({mins}m {secs}s remaining)")
        print(f"timelock_expires={tl['expires_utc']}")
        print(f"timelock_reason={tl['reason']}")
        print(f"timelock_extensions={tl['extensions']}")
    else:
        print("timelock=inactive")
    return 0


def cmd_set_pin(_: argparse.Namespace) -> int:
    state_store = StateStore(str(_state_path()))
    st = state_store.load()

    if has_pin(st):
        # Verify old PIN first
        old = _prompt_gui("Argus", "Enter current PIN:", mask=True)
        if not old:
            print("Cancelled.")
            return 1
        result = check_pin(st, old)
        if not result.ok:
            print(f"Current PIN incorrect: {result.reason}")
            return 1

    new_pin = _prompt_gui("Argus", "Enter new PIN (4-8 digits):", mask=True)
    if not new_pin:
        print("Cancelled.")
        return 1

    confirm = _prompt_gui("Argus", "Confirm new PIN:", mask=True)
    if new_pin != confirm:
        print("PINs do not match.")
        return 1

    result = set_pin(st, new_pin)
    if not result.ok:
        print(f"Invalid PIN: {result.reason}")
        return 1

    state_store.save(st)
    print("PIN set successfully.")
    return 0


def _handle_failed_disarm(cfg, st, state_store, sms) -> None:
    """Extend timelock on failed disarm if applicable."""
    if cfg.timelock.enabled and cfg.timelock.extend_on_failed_disarm_minutes > 0:
        if is_timelocked(st):
            new_expiry = extend_timelock(
                st, cfg.timelock.extend_on_failed_disarm_minutes, reason="failed_disarm"
            )
            state_store.save(st)
            if new_expiry:
                print(
                    f"WARNING: TimeLock EXTENDED by {cfg.timelock.extend_on_failed_disarm_minutes} min "
                    f"due to failed disarm. New expiry: {new_expiry.strftime('%H:%M:%S UTC')}"
                )
                sms.send(
                    f"[Argus] Failed disarm attempt! TimeLock extended by "
                    f"{cfg.timelock.extend_on_failed_disarm_minutes} min."
                )


def cmd_disarm(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    state_store = StateStore(str(_state_path()))
    st = state_store.load()

    if not st.get("enabled", False):
        print("Argus already off.")
        return 0

    # TimeLock check - cannot disarm while timelocked
    if is_timelocked(st):
        locked, remaining = check_timelock(st)
        mins = remaining // 60
        secs = remaining % 60
        print(f"TIMELOCK ACTIVE - system isolated for {mins}m {secs}s more.")
        print("Cannot disarm until timelock expires.")
        print("Network adapters are disabled. Do not attempt to bypass.")
        return 1

    sms = SmsSink(
        enabled=cfg.sms.enabled,
        account_sid=cfg.sms.twilio_account_sid,
        auth_token=cfg.sms.twilio_auth_token,
        from_number=cfg.sms.from_number,
        to_number=cfg.sms.to_number,
    )

    pin_configured = has_pin(st)
    sms_configured = cfg.sms.enabled

    # ── Step 1: PIN verification (if configured) ──
    if pin_configured:
        pin_input = (getattr(args, "pin", "") or "").strip()
        if not pin_input:
            pin_input = _prompt_gui("Argus", "Enter your PIN to disarm:", mask=True)
        if not pin_input:
            print("No PIN entered. Argus remains active.")
            return 1
        pin_result = check_pin(st, pin_input)
        if not pin_result.ok:
            print(f"Disarm failed: {pin_result.reason}")
            _handle_failed_disarm(cfg, st, state_store, sms)
            return 1

    # ── Step 2: SMS 2FA verification (if configured and PIN was ok) ──
    if sms_configured:
        code = (getattr(args, "code", "") or "").strip()
        if not code:
            sms_code = issue_disarm_code(st)
            state_store.save(st)
            sms.send(f"[Argus] Disarm code: {sms_code}. Valid for 60 seconds.")
            print("SMS verification code sent.")
            code = _prompt_gui("Argus", "Enter SMS verification code:")
            if not code:
                print("No code entered. Argus remains active.")
                return 1
        status = verify_disarm_code(st, code)
        state_store.save(st)
        if not status.ok:
            print(f"Disarm failed: {status.reason}")
            _handle_failed_disarm(cfg, st, state_store, sms)
            return 1

    # ── Step 3: Fallback - if neither PIN nor SMS, use legacy code flow ──
    if not pin_configured and not sms_configured:
        code = (getattr(args, "code", "") or "").strip()
        if not code:
            code = _prompt_gui("Argus", "Enter disarm code:")
            if not code:
                print("No code entered. Argus remains active.")
                return 1
        # Without PIN or SMS, we can't verify - just accept any input
        # (user should configure at least one auth method)
        print("WARNING: No PIN or SMS configured. Set a PIN with: argus set-pin")

    # ── Disarm successful ──
    if st.get("timelock_active"):
        release_timelock(st)
        print("TimeLock released. Network restored.")

    stop_pid(st.get("monitor_pid"))
    st["enabled"] = False
    st["monitor_pid"] = None
    st["current_state"] = "DISARMED"
    clear_disarm_state(st)
    state_store.save(st)
    print("Argus OFF")
    return 0


def cmd_install_lock_hooks(args: argparse.Namespace) -> int:
    install_lock_hooks(require_code=bool(args.require_code), config_path=args.config)
    print("Installed lock hooks.")
    return 0


def cmd_remove_lock_hooks(_: argparse.Namespace) -> int:
    remove_lock_hooks()
    print("Removed lock hooks.")
    return 0


def cmd_run_monitor(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    daemon = ArgusDaemon(cfg, state_store=StateStore(str(_state_path())), config_path=args.config)
    asyncio.run(daemon.run())
    return 0


def _ensure_tray_deps() -> bool:
    """Auto-install pystray and Pillow if missing. Returns True on success."""
    missing = []
    try:
        import pystray  # noqa: F401
    except ImportError:
        missing.append("pystray")
    try:
        import PIL  # noqa: F401
    except ImportError:
        missing.append("Pillow")
    if not missing:
        return True
    print(f"Installing tray dependencies: {', '.join(missing)} ...")
    ret = subprocess.call([sys.executable, "-m", "pip", "install", *missing])
    if ret != 0:
        print("Failed to install dependencies. Try manually: pip install pystray Pillow")
        return False
    return True


def cmd_tray(args: argparse.Namespace) -> int:
    if not _ensure_tray_deps():
        return 1
    from .tray import ArgusTray
    tray = ArgusTray(config_path=args.config)
    tray.run()
    return 0


def cmd_listener(args: argparse.Namespace) -> int:
    from .listener import serve
    serve(args.config)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="argus", description="Argus host sentinel")
    p.add_argument("--config", default="config.toml", help="Path to Argus TOML/JSON/YAML config")
    p.add_argument("--check-config", action="store_true", help="Validate config and exit (legacy flag)")

    sub = p.add_subparsers(dest="cmd", required=False)

    chk = sub.add_parser("check-config")
    chk.set_defaults(func=cmd_check_config)

    on = sub.add_parser("on")
    on.set_defaults(func=cmd_on)

    off = sub.add_parser("off")
    off.set_defaults(func=cmd_off)

    status = sub.add_parser("status")
    status.set_defaults(func=cmd_status)

    disarm = sub.add_parser("disarm")
    disarm.add_argument("--pin", default="", help="Disarm PIN")
    disarm.add_argument("--code", default="", help="SMS verification code")
    disarm.set_defaults(func=cmd_disarm)

    sp = sub.add_parser("set-pin", help="Set or change the disarm PIN")
    sp.set_defaults(func=cmd_set_pin)

    ih = sub.add_parser("install-lock-hooks")
    ih.add_argument(
        "--require-code",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Require disarm code on unlock.",
    )
    ih.set_defaults(func=cmd_install_lock_hooks)

    rh = sub.add_parser("remove-lock-hooks")
    rh.set_defaults(func=cmd_remove_lock_hooks)

    runm = sub.add_parser("run-monitor")
    runm.set_defaults(func=cmd_run_monitor)

    tray = sub.add_parser("tray", help="Launch system tray icon (requires pystray + Pillow)")
    tray.set_defaults(func=cmd_tray)

    listener = sub.add_parser("listener", help="Start LAN disarm HTTP listener")
    listener.set_defaults(func=cmd_listener)

    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if getattr(args, "check_config", False):
        return cmd_check_config(args)

    # Backward compatibility: no subcommand means check config only if requested,
    # otherwise behave like `run-monitor` for direct launches.
    if getattr(args, "cmd", None) is None:
        return cmd_run_monitor(args)

    return int(args.func(args))
