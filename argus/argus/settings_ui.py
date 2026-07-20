"""Argus Settings UI — tkinter panel for configuring Argus at runtime.

Launched from the tray menu. Allows changing:
- Lockdown mode (reactive / passive)
- TimeLock duration (minutes)
- Network isolation on/off
- PIN (set / change)
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

log = logging.getLogger("argus.settings_ui")


def _load_config_raw(config_path: str) -> dict[str, Any]:
    """Load config file as raw dict."""
    p = Path(config_path)
    if not p.exists():
        return {}
    raw = p.read_text(encoding="utf-8")
    if p.suffix.lower() in {".toml", ".tml"}:
        try:
            import tomllib
            return tomllib.loads(raw)
        except Exception:
            return {}
    import json
    try:
        return json.loads(raw)
    except Exception:
        return {}


def _save_config_toml(config_path: str, data: dict) -> None:
    """Write config dict back as TOML (simplified key=value writer)."""
    # We only update the [argus.timelock] section in-place
    p = Path(config_path)
    if not p.exists():
        return

    lines = p.read_text(encoding="utf-8").splitlines()
    new_lines = []
    in_timelock = False

    for line in lines:
        stripped = line.strip()
        if stripped == "[argus.timelock]":
            in_timelock = True
            new_lines.append(line)
            # Write updated values
            tl = data.get("argus", {}).get("timelock", {})
            new_lines.append(f'enabled = {str(tl.get("enabled", True)).lower()}')
            new_lines.append(f'lockdown_mode = "{tl.get("lockdown_mode", "reactive")}"')
            new_lines.append(f'duration_minutes = {tl.get("duration_minutes", 15)}')
            new_lines.append(f'network_isolation = {str(tl.get("network_isolation", True)).lower()}')
            new_lines.append(f'extend_on_failed_disarm_minutes = {tl.get("extend_on_failed_disarm_minutes", 5)}')
            continue
        elif in_timelock:
            if stripped.startswith("[") and stripped != "[argus.timelock]":
                in_timelock = False
                new_lines.append(line)
            # Skip old timelock lines (we already wrote the new ones)
            elif stripped and not stripped.startswith("#"):
                continue
            else:
                new_lines.append(line)
            continue
        else:
            new_lines.append(line)

    p.write_text("\n".join(new_lines) + "\n", encoding="utf-8")


def open_settings(config_path: str = "config.toml") -> None:
    """Open the Argus settings window."""
    try:
        import tkinter as tk
        from tkinter import ttk, messagebox
    except ImportError:
        log.error("tkinter not available")
        return

    from .core import StateStore, has_pin, set_pin, check_pin, validate_pin_format

    state_store = StateStore(str((Path.home() / ".argus" / "state.json").resolve()))

    # Load current config
    raw = _load_config_raw(config_path)
    argus = raw.get("argus", raw if "guard" in raw else {})
    tl = argus.get("timelock", {}) if isinstance(argus.get("timelock"), dict) else {}

    root = tk.Tk()
    root.title("Argus Settings")
    root.geometry("420x480")
    root.resizable(False, False)

    try:
        root.configure(bg="#1a1b26")
    except Exception:
        pass

    style = ttk.Style()
    try:
        style.theme_use("clam")
    except Exception:
        pass

    # ── TimeLock Section ──
    frame_tl = ttk.LabelFrame(root, text="TimeLock", padding=10)
    frame_tl.pack(fill="x", padx=15, pady=(15, 5))

    # Enabled
    var_enabled = tk.BooleanVar(value=tl.get("enabled", True))
    ttk.Checkbutton(frame_tl, text="TimeLock enabled", variable=var_enabled).grid(
        row=0, column=0, columnspan=2, sticky="w", pady=2
    )

    # Lockdown mode
    ttk.Label(frame_tl, text="Lockdown mode:").grid(row=1, column=0, sticky="w", pady=2)
    var_mode = tk.StringVar(value=tl.get("lockdown_mode", "reactive"))
    mode_combo = ttk.Combobox(frame_tl, textvariable=var_mode, values=["reactive", "passive"], state="readonly", width=15)
    mode_combo.grid(row=1, column=1, sticky="w", pady=2)

    # Duration
    ttk.Label(frame_tl, text="Duration (minutes):").grid(row=2, column=0, sticky="w", pady=2)
    var_duration = tk.IntVar(value=tl.get("duration_minutes", 15))
    dur_spin = ttk.Spinbox(frame_tl, from_=1, to=120, textvariable=var_duration, width=8)
    dur_spin.grid(row=2, column=1, sticky="w", pady=2)

    # Network isolation
    var_netiso = tk.BooleanVar(value=tl.get("network_isolation", True))
    ttk.Checkbutton(frame_tl, text="Kill network on lockdown", variable=var_netiso).grid(
        row=3, column=0, columnspan=2, sticky="w", pady=2
    )

    # Extend on failed disarm
    ttk.Label(frame_tl, text="Extend on failed disarm (min):").grid(row=4, column=0, sticky="w", pady=2)
    var_extend = tk.IntVar(value=tl.get("extend_on_failed_disarm_minutes", 5))
    ext_spin = ttk.Spinbox(frame_tl, from_=0, to=60, textvariable=var_extend, width=8)
    ext_spin.grid(row=4, column=1, sticky="w", pady=2)

    # Mode descriptions
    desc_frame = ttk.Frame(frame_tl)
    desc_frame.grid(row=5, column=0, columnspan=2, sticky="w", pady=(8, 0))
    desc_label = ttk.Label(desc_frame, text="", wraplength=350, foreground="gray")
    desc_label.pack(anchor="w")

    def update_desc(*_):
        m = var_mode.get()
        if m == "reactive":
            desc_label.config(text="Reactive: Kills all network + locks workstation for the timer duration. Use for endpoints you can physically access.")
        else:
            desc_label.config(text="Passive: Alerts + evidence only. Network stays up. Use for remote servers (SSH remains available).")

    var_mode.trace_add("write", update_desc)
    update_desc()

    # ── PIN Section ──
    frame_pin = ttk.LabelFrame(root, text="Disarm PIN", padding=10)
    frame_pin.pack(fill="x", padx=15, pady=5)

    st = state_store.load()
    pin_status = "PIN is set" if has_pin(st) else "No PIN configured"
    pin_label = ttk.Label(frame_pin, text=pin_status)
    pin_label.grid(row=0, column=0, sticky="w", pady=2)

    def change_pin():
        st_now = state_store.load()
        if has_pin(st_now):
            from tkinter import simpledialog
            old = simpledialog.askstring("Argus", "Enter current PIN:", show="*", parent=root)
            if not old:
                return
            result = check_pin(st_now, old)
            if not result.ok:
                messagebox.showerror("Error", "Current PIN is incorrect.", parent=root)
                return

        from tkinter import simpledialog
        new = simpledialog.askstring("Argus", "Enter new PIN (4-8 digits):", show="*", parent=root)
        if not new:
            return
        confirm = simpledialog.askstring("Argus", "Confirm new PIN:", show="*", parent=root)
        if new != confirm:
            messagebox.showerror("Error", "PINs do not match.", parent=root)
            return

        v = validate_pin_format(new)
        if not v.ok:
            messagebox.showerror("Error", f"Invalid PIN: {v.reason}", parent=root)
            return

        result = set_pin(st_now, new)
        if result.ok:
            state_store.save(st_now)
            pin_label.config(text="PIN is set")
            messagebox.showinfo("Success", "PIN updated.", parent=root)
        else:
            messagebox.showerror("Error", f"Failed: {result.reason}", parent=root)

    ttk.Button(frame_pin, text="Change PIN", command=change_pin).grid(row=0, column=1, sticky="e", padx=(10, 0))

    # ── Save / Cancel ──
    btn_frame = ttk.Frame(root)
    btn_frame.pack(fill="x", padx=15, pady=15)

    def save():
        # Build updated config
        updated = dict(raw)
        argus_section = updated.setdefault("argus", {})
        argus_section["timelock"] = {
            "enabled": var_enabled.get(),
            "lockdown_mode": var_mode.get(),
            "duration_minutes": var_duration.get(),
            "network_isolation": var_netiso.get(),
            "extend_on_failed_disarm_minutes": var_extend.get(),
        }

        try:
            _save_config_toml(config_path, updated)
            messagebox.showinfo("Saved", "Settings saved. Restart Argus for changes to take effect.", parent=root)
            root.destroy()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save: {e}", parent=root)

    ttk.Button(btn_frame, text="Save", command=save).pack(side="right", padx=(5, 0))
    ttk.Button(btn_frame, text="Cancel", command=root.destroy).pack(side="right")

    root.mainloop()
