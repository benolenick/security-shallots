"""Argus system tray icon.

Provides visual state indicator + right-click menu for arm/disarm/off.
Requires optional deps: pystray, Pillow.
Install: pip install argus-agent[tray]
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any


# State → color mapping
_STATE_COLORS = {
    "ARMED_HOME": (63, 185, 80),      # green
    "ARMED_AWAY": (210, 153, 34),      # amber
    "LOCKDOWN":   (248, 81, 73),       # red
    "DISARMED":   (110, 118, 129),     # gray
}

_STATE_LABELS = {
    "ARMED_HOME": "Armed (Home)",
    "ARMED_AWAY": "Armed (Away)",
    "LOCKDOWN":   "LOCKDOWN",
    "DISARMED":   "Disarmed",
}


def _read_state(state_path: Path) -> dict[str, Any]:
    """Read ~/.argus/state.json, return empty dict on failure."""
    try:
        return json.loads(state_path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _make_icon(state: str, size: int = 64):
    """Generate a shield-shaped icon colored by state."""
    from PIL import Image, ImageDraw

    color = _STATE_COLORS.get(state, (110, 118, 129))
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Shield shape: pointed bottom, rounded top
    cx, cy = size // 2, size // 2
    points = [
        (cx, size - 4),         # bottom point
        (6, int(size * 0.55)),  # left mid
        (6, int(size * 0.2)),   # left top
        (cx, 4),                # top center
        (size - 6, int(size * 0.2)),   # right top
        (size - 6, int(size * 0.55)),  # right mid
    ]
    draw.polygon(points, fill=color)

    # Inner lighter area for depth
    inner = [
        (cx, size - 10),
        (12, int(size * 0.55)),
        (12, int(size * 0.25)),
        (cx, 10),
        (size - 12, int(size * 0.25)),
        (size - 12, int(size * 0.55)),
    ]
    lighter = tuple(min(255, c + 40) for c in color)
    draw.polygon(inner, fill=(*lighter, 80))

    return img


def _toast_notification(title: str, msg: str) -> None:
    """Windows toast notification via PowerShell (best-effort)."""
    try:
        ps = (
            "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, "
            "ContentType = WindowsRuntime] > $null; "
            "$xml = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent(1); "
            f"$xml.GetElementsByTagName('text')[0].AppendChild($xml.CreateTextNode('{title}')) > $null; "
            f"$xml.GetElementsByTagName('text')[1].AppendChild($xml.CreateTextNode('{msg}')) > $null; "
            "$toast = [Windows.UI.Notifications.ToastNotification]::new($xml); "
            "[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('Argus').Show($toast)"
        )
        subprocess.Popen(
            ["powershell", "-WindowStyle", "Hidden", "-Command", ps],
            creationflags=0x00000008 if sys.platform == "win32" else 0,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        pass


def _run_argus_cmd(*args: str, config_path: str = "config.toml") -> None:
    """Run an argus CLI command as a subprocess."""
    cmd = [sys.executable, "-m", "argus", "--config", config_path, *args]
    try:
        subprocess.Popen(
            cmd,
            creationflags=0x00000008 if sys.platform == "win32" else 0,
        )
    except Exception:
        pass


class ArgusTray:
    """System tray icon that polls state.json and provides arm/disarm menu."""

    def __init__(self, config_path: str = "config.toml", poll_seconds: float = 2.0):
        self.config_path = config_path
        self.poll_seconds = poll_seconds
        self.state_path = (Path.home() / ".argus" / "state.json").resolve()
        self._last_state = ""
        self._icon = None
        self._stop = threading.Event()

    def run(self) -> None:
        """Start the tray icon (blocks until quit)."""
        import pystray

        st = _read_state(self.state_path)
        current = st.get("current_state", "DISARMED")
        self._last_state = current

        menu = pystray.Menu(
            pystray.MenuItem("Arm", lambda: self._action("on")),
            pystray.MenuItem("Disarm", lambda: self._action("disarm")),
            pystray.MenuItem("Turn Off", lambda: self._action("off")),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Status", lambda: self._action("status")),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Quit", self._quit),
        )

        self._icon = pystray.Icon(
            name="argus",
            icon=_make_icon(current),
            title=f"Argus - {_STATE_LABELS.get(current, current)}",
            menu=menu,
        )

        # Start poll thread
        poll_thread = threading.Thread(target=self._poll_loop, daemon=True)
        poll_thread.start()

        self._icon.run()

    def _poll_loop(self) -> None:
        """Poll state.json and update icon on changes."""
        while not self._stop.is_set():
            time.sleep(self.poll_seconds)
            try:
                st = _read_state(self.state_path)
                current = st.get("current_state", "DISARMED")
                if current != self._last_state:
                    old = self._last_state
                    self._last_state = current
                    if self._icon:
                        self._icon.icon = _make_icon(current)
                        label = _STATE_LABELS.get(current, current)
                        # TimeLock status in tooltip
                        if st.get("timelock_active"):
                            exp = st.get("timelock_expires_utc", "?")
                            label = f"TIMELOCKED (expires {exp})"
                        self._icon.title = f"Argus - {label}"
                    _toast_notification(
                        "Argus",
                        f"State changed: {_STATE_LABELS.get(old, old)} → {_STATE_LABELS.get(current, current)}",
                    )
                    if st.get("timelock_active") and current == "LOCKDOWN":
                        _toast_notification(
                            "Argus TIMELOCK",
                            "System isolated! All network disabled. Cannot disarm until timer expires.",
                        )
            except Exception:
                pass

    def _action(self, cmd: str) -> None:
        """Run an argus CLI command."""
        _run_argus_cmd(cmd, config_path=self.config_path)

    def _quit(self) -> None:
        """Stop the tray icon."""
        self._stop.set()
        if self._icon:
            self._icon.stop()
