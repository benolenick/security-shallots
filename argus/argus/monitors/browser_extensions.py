from __future__ import annotations

import asyncio
import json
import os
from dataclasses import dataclass
from pathlib import Path

from .types import ThreatSignal


@dataclass(slots=True)
class BrowserExtensionConfig:
    enabled: bool = True
    poll_seconds: int = 300


class BrowserExtensionMonitor:
    def __init__(self, cfg: BrowserExtensionConfig) -> None:
        self.cfg = cfg
        self._known_extensions: set[str] = set()
        self._primed = False

    async def start(self, queue: asyncio.Queue[ThreatSignal]) -> None:
        while True:
            for signal in self._poll_once():
                await queue.put(signal)
            await asyncio.sleep(max(60, int(self.cfg.poll_seconds)))

    def _poll_once(self) -> list[ThreatSignal]:
        current = self._enumerate_extensions()
        out: list[ThreatSignal] = []

        if not self._primed:
            self._known_extensions = {e["key"] for e in current}
            self._primed = True
            return out

        for ext in current:
            key = ext["key"]
            if key in self._known_extensions:
                continue
            self._known_extensions.add(key)
            out.append(
                ThreatSignal(
                    event_type="browser_extension",
                    title="New browser extension detected",
                    description=(
                        f"New extension appeared in {ext['browser']}: "
                        f"{ext['extension_name']} ({ext['extension_id']})"
                    ),
                    severity="medium",
                    confidence=0.75,
                    category="collection",
                    details={
                        "browser": ext["browser"],
                        "extension_id": ext["extension_id"],
                        "extension_name": ext["extension_name"],
                    },
                    raw=ext,
                )
            )

        return out

    @staticmethod
    def _enumerate_extensions() -> list[dict]:
        results: list[dict] = []
        if os.name != "nt":
            results.extend(_scan_chromium_extensions_linux("chrome"))
            results.extend(_scan_chromium_extensions_linux("chromium"))
            results.extend(_scan_firefox_extensions_linux())
        else:
            results.extend(_scan_chromium_extensions("chrome"))
            results.extend(_scan_chromium_extensions("edge"))
            results.extend(_scan_firefox_extensions())
        return results


def _scan_chromium_extensions(browser: str) -> list[dict]:
    if browser == "chrome":
        base_env = r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Extensions"
    else:
        base_env = r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Extensions"

    base = Path(os.path.expandvars(base_env))
    if not base.is_dir():
        return []

    results: list[dict] = []
    for ext_dir in base.iterdir():
        if not ext_dir.is_dir():
            continue
        extension_id = ext_dir.name
        name = _read_chromium_manifest_name(ext_dir)
        results.append(
            {
                "key": f"{browser}:{extension_id}",
                "browser": browser,
                "extension_id": extension_id,
                "extension_name": name,
            }
        )
    return results


def _read_chromium_manifest_name(ext_dir: Path) -> str:
    """Return the name field from manifest.json in the latest version subfolder."""
    try:
        version_dirs = [d for d in ext_dir.iterdir() if d.is_dir()]
        if not version_dirs:
            return ""
        latest = sorted(version_dirs, key=lambda d: d.name)[-1]
        manifest_path = latest / "manifest.json"
        data = json.loads(manifest_path.read_text(encoding="utf-8", errors="replace"))
        return str(data.get("name", ""))
    except Exception:
        return ""


def _scan_firefox_extensions() -> list[dict]:
    import glob

    profiles_base = Path(os.path.expandvars(r"%APPDATA%\Mozilla\Firefox\Profiles"))
    if not profiles_base.is_dir():
        return []

    results: list[dict] = []
    for extensions_json in glob.glob(str(profiles_base / "*" / "extensions.json")):
        try:
            data = json.loads(
                Path(extensions_json).read_text(encoding="utf-8", errors="replace")
            )
            addons = data.get("addons", [])
            for addon in addons:
                if not isinstance(addon, dict):
                    continue
                addon_id = str(addon.get("id", "") or "")
                addon_name = str(addon.get("defaultLocale", {}).get("name", "") or addon_id)
                results.append(
                    {
                        "key": f"firefox:{addon_id}",
                        "browser": "firefox",
                        "extension_id": addon_id,
                        "extension_name": addon_name,
                    }
                )
        except Exception:
            continue

    return results


def _scan_chromium_extensions_linux(browser: str) -> list[dict]:
    """Scan Chromium-based extension directories on Linux."""
    home = Path.home()
    if browser == "chrome":
        base = home / ".config" / "google-chrome" / "Default" / "Extensions"
    else:
        base = home / ".config" / "chromium" / "Default" / "Extensions"

    if not base.is_dir():
        return []

    results: list[dict] = []
    for ext_dir in base.iterdir():
        if not ext_dir.is_dir():
            continue
        extension_id = ext_dir.name
        name = _read_chromium_manifest_name(ext_dir)
        results.append(
            {
                "key": f"{browser}:{extension_id}",
                "browser": browser,
                "extension_id": extension_id,
                "extension_name": name,
            }
        )
    return results


def _scan_firefox_extensions_linux() -> list[dict]:
    """Scan Firefox extension profiles on Linux."""
    import glob

    profiles_base = Path.home() / ".mozilla" / "firefox"
    if not profiles_base.is_dir():
        return []

    results: list[dict] = []
    for extensions_json in glob.glob(str(profiles_base / "*" / "extensions.json")):
        try:
            data = json.loads(
                Path(extensions_json).read_text(encoding="utf-8", errors="replace")
            )
            addons = data.get("addons", [])
            for addon in addons:
                if not isinstance(addon, dict):
                    continue
                addon_id = str(addon.get("id", "") or "")
                addon_name = str(addon.get("defaultLocale", {}).get("name", "") or addon_id)
                results.append(
                    {
                        "key": f"firefox:{addon_id}",
                        "browser": "firefox",
                        "extension_id": addon_id,
                        "extension_name": addon_name,
                    }
                )
        except Exception:
            continue

    return results
