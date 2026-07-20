from __future__ import annotations

import asyncio
import json
import os
import subprocess
from dataclasses import dataclass

from .types import ThreatSignal


@dataclass(slots=True)
class UsbMonitorConfig:
    enabled: bool = True
    poll_seconds: int = 10


class UsbMonitor:
    def __init__(self, cfg: UsbMonitorConfig) -> None:
        self.cfg = cfg
        self._known_devices: set[str] = set()
        self._primed = False

    async def start(self, queue: asyncio.Queue[ThreatSignal]) -> None:
        while True:
            for signal in self._poll_once():
                await queue.put(signal)
            await asyncio.sleep(max(5, int(self.cfg.poll_seconds)))

    def _poll_once(self) -> list[ThreatSignal]:
        devices = self._list_usb_storage()
        out: list[ThreatSignal] = []

        if not self._primed:
            self._known_devices = {d["instance_id"] for d in devices}
            self._primed = True
            return out

        for device in devices:
            instance_id = device["instance_id"]
            if instance_id in self._known_devices:
                continue
            self._known_devices.add(instance_id)
            out.append(
                ThreatSignal(
                    event_type="usb_device",
                    title="New USB storage device connected",
                    description=f"USB storage device appeared: {device['friendly_name']} ({instance_id})",
                    severity="high",
                    confidence=0.85,
                    category="collection",
                    details={
                        "instance_id": instance_id,
                        "friendly_name": device["friendly_name"],
                        "status": device["status"],
                    },
                    raw=device,
                )
            )

        return out

    @staticmethod
    def _list_usb_storage() -> list[dict]:
        if os.name != "nt":
            return UsbMonitor._list_usb_storage_linux()

        ps = (
            "Get-PnpDevice -Class USB | "
            "Where-Object { $_.InstanceId -match 'USBSTOR' } | "
            "Select-Object InstanceId,FriendlyName,Status | "
            "ConvertTo-Json -Compress"
        )
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps],
            capture_output=True,
            text=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        raw = (proc.stdout or "").strip()
        if not raw:
            return []
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return []
        items = parsed if isinstance(parsed, list) else [parsed]
        out = []
        for it in items:
            if not isinstance(it, dict):
                continue
            out.append(
                {
                    "instance_id": str(it.get("InstanceId", "") or ""),
                    "friendly_name": str(it.get("FriendlyName", "") or ""),
                    "status": str(it.get("Status", "") or ""),
                }
            )
        return out

    @staticmethod
    def _list_usb_storage_linux() -> list[dict]:
        """List USB storage devices on Linux using lsblk."""
        try:
            proc = subprocess.run(
                ["lsblk", "-J", "-o", "NAME,TYPE,TRAN,MODEL,SERIAL,SIZE"],
                capture_output=True,
                text=True,
            )
        except FileNotFoundError:
            return []
        raw = (proc.stdout or "").strip()
        if not raw:
            return []
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return []

        devices = parsed.get("blockdevices", [])
        out: list[dict] = []
        for dev in devices:
            if not isinstance(dev, dict):
                continue
            tran = str(dev.get("tran", "") or "").lower()
            if tran != "usb":
                continue
            name = str(dev.get("name", "") or "")
            model = str(dev.get("model", "") or "").strip()
            serial = str(dev.get("serial", "") or "").strip()
            size = str(dev.get("size", "") or "")
            # Use serial as instance_id if available, otherwise name
            instance_id = serial if serial else f"usb-{name}"
            friendly_name = f"{model} ({size})" if model else f"{name} ({size})"
            out.append({
                "instance_id": instance_id,
                "friendly_name": friendly_name,
                "status": "connected",
            })
        return out
