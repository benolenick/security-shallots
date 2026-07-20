from __future__ import annotations

import logging
import os
import subprocess

log = logging.getLogger("argus.actions.network_isolation")

_BLOCK_IN_NAME = "Argus-TimeLock-BlockAll-In"
_BLOCK_OUT_NAME = "Argus-TimeLock-BlockAll-Out"


def _run_ps(script: str, timeout: int = 30) -> tuple[int, str]:
    """Run a PowerShell snippet.  Returns (returncode, combined output)."""
    if os.name != "nt":
        log.warning("_run_ps called on non-Windows platform")
        return 1, "not windows"
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return r.returncode, (r.stdout + r.stderr).strip()
    except Exception as exc:
        log.error("powershell failed: %s", exc)
        return 1, str(exc)


def _run_cmd(args: list[str], timeout: int = 30) -> tuple[int, str]:
    """Run a shell command on Linux.  Returns (returncode, combined output)."""
    try:
        r = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return r.returncode, (r.stdout + r.stderr).strip()
    except FileNotFoundError:
        log.error("command not found: %s", args[0])
        return 1, f"{args[0]} not found"
    except Exception as exc:
        log.error("command failed: %s", exc)
        return 1, str(exc)


def isolate_network() -> bool:
    """Kill all network connectivity.

    Windows: Two layers — disable adapters + firewall block-all rules.
    Linux: iptables DROP rules on INPUT/OUTPUT (preserving loopback).

    Returns True if isolation was successfully applied.
    """
    if os.name != "nt":
        return _isolate_network_linux()

    success = True

    # Layer 1: disable all network adapters
    rc, out = _run_ps(
        "Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } "
        "| ForEach-Object { "
        "  Disable-NetAdapter -Name $_.Name -Confirm:$false -ErrorAction SilentlyContinue; "
        "  $_.Name "
        "}"
    )
    if rc == 0:
        adapters = [a for a in out.splitlines() if a.strip()]
        log.info("disabled %d network adapter(s): %s", len(adapters), adapters)
    else:
        log.error("failed to disable adapters: %s", out)
        success = False

    # Layer 2: firewall block-all rules (inbound + outbound)
    fw_script = (
        f'Remove-NetFirewallRule -DisplayName "{_BLOCK_IN_NAME}" -ErrorAction SilentlyContinue; '
        f'Remove-NetFirewallRule -DisplayName "{_BLOCK_OUT_NAME}" -ErrorAction SilentlyContinue; '
        f'New-NetFirewallRule -DisplayName "{_BLOCK_IN_NAME}" '
        f"  -Direction Inbound -Action Block -Profile Any -Enabled True "
        f"  -Description 'Argus TimeLock: block all inbound' | Out-Null; "
        f'New-NetFirewallRule -DisplayName "{_BLOCK_OUT_NAME}" '
        f"  -Direction Outbound -Action Block -Profile Any -Enabled True "
        f"  -Description 'Argus TimeLock: block all outbound' | Out-Null; "
        f"Write-Output 'ok'"
    )
    rc, out = _run_ps(fw_script)
    if rc == 0 and "ok" in out:
        log.info("firewall block-all rules applied")
    else:
        log.error("failed to apply firewall block rules: %s", out)
        success = False

    return success


def _isolate_network_linux() -> bool:
    """Isolate network on Linux using iptables DROP rules (preserve loopback)."""
    success = True

    # Allow loopback first so we don't break local services
    for args in [
        ["iptables", "-I", "INPUT", "-i", "lo", "-j", "ACCEPT"],
        ["iptables", "-I", "OUTPUT", "-o", "lo", "-j", "ACCEPT"],
        ["iptables", "-I", "INPUT", "-m", "comment", "--comment", _BLOCK_IN_NAME, "-j", "DROP"],
        ["iptables", "-I", "OUTPUT", "-m", "comment", "--comment", _BLOCK_OUT_NAME, "-j", "DROP"],
    ]:
        rc, out = _run_cmd(args)
        if rc != 0:
            log.error("iptables command failed: %s — %s", args, out)
            success = False

    if success:
        log.info("Linux network isolation applied via iptables (loopback preserved)")
    return success


def restore_network() -> bool:
    """Restore network connectivity.

    Windows: Remove firewall block-all rules + re-enable adapters.
    Linux: Remove iptables DROP rules.

    Returns True if restoration succeeded.
    """
    if os.name != "nt":
        return _restore_network_linux()

    success = True

    # Remove firewall block rules first
    rc, out = _run_ps(
        f'Remove-NetFirewallRule -DisplayName "{_BLOCK_IN_NAME}" -ErrorAction SilentlyContinue; '
        f'Remove-NetFirewallRule -DisplayName "{_BLOCK_OUT_NAME}" -ErrorAction SilentlyContinue; '
        f"Write-Output 'ok'"
    )
    if rc != 0:
        log.error("failed to remove firewall block rules: %s", out)
        success = False
    else:
        log.info("firewall block-all rules removed")

    # Re-enable all disabled adapters
    rc, out = _run_ps(
        "Get-NetAdapter | Where-Object { $_.Status -eq 'Disabled' } "
        "| ForEach-Object { "
        "  Enable-NetAdapter -Name $_.Name -Confirm:$false -ErrorAction SilentlyContinue; "
        "  $_.Name "
        "}"
    )
    if rc == 0:
        adapters = [a for a in out.splitlines() if a.strip()]
        log.info("re-enabled %d network adapter(s): %s", len(adapters), adapters)
    else:
        log.error("failed to re-enable adapters: %s", out)
        success = False

    return success


def _restore_network_linux() -> bool:
    """Remove Argus iptables isolation rules on Linux."""
    success = True

    # Remove the DROP rules (by comment match)
    for args in [
        ["iptables", "-D", "INPUT", "-m", "comment", "--comment", _BLOCK_IN_NAME, "-j", "DROP"],
        ["iptables", "-D", "OUTPUT", "-m", "comment", "--comment", _BLOCK_OUT_NAME, "-j", "DROP"],
    ]:
        rc, out = _run_cmd(args)
        if rc != 0:
            log.warning("iptables delete may have already been removed: %s — %s", args, out)
            # Not necessarily a failure — rule may already be gone

    # Remove the loopback ACCEPT rules we added
    for args in [
        ["iptables", "-D", "INPUT", "-i", "lo", "-j", "ACCEPT"],
        ["iptables", "-D", "OUTPUT", "-o", "lo", "-j", "ACCEPT"],
    ]:
        rc, out = _run_cmd(args)
        if rc != 0:
            log.warning("loopback rule removal: %s — %s", args, out)

    log.info("Linux network isolation rules removed")
    return success


def is_isolated() -> bool:
    """Check if the firewall block-all rules are currently active."""
    if os.name != "nt":
        return _is_isolated_linux()
    rc, out = _run_ps(
        f'(Get-NetFirewallRule -DisplayName "{_BLOCK_IN_NAME}" -ErrorAction SilentlyContinue).Enabled'
    )
    return rc == 0 and "True" in out


def _is_isolated_linux() -> bool:
    """Check if Argus iptables DROP rules are present."""
    rc, out = _run_cmd(["iptables", "-L", "INPUT", "-n", "--line-numbers", "-v"])
    if rc != 0:
        return False
    return _BLOCK_IN_NAME in out
