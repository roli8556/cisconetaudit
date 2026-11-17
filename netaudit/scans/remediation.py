"""
Applying fixes from a scan.

Fixes are grouped per device so each device gets ONE config session (one revert timer, one
confirm) instead of one per finding. See SshCollector.apply_config() for the rollback safety net.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass, replace

from ..collectors.ssh import CollectorError, SshCollector
from ..models import Finding, Fix
from ..project import Project
from .runner import Progress


@dataclass
class FixResult:
    host_ip: str
    hostname: str
    ok: bool
    error: str = ""


_CHANNEL_GROUP = re.compile(r"channel-group (\d+) mode (\S+)")


def _walk(fix: Fix) -> Iterator[tuple[str, int, str]]:
    """Yield (current interface, index, command) for each command in a fix - IOS applies
    sub-commands to the last "interface ..." line, so we track that the same way."""
    interface = ""
    for index, command in enumerate(fix.commands):
        if command.startswith("interface "):
            interface = command.split(None, 1)[1]
        yield interface, index, command


def reconcile(findings: list[Finding]) -> list[Finding]:
    """Merge fixes that would undo each other.

    A port can get two fixes: the mode fix ("passive" -> "active") and a port-channel renumber
    (moves it with "channel-group <new> mode <mode from the scan>"). Applied one after the
    other, the renumber puts the OLD mode back. So: the renumber uses the new mode, and the
    mode fix is dropped for ports that are moved anyway.
    """
    new_modes: dict[tuple[str, str], str] = {}  # (host_ip, interface) -> corrected mode
    for finding in findings:
        if finding.check == "etherchannel-mode-mismatch":
            for fix in finding.fixes:
                for interface, _, command in _walk(fix):
                    if match := _CHANNEL_GROUP.fullmatch(command):
                        new_modes[(fix.host_ip, interface)] = match.group(2)

    moved: set[tuple[str, str]] = set()
    result = []
    for finding in findings:
        if finding.check != "etherchannel-group-mismatch":
            result.append(finding)
            continue
        fixes = []
        for fix in finding.fixes:
            commands = list(fix.commands)
            for interface, index, command in _walk(fix):
                match = _CHANNEL_GROUP.fullmatch(command)
                if match and (fix.host_ip, interface) in new_modes:
                    commands[index] = f"channel-group {match.group(1)} mode {new_modes[(fix.host_ip, interface)]}"
                if match:
                    moved.add((fix.host_ip, interface))
            fixes.append(replace(fix, commands=commands))
        result.append(replace(finding, fixes=fixes))

    # Drop mode fixes for ports the renumber already handles.
    final = []
    for finding in result:
        if finding.check == "etherchannel-mode-mismatch":
            kept = [fix for fix in finding.fixes
                    if not any((fix.host_ip, intf) in moved for intf, _, _ in _walk(fix) if intf)]
            if not kept:
                continue  # fully covered by the renumber
            finding = replace(finding, fixes=kept)
        final.append(finding)
    return final


def commands_per_device(findings: list[Finding], phase: int | None = None) -> dict[str, tuple[str, list[str]]]:
    """{ip: (hostname, [commands...])} for the fixes in these findings, in finding order -
    only those of one phase, or all of them (phase=None, for showing the whole plan).
    Conflicting fixes are merged first (see reconcile). A block of commands that's already
    planned for a device (same fix from two findings) is only added once."""
    plan: dict[str, tuple[str, list[str]]] = {}
    seen_blocks: set[tuple] = set()
    for finding in reconcile(findings):
        for fix in finding.fixes:
            if phase is not None and fix.phase != phase:
                continue
            block = (fix.host_ip, fix.phase, tuple(fix.commands))  # tuples are hashable, lists aren't
            if block in seen_blocks:
                continue
            seen_blocks.add(block)
            hostname, commands = plan.setdefault(fix.host_ip, (fix.hostname, []))
            commands.extend(fix.commands)
    return plan


def phases(findings: list[Finding]) -> list[int]:
    return sorted({fix.phase for finding in findings for fix in finding.fixes})


def apply_fixes(project: Project, collector: SshCollector, findings: list[Finding], progress: Progress) -> list[FixResult]:
    """Apply phase by phase: every device gets its phase-1 commands before any device gets
    phase-2 commands. If anything fails, later phases are skipped - they assume the earlier
    phase succeeded on BOTH ends of a link."""
    hosts = {h.ip: h for h in project.hosts}
    results: list[FixResult] = []
    all_phases = phases(findings)
    for phase in all_phases:
        if any(not r.ok for r in results):
            progress(f"Step {phase} skipped: an earlier step failed.")
            project.log.warning("Fix step %d skipped because an earlier step failed", phase)
            break
        if len(all_phases) > 1:
            progress(f"Step {phase} of {len(all_phases)}:")
        for ip, (hostname, commands) in commands_per_device(findings, phase).items():
            host = hosts.get(ip)
            if host is None:
                results.append(FixResult(ip, hostname, False, "host no longer in the project"))
                continue
            progress(f"{hostname} ({ip}): applying {len(commands)} command(s)...")
            project.log.info("Applying fix (step %d) on %s (%s): %s", phase, hostname, ip, " | ".join(commands))
            try:
                collector.apply_config(host, commands)
            except CollectorError as exc:
                project.log.error("Fix on %s (%s) failed: %s", hostname, ip, exc)
                progress(f"{hostname}: FAILED - {exc}")
                results.append(FixResult(ip, hostname, False, str(exc)))
                continue
            project.log.info("Fix on %s (%s) applied and confirmed", hostname, ip)
            progress(f"{hostname}: applied and confirmed")
            results.append(FixResult(ip, hostname, True))
    return results


def save_to_startup(project: Project, collector: SshCollector, results: list[FixResult], progress: Progress) -> None:
    hosts = {h.ip: h for h in project.hosts}
    saved: set[str] = set()
    for result in results:
        if not result.ok or result.host_ip in saved:  # a device can appear once per step
            continue
        saved.add(result.host_ip)
        try:
            collector.write_memory(hosts[result.host_ip])
        except CollectorError as exc:
            progress(f"{result.hostname}: saving failed - {exc}")
            project.log.error("write memory on %s failed: %s", result.host_ip, exc)
            continue
        progress(f"{result.hostname}: saved to startup-config")
        project.log.info("Running-config saved to startup-config on %s", result.host_ip)
