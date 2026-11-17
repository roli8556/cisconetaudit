"""
Running a scan end to end: collect a snapshot from every host, run the checks, build a report.

No input()/print() here - progress is reported through a callback, so the same code can be
driven from the menu now and from something else later.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime

from ..collectors.ssh import CollectorError, SshCollector
from ..models import DeviceSnapshot, RunningConfig
from ..project import Project
from .baseline import BaselineScan
from .report import ScanReport

Progress = Callable[[str], None]  # receives one status line, e.g. "192.168.100.11 OK"


def collect_snapshots(
    project: Project, collector: SshCollector, progress: Progress
) -> tuple[list[DeviceSnapshot], dict[str, str]]:
    """Snapshot every host. Returns (snapshots, {ip: error} for hosts that failed)."""
    snapshots: list[DeviceSnapshot] = []
    failed: dict[str, str] = {}
    for host in project.hosts:
        try:
            snapshot = collector.fetch_snapshot(host)
        except CollectorError as exc:
            failed[host.ip] = str(exc)
            project.log.warning("Scan: %s failed: %s", host.ip, exc)
            progress(f"{host.ip}  FAILED: {exc}")
            continue
        # The scan read the running-config anyway - keep it, like "Fetch running-configs" does.
        project.save_config(RunningConfig(host.ip, snapshot.hostname, snapshot.running_config, snapshot.collected_at))
        snapshots.append(snapshot)
        progress(f"{host.ip}  OK  {snapshot.hostname}: {len(snapshot.interfaces)} interfaces, "
                 f"{len(snapshot.cdp_neighbors)} CDP neighbors, {len(snapshot.ospf_neighbors)} OSPF neighbors")
    return snapshots, failed


def run_baseline(project: Project, collector: SshCollector, progress: Progress, scan_type: str = "baseline") -> ScanReport:
    report = ScanReport(scan_type=scan_type, started=datetime.now())
    project.log.info("Scan started: %s (%d hosts)", scan_type, len(project.hosts))

    snapshots, report.failed = collect_snapshots(project, collector, progress)
    findings, links = BaselineScan().run(snapshots)

    report.devices = {s.host_ip: s.hostname for s in snapshots}
    report.links = [link.location for link in links]
    report.notes = [f"{s.hostname}: {note}" for s in snapshots for note in s.notes]
    report.findings = findings
    report.finished = datetime.now()

    project.save_scan(report)
    project.log.info("Scan finished: %s - %d findings on %d links", scan_type, len(findings), len(links))
    for finding in findings:
        project.log.info("Finding [%s] %s %s: %s", finding.severity, finding.check, finding.location, finding.message)
    return report
