"""
ScanReport: the result of one scan, as stored (encrypted JSON) in the project's scans/ folder.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime

from ..models import Finding, Fix, FixInput, FixQuestion, FixTarget


@dataclass
class ScanReport:
    scan_type: str  # "baseline", "baseline-postfix"...
    started: datetime
    finished: datetime | None = None
    devices: dict[str, str] = field(default_factory=dict)  # ip -> hostname (scanned OK)
    failed: dict[str, str] = field(default_factory=dict)  # ip -> error message
    links: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    # ---------- JSON conversion (json can't store datetime or dataclasses directly) ----------

    def to_dict(self) -> dict:
        data = asdict(self)  # converts nested dataclasses (Findings, Fixes) to dicts too
        data["started"] = self.started.isoformat(timespec="seconds")
        data["finished"] = self.finished.isoformat(timespec="seconds") if self.finished else None
        return data

    @classmethod
    def from_dict(cls, data: dict) -> "ScanReport":
        findings = [
            # {**a, k: v} = a copy of dict a with key k replaced. asdict() turned the nested
            # dataclasses into plain dicts, so they're rebuilt here.
            Finding(**{**f, "fixes": [Fix(**x) for x in f["fixes"]], "fix_input": _fix_input(f.get("fix_input"))})
            for f in data["findings"]
        ]
        return cls(
            scan_type=data["scan_type"],
            started=datetime.fromisoformat(data["started"]),
            finished=datetime.fromisoformat(data["finished"]) if data["finished"] else None,
            devices=data["devices"],
            failed=data["failed"],
            links=data["links"],
            notes=data["notes"],
            findings=findings,
        )

    # ---------- display ----------

    def format(self) -> str:
        """Human-readable report text."""
        lines = [
            f"Scan: {self.scan_type}   started {self.started:%Y-%m-%d %H:%M:%S}",
            f"Devices scanned: {len(self.devices)}   failed: {len(self.failed)}   links compared: {len(self.links)}",
        ]
        for ip, error in self.failed.items():
            lines.append(f"  ! {ip}: {error}")
        for note in self.notes:
            lines.append(f"  - {note}")
        if not self.findings:
            lines.append("\nNo findings.")
            return "\n".join(lines)

        counts = {s: sum(f.severity == s for f in self.findings) for s in ("high", "medium", "low")}
        lines.append(f"\nFindings: {len(self.findings)}  (high {counts['high']}, medium {counts['medium']}, low {counts['low']})")
        for number, finding in enumerate(self.findings, start=1):
            lines.append(format_finding(number, finding))
        return "\n".join(lines)


def _fix_input(data: dict | None) -> FixInput | None:
    if data is None:
        return None
    return FixInput(**{**data,
                       "targets": [FixTarget(**t) for t in data["targets"]],
                       "followups": [FixQuestion(**q) for q in data.get("followups", [])]})
    # .get(..., []): reports saved before follow-up questions existed don't have the key


def format_finding(number: int, finding: Finding, with_commands: bool = False) -> str:
    if finding.fix_input:
        fix_tag = "auto-fix, asks for a value"
    elif finding.fixes:
        fix_tag = "auto-fix available"
    else:
        fix_tag = "manual fix"
    lines = [
        f"\n{number:>3}. [{finding.severity.upper()}] {finding.location}   ({finding.check}, {fix_tag})",
        f"     {finding.message}",
        f"     Fix: {finding.fix_description}",
    ]
    if with_commands:
        for fix in finding.fixes:
            lines.append(f"       {fix.hostname} ({fix.host_ip}):")
            lines.extend(f"         {cmd}" for cmd in fix.commands)
        if finding.fix_input:
            default = f" (suggested: {finding.fix_input.default})" if finding.fix_input.default else ""
            devices = sorted({t.hostname for t in finding.fix_input.targets})
            lines.append(f"       Needs a value: {finding.fix_input.question}{default} - changes {', '.join(devices)}")
            for question in finding.fix_input.followups:
                lines.append(f"       + {question.question} (suggested: {question.default})")
    return "\n".join(lines)
