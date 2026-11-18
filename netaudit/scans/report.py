"""
Scan reports: the result of one scan, as stored (encrypted JSON) in the project's scans/ folder.

ScanReport is the base class with what EVERY scan has (when it ran, which devices answered,
notes, findings). Each kind of scan has its own subclass that adds its own fields:

    BaselineReport   the static config/state scan (adds: the links that were compared)
    (later)          long-running live-traffic scans (e.g. sample period, counters...)

A subclass:
  1. sets kind = "..." - stored in the JSON, so reading a file back knows which class to build
  2. adds its fields (dataclass fields WITH defaults - the base class fields already have them)
  3. overrides _fields_from_dict() / _summary() if its new fields need converting / showing
  4. is added to REPORT_KINDS at the bottom of this file
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import ClassVar

from ..models import Finding, Fix, FixInput, FixQuestion, FixTarget


@dataclass
class ScanReport:
    """Base class - create a subclass (BaselineReport...), not this one."""

    # ClassVar = a class attribute, NOT a dataclass field (like a static member in C++):
    # each subclass sets its own value, and it isn't an __init__ parameter.
    kind: ClassVar[str] = ""

    scan_type: str  # the name shown/used in file names: "baseline", "baseline-postfix"...
    started: datetime
    finished: datetime | None = None
    devices: dict[str, str] = field(default_factory=dict)  # ip -> hostname (scanned OK)
    failed: dict[str, str] = field(default_factory=dict)  # ip -> error message
    notes: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    # ---------- JSON conversion (json can't store datetime or dataclasses directly) ----------

    def to_dict(self) -> dict:
        data = asdict(self)  # all fields, including a subclass's; nested dataclasses become dicts
        data["kind"] = self.kind  # ClassVars aren't fields, so asdict() leaves it out
        data["started"] = self.started.isoformat(timespec="seconds")
        data["finished"] = self.finished.isoformat(timespec="seconds") if self.finished else None
        return data

    @staticmethod
    def from_dict(data: dict) -> ScanReport:
        """Rebuild a report from its JSON dict, as the subclass named by its "kind".
        @staticmethod = a plain function inside the class (no self/cls), like a C++ static method."""
        # Reports saved before there were subclasses have no "kind" - they were all baseline scans
        report_class = REPORT_KINDS[data.get("kind", "baseline")]
        # ** unpacks the dict into keyword arguments: report_class(scan_type=..., started=..., ...)
        return report_class(**report_class._fields_from_dict(data))

    @classmethod
    def _fields_from_dict(cls, data: dict) -> dict:
        """The base class fields, converted back from JSON. A subclass with its own fields
        overrides this: {**super()._fields_from_dict(data), "its_field": ...}."""
        findings = [
            # {**a, k: v} = a copy of dict a with key k replaced. asdict() turned the nested
            # dataclasses into plain dicts, so they're rebuilt here.
            Finding(**{**f, "fixes": [Fix(**x) for x in f["fixes"]], "fix_input": _fix_input(f.get("fix_input"))})
            for f in data["findings"]
        ]
        return {
            "scan_type": data["scan_type"],
            "started": datetime.fromisoformat(data["started"]),
            "finished": datetime.fromisoformat(data["finished"]) if data["finished"] else None,
            "devices": data["devices"],
            "failed": data["failed"],
            "notes": data["notes"],
            "findings": findings,
        }

    # ---------- display ----------

    def _summary(self) -> str:
        """The counts line under the title. Subclasses add their own counts."""
        return f"Devices scanned: {len(self.devices)}   failed: {len(self.failed)}"

    def format(self) -> str:
        """Human-readable report text."""
        lines = [
            f"Scan: {self.scan_type}   started {self.started:%Y-%m-%d %H:%M:%S}",
            self._summary(),  # calls the SUBCLASS's version if it has one (like a C++ virtual)
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


@dataclass
class BaselineReport(ScanReport):
    """The baseline scan: a one-time look at config and state, comparing both ends of links."""

    kind: ClassVar[str] = "baseline"

    links: list[str] = field(default_factory=list)  # "SW1 Et0/1 <-> SW2 Et0/1" - links compared

    @classmethod
    def _fields_from_dict(cls, data: dict) -> dict:
        # super() = the parent class's version (ScanReport._fields_from_dict), then add our field
        return {**super()._fields_from_dict(data), "links": data["links"]}

    def _summary(self) -> str:
        return f"{super()._summary()}   links compared: {len(self.links)}"


# Every kind of report, by the "kind" stored in its JSON. Add new subclasses here.
REPORT_KINDS: dict[str, type[ScanReport]] = {
    BaselineReport.kind: BaselineReport,
}


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
