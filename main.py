"""
Entry point: create or load a project folder and manage its (encrypted) host list.

A project is just a folder - it can live anywhere on disk, e.g.
    C:\\Users\\sambr\\Documents\\netaudit-projects\\office-lab

Run:
    python main.py                      interactive menu
    python main.py --load "C:\\path\\to\\project"
"""

import argparse
import sys
from datetime import datetime, timedelta
from getpass import getpass
from pathlib import Path

from netaudit.collectors.hostkeys import KnownHosts
from netaudit.collectors.ssh import REVERT_MINUTES, CollectorError, SshCollector
from netaudit.inventory import Host, InventoryError, parse_hosts, validate_host
from netaudit.project import MIN_PASSWORD_LENGTH, VALID_METHODS, Project, ProjectError
from netaudit.models import Finding
from netaudit.scans import fix_inputs
from netaudit.scans.remediation import apply_fixes, commands_per_device, phases, save_to_startup
from netaudit.scans.report import ScanReport, format_finding
from netaudit.scans.runner import run_baseline
from netaudit.vault import VaultError

BANNER = """
███    ██ ███████ ████████  █████  ██    ██ ██████  ██ ████████
████   ██ ██         ██    ██   ██ ██    ██ ██   ██ ██    ██
██ ██  ██ █████      ██    ███████ ██    ██ ██   ██ ██    ██
██  ██ ██ ██         ██    ██   ██ ██    ██ ██   ██ ██    ██
██   ████ ███████    ██    ██   ██  ██████  ██████  ██    ██
"""


def ask_path(prompt: str, default: Path | None = None) -> Path:
    """Ask for a folder path. Strips the quotes Windows adds with 'Copy as path'."""
    suffix = f" [{default}]" if default else ""
    answer = input(f"{prompt}{suffix}: ").strip().strip('"').strip("'")
    if not answer and default:
        return default
    return Path(answer).expanduser()


def ask_method() -> str:
    while True:
        method = input(f"Collection method {VALID_METHODS}: ").strip().lower()
        if method in VALID_METHODS:
            return method
        print(f"  Please type one of: {', '.join(VALID_METHODS)}")


def ask_new_password() -> str:
    """Ask for a new project password twice. getpass() doesn't echo what you type."""
    while True:
        password = getpass(f"New project password (min {MIN_PASSWORD_LENGTH} chars): ")
        if len(password) < MIN_PASSWORD_LENGTH:
            print(f"  Too short - use at least {MIN_PASSWORD_LENGTH} characters.")
            continue
        if getpass("Repeat password: ") != password:
            print("  Passwords don't match.")
            continue
        return password


# ---------- project actions (work without a loaded project) ----------

def create_project() -> Project | None:
    parent = ask_path("Folder to create the project in", default=Path.cwd())
    name = input("Project name: ").strip()
    if not name:
        print("  Name can't be empty.")
        return None
    method = ask_method()
    print("  The project password encrypts hosts.enc. It can't be recovered if you forget it.")
    password = ask_new_password()
    try:
        project = Project.create(parent, name, password, method)
    except (ProjectError, OSError) as exc:
        print(f"  Error: {exc}")
        return None
    print(f"  Created {project.path.resolve()}")
    print("  Next: add devices with 'Add host' or 'Import hosts from file'.")
    return project


def load_project(path: Path | None = None) -> Project | None:
    if path is None:
        path = ask_path("Path to project folder")
    password = getpass("Project password: ")
    print("  Unlocking...")  # scrypt takes a moment - that's the point
    try:
        project = Project.load(path, password)
    except (ProjectError, VaultError, InventoryError) as exc:
        print(f"  Error: {exc}")
        return None
    print(f"  Loaded: {project}")
    return project


# ---------- host actions (need a loaded project) ----------

def list_hosts(project: Project) -> None:
    if not project.hosts:
        print("  No hosts yet.")
    for host in project.hosts:
        print(f"    - {host.ip:<16} user: {host.username}")  # password is never shown


def add_host(project: Project) -> None:
    ip = input("IP address: ").strip()
    username = input("SSH username: ").strip()
    password = getpass("SSH password: ")
    # "or None": an empty string is falsy in Python, so "" becomes None (= no enable password)
    enable_password = getpass("Enable password (leave empty if none): ") or None
    error = validate_host(ip, username, password, enable_password)
    if error:
        print(f"  Error: {error}")
        return
    try:
        project.add_hosts([Host(ip, username, password, enable_password)])
    except InventoryError as exc:
        print(f"  Error: {exc}")
        return
    print(f"  Added {ip}.")


def make_collector(project: Project) -> SshCollector | None:
    """An SshCollector for this project, or None (with a message) if SSH can't be used."""
    if project.config.collection_method != "ssh":
        print("  This needs SSH (this project uses SNMP).")
        return None
    if not project.hosts:
        print("  No hosts yet.")
        return None

    # A function defined inside a function. It can use "project" from the enclosing scope
    # (a closure - like a C++ lambda capturing [&project]). The collector calls it back.
    def confirm_new_key(ip: str, key_type: str, fp: str) -> bool:
        print(f"    Unknown SSH host key for {ip}:")
        print(f"      {key_type} {fp}")
        print("    Only accept if you trust the network path to this device (e.g. a lab, or")
        print("    you've checked the key on the console).")
        accepted = ask_yes_no("    Accept and remember this key?")
        if accepted:
            project.log.info("Host key accepted for %s: %s %s", ip, key_type, fp)
        return accepted

    return SshCollector(
        known_hosts=KnownHosts(project.known_hosts_path),
        confirm_new_key=confirm_new_key,
        port=project.config.ssh_port,
        timeout=project.config.ssh_timeout,
    )


def ask_yes_no(question: str) -> bool:
    """Default is No - anything but y/yes counts as no (safe for questions that change things)."""
    return input(f"{question} [y/N]: ").strip().lower() in ("y", "yes")


def choose_file(files: list[Path], what: str) -> Path | None:
    """Show a numbered list of files and let the user pick one."""
    if not files:
        print(f"  No saved {what} yet.")
        return None
    # enumerate(..., start=1) gives (1, first), (2, second)... - no manual index counter
    for number, path in enumerate(files, start=1):
        print(f"    {number:>3}) {path.stem}")  # stem = file name without extension
    choice = input("  Number to show: ").strip()
    if not choice.isdigit() or not 1 <= int(choice) <= len(files):
        print("  Invalid number.")
        return None
    return files[int(choice) - 1]


def fetch_configs(project: Project) -> None:
    """Fetch the running-config from every host and save it in configs/."""
    collector = make_collector(project)
    if collector is None:
        return
    ok = 0
    for host in project.hosts:
        print(f"  {host.ip}")
        try:
            config = collector.fetch_running_config(host)
        except CollectorError as exc:
            print(f"    FAILED: {exc}")
            project.log.warning("Fetching running-config from %s failed: %s", host.ip, exc)
            continue  # one broken device shouldn't stop the others
        path = project.save_config(config)
        print(f"    OK  {config.hostname} -> configs/{path.name}")
        ok += 1
    print(f"  Done: {ok}/{len(project.hosts)} config(s) saved.")


def view_config(project: Project) -> None:
    """Saved configs are encrypted, so this is the way to read them."""
    path = choose_file(project.list_configs(), "configs")
    if path is None:
        return
    try:
        print(project.read_config(path))
    except VaultError as exc:
        print(f"  Error: {exc}")


def view_log(project: Project) -> None:
    lines = project.read_log()
    print("\n".join(lines) if lines else "  The log is empty.")


# ---------- scans ----------

def scan_menu(project: Project) -> None:
    actions = {"1": baseline_scan, "2": view_scan}
    while True:
        print(f"\n=== netaudit | project: {project.config.name} | scan ===")
        print("1) Baseline scan (compares configs and state, changes nothing)")
        print("2) View saved scan report\nb) Back")
        choice = input("> ").strip().lower()
        if choice == "b":
            return
        if choice in actions:
            actions[choice](project)
        else:
            print("  Unknown choice.")


def baseline_scan(project: Project) -> None:
    collector = make_collector(project)
    if collector is None:
        return
    print("  Collecting state from all devices...")
    progress = lambda line: print(f"    {line}")  # lambda = small anonymous function
    report = run_baseline(project, collector, progress)
    print()
    print(report.format())
    if report.findings:
        handle_findings(project, collector, report)


MAX_SCAN_AGE = timedelta(days=1)  # older reports get a warning before fixes are offered


def format_age(age: timedelta) -> str:
    """timedelta -> "3 days" / "5 hours" / "12 minutes"."""
    if age.days >= 1:
        return f"{age.days} day{'s' if age.days > 1 else ''}"
    hours, minutes = age.seconds // 3600, age.seconds % 3600 // 60  # // is integer division
    return f"{hours} hour{'s' if hours != 1 else ''}" if hours else f"{minutes} minute{'s' if minutes != 1 else ''}"


def view_scan(project: Project) -> None:
    """Show a saved report - and, like right after a scan, offer to handle its findings."""
    path = choose_file(project.list_scans(), "scan reports")
    if path is None:
        return
    try:
        report = project.read_scan(path)
    except VaultError as exc:
        print(f"  Error: {exc}")
        return
    age = datetime.now() - report.started  # datetime - datetime = timedelta
    print(report.format())
    print(f"\n  This scan is {format_age(age)} old.")

    if not any(f.fixable for f in report.findings):
        return
    if not ask_yes_no("  Handle the findings from this scan now?"):
        return
    if age > MAX_SCAN_AGE:
        print(f"\n  WARNING: this scan is {format_age(age)} old. The network may have changed since -")
        print("  fixes are built from the state back then and could undo newer changes or no longer fit.")
        print("  Running a new scan (Scan menu -> 1) is safer.")
        if not ask_yes_no("  Use this old scan anyway?"):
            return
    collector = make_collector(project)
    if collector is None:
        return
    project.log.info("Handling findings from saved scan %s (%s old)", path.name, format_age(age))
    handle_findings(project, collector, report)


def ask_fix_value(finding: Finding) -> Finding | None:
    """For a fix that needs a value: ask until it's valid, then return the finding with its
    commands built. Fixes with ready-made commands are returned unchanged. None = skipped."""
    fix_input = finding.fix_input
    if fix_input is None:
        return finding
    hint = f"Enter = {fix_input.default}, " if fix_input.default else ""
    while True:
        value = input(f"     {fix_input.question} ({hint}s = skip): ").strip()
        if value.lower() == "s":
            print("     Skipped.")
            return None
        if not value:
            if not fix_input.default:
                print("     Please type a value (or s to skip).")
                continue
            value = fix_input.default
        error = fix_inputs.validate(fix_input, value)
        if error:
            print(f"     {error}")
            continue
        caution = fix_inputs.warning(fix_input, value)
        if caution and not ask_yes_no(f"     WARNING: {caution}. Use this value anyway?"):
            continue  # ask for the value again
        resolved = fix_inputs.resolve(finding, value)
        for fix in resolved.fixes:  # show exactly what will be sent
            print(f"       {fix.hostname}: " + " | ".join(fix.commands))
        return resolved


def handle_findings(project: Project, collector: SshCollector, report: ScanReport) -> None:
    """After a scan: let the user pick how to deal with the findings."""
    fixable = [f for f in report.findings if f.fixable]
    print(f"\n{len(fixable)} of {len(report.findings)} findings have an automatic fix; the rest must be fixed by hand.")
    if not fixable:
        return
    print("How do you want to handle them?")
    print("1) No fix - show me the commands, I'll do it myself")
    print("2) Step by step - ask me about each fix")
    print("3) Fix all automatically")
    choice = input("> ").strip()

    if choice == "2":
        selected = []
        for number, finding in enumerate(fixable, start=1):
            print(format_finding(number, finding, with_commands=True))
            if not ask_yes_no("     Apply this fix?"):
                continue
            resolved = ask_fix_value(finding)  # asks only if the fix needs a value
            if resolved:
                selected.append(resolved)
    elif choice == "3":
        needs_value = [f for f in fixable if f.fix_input]
        if needs_value:
            print(f"\n  {len(needs_value)} fix(es) need a value from you first:")
        selected = []
        for finding in fixable:
            if finding.fix_input:
                print(f"\n  [{finding.severity.upper()}] {finding.check}  {finding.location}")
                print(f"     {finding.fix_description}")
            resolved = ask_fix_value(finding)
            if resolved:
                selected.append(resolved)
    else:
        for number, finding in enumerate(fixable, start=1):
            print(format_finding(number, finding, with_commands=True))
        project.log.info("Scan findings: user chose to fix manually")
        return

    if not selected:
        print("  Nothing selected - no changes made.")
        return
    plan = commands_per_device(selected)
    print(f"\n  {len(selected)} fix(es) will change the configuration of {len(plan)} device(s):")
    for ip, (hostname, commands) in plan.items():
        print(f"    {hostname} ({ip}): {len(commands)} command(s)")
    steps = phases(selected)
    if len(steps) > 1:
        print(f"  Applied in {len(steps)} steps (all devices finish step 1 before step 2 starts),")
        print("  so both ends of a link stay compatible while they're changed. A failure stops later steps.")
    print(f"  Each device gets a {REVERT_MINUTES}-minute revert timer: if netaudit can't log in again to")
    print("  confirm the change, the device rolls it back by itself.")
    if not ask_yes_no("  Apply now?"):
        print("  Cancelled - no changes made.")
        return

    progress = lambda line: print(f"    {line}")
    results = apply_fixes(project, collector, selected, progress)
    if not any(r.ok for r in results):
        print("  No changes were applied.")
        return

    # Post-check: scan again and see which of the selected findings are really gone.
    print("\n  Re-scanning to verify...")
    after = run_baseline(project, collector, progress, scan_type="baseline-postfix")
    remaining = {f.key for f in after.findings}
    for finding in selected:
        status = "still present" if finding.key in remaining else "fixed"
        print(f"    {status:<14} {finding.check}  {finding.location}")
    new = [f for f in after.findings if f.key not in {g.key for g in report.findings}]
    if new:
        print(f"  WARNING: {len(new)} new finding(s) appeared after the changes:")
        for finding in new:
            print(f"    [{finding.severity}] {finding.check}  {finding.location}")

    print("\n  The changes are in the running-config only - a reload would undo them.")
    if ask_yes_no("  Save to startup-config (write memory) on the changed devices?"):
        save_to_startup(project, collector, results, progress)


def remove_host(project: Project) -> None:
    ip = input("IP address to remove: ").strip()
    try:
        project.remove_host(ip)
    except InventoryError as exc:
        print(f"  Error: {exc}")
        return
    print(f"  Removed {ip}.")


def import_hosts(project: Project) -> None:
    """Bulk-add hosts from a plaintext file (ip username password per line)."""
    path = ask_path("Plaintext file to import")
    try:
        new_hosts = parse_hosts(path.read_text(encoding="utf-8"))
        project.add_hosts(new_hosts)
    except (OSError, InventoryError) as exc:
        print(f"  Error: {exc}")
        return
    print(f"  Imported {len(new_hosts)} host(s).")
    print(f"  {path} still holds the passwords in plaintext.")
    if input("  Delete it now? [y/N]: ").strip().lower() == "y":
        path.unlink()
        print("  Deleted. (Also empty the Recycle Bin if it was ever there.)")


def start_menu() -> Project | None:
    """Loop until a project is created/loaded (returned) or the user quits (None)."""
    # Dispatch table: functions are objects in Python, so a dict can map a menu key
    # straight to the function to call (like a map of function pointers in C++).
    actions = {"1": create_project, "2": load_project}

    while True:
        print("\n=== netaudit ===")
        print("1) Create project\n2) Load project\nq) Quit")
        choice = input("> ").strip().lower()

        if choice == "q":
            return None
        if choice in actions:
            project = actions[choice]()
            if project:
                return project
        else:
            print("  Unknown choice.")


def project_menu(project: Project) -> None:
    """Work inside one project. The only way out is quitting the program."""
    actions = {
        "1": list_hosts,
        "2": add_host,
        "3": remove_host,
        "4": import_hosts,
        "5": fetch_configs,
        "6": view_config,
        "7": scan_menu,
        "8": view_log,
    }

    while True:
        print(f"\n=== netaudit | project: {project.config.name} ({project.path.resolve()}) ===")
        print("1) List hosts\n2) Add host\n3) Remove host\n4) Import hosts from file")
        print("5) Fetch running-configs\n6) View saved config\n7) Scan\n8) View log\nq) Quit")
        choice = input("> ").strip().lower()

        if choice == "q":
            return
        if choice in actions:
            actions[choice](project)
        else:
            print("  Unknown choice.")


def main() -> None:
    parser = argparse.ArgumentParser(description="netaudit - network security auditing")
    parser.add_argument("--load", type=Path, metavar="PATH", help="project folder to load on start")
    args = parser.parse_args()

    # The banner uses Unicode block characters (█). On Windows, redirected output defaults
    # to the old cp1252 encoding, which doesn't have them -> UnicodeEncodeError. Force UTF-8.
    sys.stdout.reconfigure(encoding="utf-8")
    print(BANNER)

    # --load skips the start menu; if loading fails, fall back to it.
    project = load_project(args.load) if args.load else None
    if project is None:
        project = start_menu()
    if project is not None:
        project_menu(project)


if __name__ == "__main__":
    main()
