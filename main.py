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
from netaudit.project import Project, ProjectError
from netaudit.models import Finding, FixQuestion
from netaudit.recent import RecentProjects, default_file
from netaudit.scans import fix_inputs
from netaudit.scans.remediation import apply_fixes, commands_per_device, phases, save_to_startup
from netaudit.scans.report import ScanReport, format_finding
from netaudit.scans.runner import run_baseline
from netaudit.vault import VaultError, WrongPasswordError

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


MIN_PASSWORD_LENGTH = 12


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

def prompt_create_project() -> Project | None:
    """Ask for folder, name and password, then let Project.create() make the project."""
    # Suggest the folder the most recent project lives in - projects are usually kept together
    recent = RECENT.entries
    default_parent = Path(recent[0].path).parent if recent else Path.cwd()
    parent = ask_path("Folder to create the project in", default=default_parent)
    name = input("Project name: ").strip()
    if not name:
        print("  Name can't be empty.")
        return None
    print("  The project password encrypts everything sensitive in the project: device credentials,")
    print("  saved configs, scan reports and the log. It can't be recovered if you forget it -")
    print("  without it, none of that data can be read.")
    password = ask_new_password()
    try:
        project = Project.create(parent, name, password)
    except (ProjectError, OSError) as exc:
        print(f"  Error: {exc}")
        return None
    print(f"  Created {project.path.resolve()}")
    print("  Next: add devices with 'Add host' or 'Import hosts from file'.")
    RECENT.remember(project.path, project.config.name)
    return project


def choose_project_path() -> Path | None:
    """Pick a recently used project, or type a path. None = cancelled."""
    while True:
        if not RECENT.entries:
            return ask_path("Path to project folder")
        print("  Recent projects:")
        for number, entry in enumerate(RECENT.entries, start=1):
            missing = "" if entry.exists else "   (not found - moved, deleted or drive not connected?)"
            print(f"    {number:>2}) {entry.name:<20} {entry.path}{missing}")
        print("     p) Enter a path   r) Remove a project from this list   b) Back")
        choice = input("  > ").strip().lower()
        if choice == "b":
            return None
        if choice == "p":
            return ask_path("Path to project folder")
        if choice == "r":
            number = input("  Number to remove from the list (the folder itself is not touched): ").strip()
            if number.isdigit() and 1 <= int(number) <= len(RECENT.entries):
                RECENT.forget(RECENT.entries[int(number) - 1])
            continue  # show the list again
        if choice.isdigit() and 1 <= int(choice) <= len(RECENT.entries):
            return Path(RECENT.entries[int(choice) - 1].path)
        print("  Unknown choice.")


def prompt_load_project(path: Path | None = None) -> Project | None:
    """Pick a project (or use path, from --load) and its password, then let Project.load() open it."""
    if path is None:
        path = choose_project_path()
        if path is None:
            return None
    # Before asking: an interrupted password change decides WHICH password is valid
    if path.is_dir() and (message := Project.recover_password_change(path)):
        print(f"  NOTE: {message}")
    password = getpass("Project password: ")
    print("  Unlocking...")  # scrypt takes a moment - that's the point
    try:
        project = Project.load(path, password)
    except (ProjectError, VaultError, InventoryError) as exc:
        print(f"  Error: {exc}")
        return None
    print(f"  Loaded: {project}")
    RECENT.remember(project.path, project.config.name)  # only after a successful load
    return project


# ---------- host actions (need a loaded project) ----------

def host_line(host: Host, hostnames: dict[str, str]) -> str:
    """One host for the host lists: hostname (from the newest saved config, "?" if the device
    was never fetched or scanned), IP and username. The password is never shown."""
    return f"{hostnames.get(host.ip, '?'):<20} {host.ip:<16} user: {host.username}"


def list_hosts(project: Project) -> None:
    if not project.hosts:
        print("  No hosts yet.")
        return
    hostnames = project.last_known_hostnames()
    for host in project.hosts:
        print(f"    - {host_line(host, hostnames)}")
    if len(hostnames) < len(project.hosts):
        print("  (? = hostname not known yet: fetch its running-config or run a scan)")


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
    """An SshCollector for this project, or None (with a message) if there are no hosts."""
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


def choose_file_from_list(files: list[Path], what: str) -> Path | None:
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


def choose_hosts(project: Project) -> list[Host]:
    """Let the user pick hosts: Enter = all, or numbers like "2" or "1,3"."""
    hostnames = project.last_known_hostnames()
    for number, host in enumerate(project.hosts, start=1):
        print(f"    {number:>3}) {host_line(host, hostnames)}")
    while True:
        answer = input("  Hosts to fetch (e.g. 2 or 1,3 - Enter = all): ").strip()
        if not answer:
            return list(project.hosts)
        parts = [p.strip() for p in answer.split(",")]
        if all(p.isdigit() and 1 <= int(p) <= len(project.hosts) for p in parts):
            # dict.fromkeys() removes duplicates ("1,1") but keeps the order - a set wouldn't
            return [project.hosts[int(p) - 1] for p in dict.fromkeys(parts)]
        print(f"  Enter numbers between 1 and {len(project.hosts)}, separated by commas.")


def fetch_configs(project: Project) -> None:
    """Fetch the running-config from the chosen hosts and save it (encrypted) in configs/."""
    collector = make_collector(project)
    if collector is None:
        return
    hosts = choose_hosts(project)
    ok = 0
    for host in hosts:
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
    print(f"  Done: {ok}/{len(hosts)} config(s) saved.")


def configs_menu(project: Project) -> None:
    actions = {"1": view_config, "2": remove_old_configs}
    while True:
        versions = project.get_configs_sorted_by_time()
        total = sum(len(paths) for paths in versions.values())
        print(f"\n=== netaudit | project: {project.config.name} | saved configs ===")
        print(f"  {total} config(s) from {len(versions)} device(s)")
        print("1) View a config\n2) Remove old versions (keep the newest per device)\nb) Back")
        choice = input("> ").strip().lower()
        if choice == "b":
            return
        if choice in actions:
            actions[choice](project)
        else:
            print("  Unknown choice.")


def remove_old_configs(project: Project) -> None:
    """Delete every saved config except the newest one of each device (after asking)."""
    configs = project.get_configs_sorted_by_time()  # {ip: [oldest ... newest]} - read once
    # paths[:-1] = all but the last (newest) element - a slice, like a sub-range in C++
    old = [path for paths in configs.values() for path in paths[:-1]]
    if not old:
        print("  Nothing to remove - every device has only one saved config.")
        return
    print(f"  {len(old)} older config(s) will be deleted; the newest per device is kept:")
    for ip, paths in configs.items():
        if len(paths) > 1:
            print(f"    {ip:<16} keep {paths[-1].stem}, delete {len(paths) - 1} older")
    if not ask_yes_no("  Delete them? This can't be undone"):
        print("  Nothing deleted.")
        return
    project.delete_configs(old)
    print(f"  Deleted {len(old)} config(s).")


def view_config(project: Project) -> None:
    """Saved configs are encrypted, so this is the way to read them."""
    path = choose_file_from_list(project.list_configs_by_hostname(), "configs")
    if path is None:
        return
    try:
        print(project.read_config(path))
    except VaultError as exc:
        print(f"  Error: {exc}")


def view_log(project: Project) -> None:
    lines = project.read_log()
    print("\n".join(lines) if lines else "  The log is empty.")


# ---------- settings ----------

def settings_menu(project: Project) -> None:
    actions = {"1": set_syslog_server, "2": disable_syslog, "3": send_syslog_test, "4": set_ssh_options,
               "5": change_password}
    while True:
        cfg = project.config
        print(f"\n=== netaudit | project: {cfg.name} | settings ===")
        if cfg.syslog_host:
            status = f"ERROR: {project.syslog_error}" if project.syslog_error else "active"
            print(f"  Syslog server: {cfg.syslog_host}:{cfg.syslog_port} ({cfg.syslog_protocol.upper()}) - {status}")
        else:
            print("  Syslog server: not set (log is only kept in the encrypted local file)")
        print(f"  SSH: port {cfg.ssh_port}, timeout {cfg.ssh_timeout} s")
        print("1) Set syslog server\n2) Turn syslog off\n3) Send a syslog test message\n4) SSH port and timeout")
        print("5) Change project password\nb) Back")
        choice = input("> ").strip().lower()
        if choice == "b":
            return
        if choice in actions:
            actions[choice](project)
        else:
            print("  Unknown choice.")


def ask_number(prompt: str, default: int, low: int, high: int) -> int:
    while True:
        answer = input(f"{prompt} [{default}]: ").strip()
        if not answer:
            return default
        if answer.isdigit() and low <= int(answer) <= high:
            return int(answer)
        print(f"  Enter a number between {low} and {high}.")


def set_syslog_server(project: Project) -> None:
    cfg = project.config
    print("  Note: syslog is sent UNENCRYPTED over the network. The log never contains passwords,")
    print("  but it does contain device IPs, usernames and the configuration commands applied.")
    host = input(f"Syslog server (IP or hostname) [{cfg.syslog_host or 'none'}]: ").strip() or cfg.syslog_host
    if not host:
        print("  No server given - nothing changed.")
        return
    port = ask_number("UDP/TCP port", cfg.syslog_port, 1, 65535)
    protocol = ""
    while protocol not in ("udp", "tcp"):
        protocol = input(f"Protocol udp/tcp [{cfg.syslog_protocol}]: ").strip().lower() or cfg.syslog_protocol
    cfg.syslog_host, cfg.syslog_port, cfg.syslog_protocol = host, port, protocol
    project.save_settings()
    if project.syslog_error:
        print(f"  Saved, but the server can't be reached: {project.syslog_error}")
        print("  The log is still written locally. netaudit tries again the next time the project is loaded.")
    else:
        project.log.info("Syslog server set to %s:%d/%s", host, port, protocol)
        print("  Saved. Use 'Send a syslog test message' to check it arrives.")


def disable_syslog(project: Project) -> None:
    if not project.config.syslog_host:
        print("  Syslog is already off.")
        return
    project.log.info("Syslog to %s turned off", project.config.syslog_host)
    project.config.syslog_host = ""
    project.save_settings()
    print("  Syslog turned off.")


def send_syslog_test(project: Project) -> None:
    if not project.config.syslog_host:
        print("  No syslog server set.")
        return
    project.log.info("Syslog test message from netaudit")
    if project.syslog_error:
        print(f"  Failed: {project.syslog_error}")
    elif project.config.syslog_protocol == "udp":
        print("  Sent. UDP gives no delivery confirmation - check that it arrived on the server.")
    else:
        print("  Sent over TCP (the connection accepted it). Check that it arrived on the server.")


def change_password(project: Project) -> None:
    current = getpass("Current project password: ")
    if not project.check_password(current):  # check now, not after typing the new one twice
        print("  The current password is wrong - nothing changed.")
        return
    print("  Choose the new password.")
    new = ask_new_password()
    if new == current:
        print("  That's the same password - nothing changed.")
        return
    print("  Re-encrypting hosts, configs, scan reports and the log...")
    try:
        count = project.change_password(current, new)
    except WrongPasswordError:
        print("  The current password is wrong - nothing changed.")
        return
    except (VaultError, OSError) as exc:
        print(f"  Error: {exc} - nothing changed, the old password is still valid.")
        return
    print(f"  Done: {count} file(s) re-encrypted. Use the new password from now on.")


def set_ssh_options(project: Project) -> None:
    project.config.ssh_port = ask_number("SSH port", project.config.ssh_port, 1, 65535)
    project.config.ssh_timeout = ask_number("SSH timeout in seconds", project.config.ssh_timeout, 1, 300)
    project.save_settings()
    project.log.info("SSH settings changed: port %d, timeout %d s", project.config.ssh_port, project.config.ssh_timeout)
    print("  Saved.")


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
        handle_findings(project, report)


RECENT = RecentProjects(default_file())  # module-level: one shared list for the whole program

MAX_SCAN_AGE = timedelta(days=1)  # older reports get a warning before fixes are offered


def format_age(age: timedelta) -> str:
    """timedelta -> "3 days" / "5 hours" / "12 minutes"."""
    if age.days >= 1:
        return f"{age.days} day{'s' if age.days > 1 else ''}"
    hours, minutes = age.seconds // 3600, age.seconds % 3600 // 60  # // is integer division
    return f"{hours} hour{'s' if hours != 1 else ''}" if hours else f"{minutes} minute{'s' if minutes != 1 else ''}"


def view_scan(project: Project) -> None:
    """Show a saved report - and, like right after a scan, offer to handle its findings."""
    path = choose_file_from_list(project.list_scans(), "scan reports")
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
    project.log.info("Handling findings from saved scan %s (%s old)", path.name, format_age(age))
    handle_findings(project, report)


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
        answers = {"value": value}
        for question in fix_input.followups:
            answers[question.key] = ask_followup(question)
        resolved = fix_inputs.resolve(finding, answers)
        for fix in resolved.fixes:  # show exactly what will be sent
            print(f"       {fix.hostname}: " + " | ".join(fix.commands))
        return resolved


def ask_followup(question: FixQuestion) -> str:
    """Ask one follow-up question until the answer is valid. Enter = the suggested default."""
    while True:
        value = input(f"     {question.question} (Enter = {question.default}): ").strip() or question.default
        error = fix_inputs.validate_followup(question, value)
        if not error:
            return value
        print(f"     {error}")


def handle_findings(project: Project, report: ScanReport) -> None:
    """After a scan (or for a saved report): let the user pick how to deal with the findings.
    The SSH collector is only created once the user confirms that changes will be applied."""
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

    collector = make_collector(project)  # from here on we talk to the devices
    if collector is None:
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
    actions = {"1": prompt_create_project, "2": prompt_load_project}

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
        "6": configs_menu,
        "7": scan_menu,
        "8": view_log,
        "9": settings_menu,
    }

    while True:
        print(f"\n=== netaudit | project: {project.config.name} ({project.path.resolve()}) ===")
        print("1) List hosts\n2) Add host\n3) Remove host\n4) Import hosts from file")
        print("5) Fetch running-configs\n6) Saved configs\n7) Scan\n8) View log\n9) Settings\nq) Quit")
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
    project = prompt_load_project(args.load) if args.load else None
    if project is None:
        project = start_menu()
    if project is not None:
        project_menu(project)


if __name__ == "__main__":
    main()
