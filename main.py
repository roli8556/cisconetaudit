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
from getpass import getpass
from pathlib import Path

from netaudit.collectors.hostkeys import KnownHosts
from netaudit.collectors.ssh import CollectorError, SshCollector
from netaudit.inventory import Host, InventoryError, parse_hosts, validate_host
from netaudit.project import MIN_PASSWORD_LENGTH, VALID_METHODS, Project, ProjectError
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


def fetch_configs(project: Project) -> None:
    """Fetch the running-config from every host and save it in configs/."""
    if project.config.collection_method != "ssh":
        print("  Configs can only be fetched over SSH (this project uses SNMP).")
        return
    if not project.hosts:
        print("  No hosts yet.")
        return

    # A function defined inside a function. It can use "project" from the enclosing scope
    # (a closure - like a C++ lambda capturing [&project]). The collector calls it back.
    def confirm_new_key(ip: str, key_type: str, fp: str) -> bool:
        print(f"    Unknown SSH host key for {ip}:")
        print(f"      {key_type} {fp}")
        print("    Only accept if you trust the network path to this device (e.g. a lab, or")
        print("    you've checked the key on the console).")
        accepted = input("    Accept and remember this key? [y/N]: ").strip().lower() == "y"
        if accepted:
            project.log.info("Host key accepted for %s: %s %s", ip, key_type, fp)
        return accepted

    collector = SshCollector(
        known_hosts=KnownHosts(project.known_hosts_path),
        confirm_new_key=confirm_new_key,
        port=project.config.ssh_port,
        timeout=project.config.ssh_timeout,
    )
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
    configs = project.list_configs()
    if not configs:
        print("  No saved configs yet.")
        return
    # enumerate(..., start=1) gives (1, first), (2, second)... - no manual index counter
    for number, path in enumerate(configs, start=1):
        print(f"    {number:>3}) {path.stem}")  # stem = file name without extension
    choice = input("  Number to show: ").strip()
    if not choice.isdigit() or not 1 <= int(choice) <= len(configs):
        print("  Invalid number.")
        return
    try:
        print(project.read_config(configs[int(choice) - 1]))
    except VaultError as exc:
        print(f"  Error: {exc}")


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
    }

    while True:
        print(f"\n=== netaudit | project: {project.config.name} ({project.path.resolve()}) ===")
        print("1) List hosts\n2) Add host\n3) Remove host\n4) Import hosts from file")
        print("5) Fetch running-configs\n6) View saved config\nq) Quit")
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
