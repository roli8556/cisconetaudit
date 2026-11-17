"""
Entry point: create or load a project folder.

A project is just a folder - it can live anywhere on disk, e.g.
    C:\\Users\\sambr\\Documents\\netaudit-projects\\office-lab

Run:
    python main.py                      interactive menu
    python main.py --load "C:\\path\\to\\project"
"""

import argparse
from pathlib import Path

from netaudit.inventory import InventoryError
from netaudit.project import VALID_METHODS, Project, ProjectError


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


def create_project() -> Project | None:
    parent = ask_path("Folder to create the project in", default=Path.cwd())
    name = input("Project name: ").strip()
    if not name:
        print("  Name can't be empty.")
        return None
    try:
        project = Project.create(parent, name, ask_method())
    except (ProjectError, OSError) as exc:
        print(f"  Error: {exc}")
        return None
    print(f"  Created {project.path.resolve()}")
    print(f"  Next: add your devices to {project.path / 'hosts.txt'}, then load the project.")
    return project


def load_project(path: Path | None = None) -> Project | None:
    if path is None:
        path = ask_path("Path to project folder")
    try:
        project = Project.load(path)
    except (ProjectError, InventoryError) as exc:
        print(f"  Error: {exc}")
        return None

    print(f"  Loaded: {project}")
    for host in project.hosts:
        print(f"    - {host.name:<10} {host.ip:<16} user: {host.username}")
    return project


def main() -> None:
    parser = argparse.ArgumentParser(description="netaudit - network security auditing")
    parser.add_argument("--load", type=Path, metavar="PATH", help="project folder to load on start")
    args = parser.parse_args()

    project: Project | None = load_project(args.load) if args.load else None
    actions = {"1": create_project, "2": load_project}

    while True:
        current = f"{project.config.name} ({project.path.resolve()})" if project else "none"
        print(f"\n=== netaudit | project: {current} ===")
        print("1) Create project\n2) Load project\nq) Quit")
        choice = input("> ").strip().lower()

        if choice == "q":
            break
        if choice in actions:
            result = actions[choice]()
            if result:
                project = result
        else:
            print("  Unknown choice.")


if __name__ == "__main__":
    main()
