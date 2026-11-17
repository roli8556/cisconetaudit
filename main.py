"""
Entry point: a simple menu to create or load a project.

Run from the project root with:  python main.py
"""

from pathlib import Path

from netaudit.inventory import InventoryError
from netaudit.project import VALID_METHODS, Project, ProjectError

PROJECTS_DIR = Path("projects")


def ask_method() -> str:
    while True:
        method = input(f"Collection method {VALID_METHODS}: ").strip().lower()
        if method in VALID_METHODS:
            return method
        print(f"  Please type one of: {', '.join(VALID_METHODS)}")


def create_project() -> Project | None:
    name = input("Project name: ").strip()
    if not name:
        print("  Name can't be empty.")
        return None
    try:
        project = Project.create(PROJECTS_DIR, name, ask_method())
    except ProjectError as exc:
        print(f"  Error: {exc}")
        return None
    print(f"  Created {project.path}")
    print(f"  Next: add your devices to {project.path / 'hosts.txt'}, then load the project.")
    return project


def load_project() -> Project | None:
    existing = sorted(p.name for p in PROJECTS_DIR.iterdir() if p.is_dir()) if PROJECTS_DIR.exists() else []
    if existing:
        print("  Projects:", ", ".join(existing))
    name = input("Project to load: ").strip()
    try:
        project = Project.load(PROJECTS_DIR / name)
    except (ProjectError, InventoryError) as exc:
        print(f"  Error: {exc}")
        return None

    print(f"  Loaded: {project}")
    for host in project.hosts:
        print(f"    - {host.name:<10} {host.ip:<16} user: {host.username}")
    return project


def main() -> None:
    project: Project | None = None
    actions = {"1": create_project, "2": load_project}

    while True:
        current = project.config.name if project else "none"
        print(f"\n=== netaudit (project: {current}) ===")
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
