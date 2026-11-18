"""Tests for changing the project password - including recovery from an interrupted change."""

import os
from datetime import datetime

import pytest

from netaudit.inventory import parse_hosts
from netaudit.models import RunningConfig
from netaudit.project import Project
from netaudit.scans.report import BaselineReport
from netaudit.vault import WrongPasswordError

OLD, NEW = "correct horse battery", "a brand new passphrase"


def make_project(tmp_path) -> Project:
    project = Project.create(tmp_path, "lab", OLD)
    project.add_hosts(parse_hosts("10.0.0.1 admin secret\n"))
    project.save_config(RunningConfig("10.0.0.1", "SW1", "hostname SW1\nend\n", datetime(2026, 11, 17, 9)))
    project.save_scan(BaselineReport("baseline", datetime(2026, 11, 17, 10)))
    return project


def test_change_password(tmp_path):
    project = make_project(tmp_path)
    count = project.change_password(OLD, NEW)
    assert count == 4  # hosts.enc, 1 config, 1 scan report, the log

    with pytest.raises(WrongPasswordError):  # pytest.raises: the block MUST raise this
        Project.load(project.path, OLD)
    again = Project.load(project.path, NEW)
    assert again.hosts[0].password == "secret"
    assert "hostname SW1" in again.read_config(again.list_configs_by_hostname()[0])
    assert again.read_scan(again.list_scans()[0]).scan_type == "baseline"
    log = again.read_log()
    assert any("Host added" in line for line in log)  # written BEFORE the change - re-encrypted
    assert any("Project password changed" in line for line in log)
    assert not any("unreadable" in line for line in log)
    assert not list(project.path.rglob("*.pwchange-*"))  # no leftovers


def test_project_keeps_working_after_change(tmp_path):
    project = make_project(tmp_path)
    project.change_password(OLD, NEW)
    project.log.info("written with the new key")  # the logger was rebuilt with the new vault
    project.save_config(RunningConfig("10.0.0.1", "SW1", "hostname SW1\nend\n"))
    again = Project.load(project.path, NEW)
    assert any("written with the new key" in line for line in again.read_log())
    assert all(again.read_config(p) for p in again.list_configs_by_hostname())


def test_check_password(tmp_path):
    project = make_project(tmp_path)
    assert project.check_password(OLD) and not project.check_password(NEW)


def test_wrong_current_password_changes_nothing(tmp_path):
    project = make_project(tmp_path)
    before = {p: p.read_bytes() for p in project.path.rglob("*.enc")}
    with pytest.raises(WrongPasswordError):
        project.change_password("not the password", NEW)
    assert {p: p.read_bytes() for p in project.path.rglob("*.enc")} == before


def test_crash_while_preparing_rolls_back(tmp_path):
    project = make_project(tmp_path)
    hosts = project.path / "hosts.enc"
    (project.path / "hosts.enc.pwchange-new").write_text("half-written")  # crash in phase 1
    message = Project.recover_password_change(project.path)
    assert "OLD" in message
    assert Project.load(project.path, OLD).hosts and hosts.is_file()
    assert not list(project.path.rglob("*.pwchange-*"))


def test_crash_while_swapping_rolls_back(tmp_path):
    """Phase 2 interrupted: hosts.enc already swapped to the new key, the config not yet."""
    project = make_project(tmp_path)
    hosts = project.path / "hosts.enc"
    config = project.list_configs_by_hostname()[0]
    # simulate: everything staged, then hosts.enc swapped, then the crash
    os.replace(hosts, hosts.with_name("hosts.enc.pwchange-old"))
    hosts.write_text("re-encrypted with the new key")
    config.with_name(config.name + ".pwchange-new").write_text("staged, never swapped")

    assert "OLD" in Project.recover_password_change(project.path)
    again = Project.load(project.path, OLD)  # the original hosts.enc is back
    assert again.hosts[0].password == "secret"


def test_crash_while_cleaning_up_completes(tmp_path):
    project = make_project(tmp_path)
    project.change_password(OLD, NEW)
    (project.path / "hosts.enc.pwchange-old").write_text("old copy that wasn't deleted yet")
    assert "NEW" in Project.recover_password_change(project.path)
    assert Project.load(project.path, NEW).hosts
    assert not list(project.path.rglob("*.pwchange-*"))
