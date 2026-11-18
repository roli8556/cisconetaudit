"""Tests for saved configs: grouping per device, keeping only the newest, choosing hosts."""

import builtins
from datetime import datetime

import main
from netaudit.inventory import parse_hosts
from netaudit.models import RunningConfig
from netaudit.project import Project

PASSWORD = "correct horse battery"


def save(project, ip, hostname, when):
    return project.save_config(RunningConfig(ip, hostname, "hostname x\nend\n", when))


def test_newest_per_device_is_kept(tmp_path, monkeypatch):
    project = Project.create(tmp_path, "lab", PASSWORD)
    old1 = save(project, "192.168.100.11", "SW1", datetime(2026, 11, 1, 9, 0))
    old2 = save(project, "192.168.100.11", "Switch", datetime(2026, 11, 10, 9, 0))  # renamed since
    new1 = save(project, "192.168.100.11", "SW1", datetime(2026, 11, 17, 9, 0))
    only = save(project, "192.168.100.12", "SW2", datetime(2026, 11, 2, 9, 0))
    v6 = save(project, "2001:db8::1", "CORE_SW", datetime(2026, 11, 3, 9, 0))  # "_" in name, ":" in IP
    foreign = project.configs_dir / "my-notes.enc"  # not a netaudit name -> never touched
    foreign.write_text("x")

    versions = project.get_configs_sorted_by_time()
    assert versions["192.168.100.11"] == [old1, old2, new1]  # grouped by IP despite the rename
    assert versions["2001-db8--1"] == [v6]

    monkeypatch.setattr(builtins, "input", lambda prompt="": "y")  # answer "y" to "Delete them?"
    main.remove_old_configs(project)
    assert set(project.list_configs_by_hostname()) == {new1, only, v6, foreign}
    assert any("Deleted 2 old config(s)" in line for line in project.read_log())


def test_same_second_saves_keep_order(tmp_path):
    project = Project.create(tmp_path, "lab", PASSWORD)
    when = datetime(2026, 11, 17, 9, 0, 0)
    first = save(project, "10.0.0.1", "R1", when)
    second = save(project, "10.0.0.1", "R1", when)  # gets the _2 suffix
    third = save(project, "10.0.0.1", "R1", when)  # _3
    assert project.get_configs_sorted_by_time()["10.0.0.1"] == [first, second, third]  # third = newest


def test_last_known_hostnames(tmp_path):
    project = Project.create(tmp_path, "lab", PASSWORD)
    project.add_hosts(parse_hosts("10.0.0.1 a pw\n10.0.0.2 b pw\n2001:db8::1 c pw\n"))
    save(project, "10.0.0.1", "Switch", datetime(2026, 11, 1, 9, 0))
    save(project, "10.0.0.1", "SW1", datetime(2026, 11, 17, 9, 0))  # renamed since -> newest wins
    save(project, "2001:db8::1", "CORE_SW", datetime(2026, 11, 3, 9, 0))
    save(project, "10.9.9.9", "OLD", datetime(2026, 11, 3, 9, 0))  # config of a removed host
    # 10.0.0.2 was never fetched -> not in the dict (shown as "?")
    assert project.last_known_hostnames() == {"10.0.0.1": "SW1", "2001:db8::1": "CORE_SW"}


def test_choose_hosts(tmp_path, monkeypatch):
    # monkeypatch: a pytest fixture that replaces something (here input()) only for this test
    project = Project.create(tmp_path, "lab", PASSWORD)
    project.add_hosts(parse_hosts("10.0.0.1 a pw\n10.0.0.2 b pw\n10.0.0.3 c pw\n"))
    answers = iter(["", "3,1,1", "7", "x", "2"])
    monkeypatch.setattr(builtins, "input", lambda prompt="": next(answers))

    assert [h.ip for h in main.choose_hosts(project)] == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]  # Enter = all
    assert [h.ip for h in main.choose_hosts(project)] == ["10.0.0.3", "10.0.0.1"]  # order kept, no duplicate
    assert [h.ip for h in main.choose_hosts(project)] == ["10.0.0.2"]  # "7" and "x" rejected first
