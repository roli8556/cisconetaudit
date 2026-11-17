"""Tests for the recent-projects list. tmp_path is a pytest fixture: a fresh, empty temporary
folder for each test - so tests never touch the real list in %APPDATA%."""

from netaudit.recent import MAX_ENTRIES, RecentProjects


def test_remember_and_reload(tmp_path):
    file = tmp_path / "recent.json"
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()

    recent = RecentProjects(file)
    recent.remember(tmp_path / "a", "office")
    recent.remember(tmp_path / "b", "lab")
    assert [e.name for e in recent.entries] == ["lab", "office"]  # newest first

    again = RecentProjects(file)  # a new program start reads the same list
    assert [e.name for e in again.entries] == ["lab", "office"]


def test_reopening_moves_to_top_without_duplicates(tmp_path):
    recent = RecentProjects(tmp_path / "recent.json")
    for name in ("a", "b", "a"):
        recent.remember(tmp_path / name, name)
    assert [e.name for e in recent.entries] == ["a", "b"]


def test_list_is_capped(tmp_path):
    recent = RecentProjects(tmp_path / "recent.json")
    for i in range(MAX_ENTRIES + 5):
        recent.remember(tmp_path / f"p{i}", f"p{i}")
    assert len(recent.entries) == MAX_ENTRIES
    assert recent.entries[0].name == f"p{MAX_ENTRIES + 4}"


def test_missing_folders_are_kept_but_marked(tmp_path):
    recent = RecentProjects(tmp_path / "recent.json")
    recent.remember(tmp_path / "usb-drive-project", "usb")  # folder doesn't exist
    assert len(recent.entries) == 1 and not recent.entries[0].exists
    recent.forget(recent.entries[0])
    assert RecentProjects(tmp_path / "recent.json").entries == []


def test_damaged_file_is_ignored(tmp_path):
    file = tmp_path / "recent.json"
    file.write_text("{ this is not json", encoding="utf-8")
    assert RecentProjects(file).entries == []  # starts empty instead of crashing
