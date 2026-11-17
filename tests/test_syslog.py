"""Tests for sending the project log to a syslog server - against real sockets on 127.0.0.1."""

import socket

from netaudit.project import Project

PASSWORD = "correct horse battery"


def make_project(tmp_path, host="", port=514, protocol="udp") -> Project:
    project = Project.create(tmp_path, "lab", PASSWORD)
    project.config.syslog_host, project.config.syslog_port, project.config.syslog_protocol = host, port, protocol
    project.save_settings()
    return project


def test_udp(tmp_path):
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("127.0.0.1", 0))  # port 0 = let the OS pick a free port
    server.settimeout(5)
    port = server.getsockname()[1]

    project = make_project(tmp_path, "127.0.0.1", port, "udp")
    project.log.info("Scan finished: baseline")
    message = server.recv(4096).decode()
    server.close()

    # <PRI>: facility local0 (16) * 8 + severity info (6) = 134
    assert message == "<134>netaudit[lab]: INFO Scan finished: baseline"  # no trailing NUL
    assert any("Scan finished" in line for line in project.read_log())  # still in the local log too


def test_tcp_uses_newline_framing(tmp_path):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    server.settimeout(5)
    port = server.getsockname()[1]

    project = make_project(tmp_path, "127.0.0.1", port, "tcp")
    connection, _ = server.accept()
    connection.settimeout(5)
    project.log.info("first")
    project.log.info("second")
    received = b""
    while received.count(b"\n") < 2:
        received += connection.recv(4096)
    connection.close()
    server.close()

    lines = received.decode().splitlines()
    assert lines == ["<134>netaudit[lab]: INFO first", "<134>netaudit[lab]: INFO second"]
    assert "\x00" not in received.decode()  # no NUL bytes in TCP mode


def test_unreachable_tcp_server_is_reported_not_fatal(tmp_path):
    # find a port with nothing listening: bind, read the port number, close again
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()

    project = make_project(tmp_path, "127.0.0.1", port, "tcp")
    assert project.syslog_error  # e.g. "connection refused"
    project.log.info("still works")  # no exception, no traceback
    assert any("unreachable" in line for line in project.read_log())
    assert any("still works" in line for line in project.read_log())


def test_settings_survive_reload(tmp_path):
    make_project(tmp_path, "192.0.2.10", 1514, "udp")
    again = Project.load(tmp_path / "lab", PASSWORD)
    assert (again.config.syslog_host, again.config.syslog_port, again.config.syslog_protocol) == ("192.0.2.10", 1514, "udp")


def test_turning_syslog_off(tmp_path):
    project = make_project(tmp_path, "127.0.0.1", 514, "udp")
    assert len(project.log.handlers) == 2  # encrypted file + syslog
    project.config.syslog_host = ""
    project.save_settings()
    assert len(project.log.handlers) == 1  # only the encrypted file
