# Context for Claude

## The project
netaudit: a Python tool that audits Cisco network device configurations for security issues and
recommends (and optionally applies) fixes. Later: live traffic analysis (SNMP counters, NetFlow) to
recommend STP/HSRP/ACL changes. Security is the main focus. It should be realistically deployable
in a real network, not just a lab toy.

## About the developer
- Cybersecurity student (IT-säkerhetsspecialist YH program), just finished CCNA studies.
- Comfortable with C++ and OOP; hasn't written Python in a while but reads it well.
- This is a learning project: explain the "why", especially Python idioms vs C++, and keep
  changes small enough to understand. Prefer clear OOP structure over clever one-liners.

## Design decisions so far
- Project-based: a project is a self-contained folder that can live ANYWHERE on disk (the user
  keeps them outside the repo, one folder per network). It contains config.json, hosts.txt,
  project.log, scans/, configs/. The tool loads a project by path: `Project.create(parent, name)`
  / `Project.load(path)` in netaudit/project.py, `python main.py --load PATH` on the CLI.
- hosts.txt format: `name,ip,username` — passwords are NOT stored on disk (prompt with getpass
  for now; Windows Credential Manager via `keyring` later).
- Collection method per project: "ssh" or "snmp". SSH is needed for config audits; SNMP can't read
  configs but is the right tool for traffic/interface counters.
- Architecture goal: collectors/adapters (SSH now; Catalyst Center API later) feed a common data
  model; the audit/analysis logic doesn't care where data came from.
- Read-only by default. Apply modes: recommend only / step-by-step with confirmation / automatic,
  always with rollback (`configure terminal revert timer`) and pre/post checks.
- Audit rules should be port-role aware (access vs trunk/uplink) to avoid false positives, and
  reference CIS benchmark / Cisco hardening guides.

## Planned stack
Python 3.12+, netmiko (SSH), ciscoconfparse2 (config parsing), later nornir, pysnmp, pytest.

## Lab environment
- Windows laptop with Hyper-V, Cisco Modeling Labs (CML Free, 5-node limit) as a VM.
- Management network 192.168.100.0/24 on Hyper-V internal switch "CML-Mgmt":
  Windows = 192.168.100.1, SW1 (IOL-L2) = 192.168.100.11, more devices .12, .13 ...
- Devices are reached via External Connector on CML bridge1. Management is VLAN 99 on Et0/0.
- Known quirk: IOL's SSH has issues with chacha20-poly1305; use aes-ctr ciphers.
