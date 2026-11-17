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
  keeps them outside the repo, one folder per network). It contains config.json, hosts.enc,
  project.log, scans/, configs/. The tool loads a project by path: `Project.create(parent, name)`
  / `Project.load(path)` in netaudit/project.py, `python main.py --load PATH` on the CLI.
- Inventory is `hosts.enc`: plaintext `ip username password [enable_password]` per line (whitespace
  separated, no spaces in fields, IPv4/IPv6), encrypted with a per-project password (scrypt + Fernet, netaudit/vault.py). The
  project password is never stored; asked with getpass on create/load. Never log/print passwords
  (Host.password has repr=False). Maybe later: cache project password in Credential Manager (keyring).
- Collection method per project: "ssh" or "snmp". SSH is needed for config audits; SNMP can't read
  configs but is the right tool for traffic/interface counters.
- Architecture goal: collectors/adapters (SSH now; Catalyst Center API later) feed a common data
  model; the audit/analysis logic doesn't care where data came from.
- Read-only by default. Apply modes: recommend only / step-by-step with confirmation / automatic,
  always with rollback (`configure terminal revert timer`) and pre/post checks.
- Audit rules should be port-role aware (access vs trunk/uplink) to avoid false positives, and
  reference CIS benchmark / Cisco hardening guides.

- Collectors live in netaudit/collectors/ (only place that imports netmiko) and return objects from
  netaudit/models.py (e.g. RunningConfig). Project.save_config() stores them in configs/.
- netmiko works fine with IOL (verified 2026-11-17); the chacha20 quirk only affects OpenSSH clients.
- Host keys: per-project known_hosts, TOFU. collectors/hostkeys.py pre-checks the key (clear error),
  then netmiko connects with ssh_strict=True + alt_key_file as a second check. The collector asks
  via an injected confirm_new_key callback - collectors never call input()/print().
- Scans: collectors/ssh.py fetch_snapshot() -> parsers/ios.py build_snapshot() -> models.DeviceSnapshot
  -> scans/baseline.py (pure, tested with tests/sample_outputs.py) -> Findings with optional Fixes.
  ntc-templates are used where reliable; switchport (wrapped VLAN lists) and full
  "show ip ospf interface" are parsed by hand. Interface names always normalized to full form.
- Fixes: grouped per device, applied with "configure terminal revert timer" + reconnect +
  "configure confirm"; IOS errors ("^% ") -> "configure revert now". Then re-scan as post-check.
  Requires IOS archive config on devices.
- Fixes needing a user value (native VLAN, allowed VLANs, OSPF timers, port-channel number) are
  Finding.fix_input (FixInput + FixTargets, pure data); scans/fix_inputs.py validates/warns/builds
  commands; main.ask_fix_value asks in both step-by-step and fix-all. remediation.reconcile()
  merges fixes that would undo each other (mode fix + port-channel renumber on the same port).
- Fix.phase: all devices get phase-1 commands before any phase-2 command; a failure skips later
  phases. Used by the DTP fix (1: explicit mode, 2: nonegotiate) so links never break mid-change.
- Unused ports fix creates the parking VLAN explicitly if missing: IOS's auto-create prints
  "% Access VLAN does not exist", which the "^% " error pattern would treat as a failure.
- scans/management.py: device checks (hostname, logging synchronous, NTP, syslog) and network checks
  across all devices (same domain name, same NTP root source - chains followed via interface IPs).
- Hostname/domain fixes first pin the SSH key ("ip ssh rsa keypair-name <current>"): the default key
  is named hostname.domain, so renaming could kill SSH. netmiko copes with the prompt change
  (config reads wait for base prompt OR "#").
- Log is encrypted per line (EncryptedFileHandler, project.log.enc); scan reports are encrypted JSON.
- Saved configs are vault-encrypted (configs/*.enc), same key as hosts.enc (Vault.read/write).

## Planned stack
Python 3.12+, cryptography, netmiko (+ ntc-templates), pytest (SSH), ciscoconfparse2 (config parsing), later nornir, pysnmp, pytest.

## Lab environment
- Windows laptop with Hyper-V, Cisco Modeling Labs (CML Free, 5-node limit) as a VM.
- Management network 192.168.100.0/24 on Hyper-V internal switch "CML-Mgmt":
  Windows = 192.168.100.1, SW1 (IOL-L2) = 192.168.100.11, more devices .12, .13 ...
- Devices are reached via External Connector on CML bridge1. Management is VLAN 99 on Et0/0.
- Known quirk: IOL's SSH has issues with chacha20-poly1305; use aes-ctr ciphers.
