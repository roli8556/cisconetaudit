# netaudit

A security-focused network auditing tool for Cisco networks, written in Python.

netaudit connects to network devices, audits their configurations against security best practices
(port security, BPDU guard, root guard, DHCP snooping, SSH hardening and more), and gives
recommendations with the exact configuration changes needed. Later versions will analyse live
traffic to find congestion and suggest improvements to STP, HSRP and ACLs.

> Work in progress — built as a learning project during the IT-säkerhetsspecialist program.

## Features (planned)

- [x] Projects: create and load a project folder per network
- [x] Inventory of devices with validation, encrypted with a per-project password
- [x] Collect running configs over SSH (saved encrypted to `configs/<hostname>_<ip>_<timestamp>.enc`)
- [ ] Static security audit with rules mapped to CIS / Cisco hardening guides
- [ ] Reports with findings and suggested config changes
- [ ] Apply changes: one at a time with confirmation, or automatically, with rollback
- [ ] Traffic monitoring over SNMP and live analysis

## Usage

```powershell
python main.py                                   # interactive menu
python main.py --load "C:\path\to\my-project"   # load a project directly
```

1. Create a project: choose where it should live, give it a name, pick a collection method and
   set a project password (min 12 characters - it can't be recovered).
2. Load the project (path + project password) and add devices from the menu, or import a
   plaintext file with one device per line: `ip username password [enable_password]`
   (IPv4 or IPv6; no spaces in any field; enable password only if the account doesn't log in at
   privilege 15). Delete the plaintext file afterwards - the tool offers to do it.

## Project layout

A project is a self-contained folder that can live anywhere, e.g. one folder per network
inside `Documents\netaudit-projects\`. Keep project folders outside this repository.

```
<project folder>/
    config.json     project settings
    hosts.enc       devices + SSH credentials, encrypted with the project password
    project.log     log of everything the tool has done
    known_hosts     accepted SSH host keys
    scans/          saved scan results
    configs/        saved device configurations (encrypted)
```

## Security / threat model

The machine running netaudit has access to every device in the inventory, which makes it a
high-value target.

- Device credentials are stored only in `hosts.enc`, encrypted with a key derived from the
  project password (scrypt, ~128 MB / ~0.5 s per guess) using Fernet (AES + HMAC-SHA256).
  The project password itself is never stored. Its strength is what protects the credentials.
- Passwords are never written to logs or printed.
- Configs are fetched only at privilege level 15 (lower levels show a partial config, which
  would give false audit results).
- Saved configs (`configs/*.enc`) are encrypted with the same project key as `hosts.enc`, since
  they contain password hashes, SNMP communities and keys. Read them via "View saved config".
- SSH host keys are verified (trust on first use): an unknown key is shown as a SHA256
  fingerprint and must be accepted; accepted keys go in the project's `known_hosts`. A changed
  key blocks the connection before any credentials are sent.
- Project folders are excluded from Git, since they contain device configs.
- The tool should run with a read-only account by default; write access is only needed to apply changes.
- Intended to run from a dedicated management host on an out-of-band management network.

## Lab environment

Developed and tested against Cisco Modeling Labs (CML) running in Hyper-V, with IOL / IOL-L2
devices on a dedicated management network (192.168.100.0/24).
