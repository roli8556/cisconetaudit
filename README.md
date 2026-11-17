# netaudit

A security-focused network auditing tool for Cisco networks, written in Python.

netaudit connects to network devices, audits their configurations against security best practices
(port security, BPDU guard, root guard, DHCP snooping, SSH hardening and more), and gives
recommendations with the exact configuration changes needed. Later versions will analyse live
traffic to find congestion and suggest improvements to STP, HSRP and ACLs.

> Work in progress — built as a learning project during the IT-säkerhetsspecialist program.

## Features (planned)

- [x] Projects: create and load a project folder per network
- [x] Inventory of devices with validation
- [ ] Collect running configs over SSH
- [ ] Static security audit with rules mapped to CIS / Cisco hardening guides
- [ ] Reports with findings and suggested config changes
- [ ] Apply changes: one at a time with confirmation, or automatically, with rollback
- [ ] Traffic monitoring over SNMP and live analysis

## Usage

```powershell
python main.py
```

1. Create a project and pick a collection method.
2. Add devices to `projects/<name>/hosts.txt`, one per line: `name,ip,username`
3. Load the project.

## Project layout

```
projects/<name>/
    config.json     project settings
    hosts.txt       devices to audit (no passwords)
    project.log     log of everything the tool has done
    scans/          saved scan results
    configs/        saved device configurations
```

## Security / threat model

The machine running netaudit has access to every device in the inventory, which makes it a
high-value target.

- Passwords are never stored in `hosts.txt` or anywhere in the project folder.
- Project folders are excluded from Git, since they contain device configs.
- The tool should run with a read-only account by default; write access is only needed to apply changes.
- Intended to run from a dedicated management host on an out-of-band management network.

## Lab environment

Developed and tested against Cisco Modeling Labs (CML) running in Hyper-V, with IOL / IOL-L2
devices on a dedicated management network (192.168.100.0/24).
