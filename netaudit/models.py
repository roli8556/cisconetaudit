"""
The common data model: what collectors produce and what the rest of netaudit consumes.

Collectors (SSH now, maybe Catalyst Center API later) all return these objects, so storage and
scan code never need to know how the data was fetched.

Interface names are always stored in their full form ("Ethernet0/1", never "Et0/1") - see
parsers/ios.py normalize_interface() - so data from different commands can be matched up.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True)
class RunningConfig:
    """A running-config as collected from one device."""

    host_ip: str
    hostname: str
    text: str
    collected_at: datetime = field(default_factory=datetime.now)


# ---------------------------------------------------------------- device state


@dataclass
class InterfaceState:
    """Everything we know about one interface, merged from several show commands + the config."""

    name: str
    # from "show interfaces"
    status: str = ""  # "up", "down", "administratively down"
    protocol: str = ""  # line protocol: "up" / "down"
    mtu: int | None = None
    duplex: str = ""  # "full", "half", "auto" (normalized)
    speed: str = ""  # "100mb/s", "1000mb/s", "auto" (normalized)
    # from "show interfaces switchport" (only for switchports)
    switchport: bool = False
    admin_mode: str = ""  # "trunk", "static access", "dynamic auto", "dynamic desirable"
    oper_mode: str = ""  # "trunk", "static access", "down"...
    native_vlan: int | None = None
    access_vlan: int | None = None
    allowed_vlans: str = ""  # as IOS prints it: "ALL", "1,10-20"
    dtp: bool = False  # "Negotiation of Trunking: On" - the port sends/answers DTP
    trunk_encapsulation: str = ""  # administrative: "dot1q", "isl", "negotiate"
    # from "show etherchannel summary" + config
    channel_group: int | None = None
    channel_protocol: str = ""  # "LACP", "PAgP", "-" (= mode on)
    channel_member_flags: str = ""  # "P" = bundled, "s" suspended, "I" stand-alone, "D" down
    channel_mode: str = ""  # from config: "active", "passive", "on", "desirable", "auto"
    # from the running-config
    configured_speed: str = ""  # "" = not configured (= auto)
    configured_duplex: str = ""
    ospfv3: bool = False  # "ipv6 ospf ... area" / "ospfv3 ... area" on this interface
    ip_address: str = ""  # from "show interfaces" (SVIs and routed ports)
    # layer-2 security, from the interface config
    portfast: str = ""  # "enable", "disable" or "" (not configured -> global default applies)
    bpduguard: str = ""  # same
    port_security: bool = False  # "switchport port-security"
    dhcp_trust: bool = False  # "ip dhcp snooping trust"
    dhcp_rate: int | None = None  # "ip dhcp snooping limit rate N"
    dai_trust: bool = False  # "ip arp inspection trust"
    dai_rate: int | None = None  # "ip arp inspection limit rate N"

    @property
    def is_up(self) -> bool:
        return self.status == "up" and self.protocol == "up"

    @property
    def is_trunk(self) -> bool:
        return self.switchport and self.oper_mode == "trunk"

    @property
    def is_physical(self) -> bool:
        """A real port - not a Port-channel, SVI (Vlan), Loopback or Tunnel."""
        return not self.name.startswith(("Port-channel", "Vlan", "Loopback", "Tunnel"))


@dataclass
class OspfInterface:
    """One interface from "show ip ospf interface" (OSPFv2)."""

    name: str
    process_id: int
    area: int  # stored as a number: "Area 0" and "Area 0.0.0.0" are the same area
    network_type: str  # "BROADCAST", "POINT_TO_POINT", "LOOPBACK"...
    hello: int | None = None  # None for loopbacks (they don't send hellos)
    dead: int | None = None
    passive: bool = False


@dataclass
class CdpNeighbor:
    local_interface: str
    device_id: str  # the neighbor's hostname, possibly with a domain: "SW2.lab.local"
    remote_interface: str
    mgmt_ip: str = ""
    platform: str = ""
    capabilities: str = ""  # "Router Switch IGMP", "Host Phone"...

    @property
    def is_network_device(self) -> bool:
        """A switch or router (an uplink) - as opposed to a phone or other end device."""
        return any(cap in self.capabilities.split() for cap in ("Router", "Switch", "Trans-Bridge"))


@dataclass
class OspfNeighbor:
    neighbor_id: str  # router ID
    state: str  # "FULL/DR", "2WAY/DROTHER", "EXSTART/BDR", "FULL/  -"...
    address: str
    interface: str


@dataclass
class ManagementConfig:
    """Device-wide management settings from the running-config."""

    hostname: str = ""  # "" = no "hostname" line (IOS then uses "Router"/"Switch")
    domain_name: str = ""
    domain_command: str = "ip domain-name"  # the syntax this device uses: "ip domain name" on newer IOS-XE
    ntp_servers: list[str] = field(default_factory=list)
    logging_hosts: list[str] = field(default_factory=list)
    lines_without_logging_sync: list[str] = field(default_factory=list)  # e.g. ["line vty 0 4"]
    ssh_keypair_pinned: bool = False  # "ip ssh rsa keypair-name ..." is configured


@dataclass
class L2SecurityConfig:
    """Device-wide layer-2 security settings from the running-config."""

    portfast_default: bool = False  # "spanning-tree portfast [edge] default"
    bpduguard_default: bool = False  # "spanning-tree portfast [edge] bpduguard default"
    dhcp_snooping: bool = False  # global "ip dhcp snooping"
    dhcp_snooping_vlans: str = ""  # "10,20"
    option82: bool = True  # IOS inserts option 82 unless "no ip dhcp snooping information option"
    dai_vlans: str = ""  # "ip arp inspection vlan 10,20"
    dai_validate: list[str] = field(default_factory=list)  # ["src-mac", "dst-mac", "ip"]
    errdisable_causes: list[str] = field(default_factory=list)  # "errdisable recovery cause X"
    errdisable_interval: int | None = None


@dataclass
class NtpStatus:
    """From "show ntp status"."""

    synchronized: bool
    stratum: int | None = None
    reference: str = ""  # the server/peer this device is synchronized to
    offset_ms: float | None = None


@dataclass
class DeviceSnapshot:
    """All state collected from one device during a scan."""

    host_ip: str
    hostname: str
    running_config: str
    interfaces: dict[str, InterfaceState] = field(default_factory=dict)
    cdp_neighbors: list[CdpNeighbor] = field(default_factory=list)
    ospf_interfaces: dict[str, OspfInterface] = field(default_factory=dict)
    ospf_neighbors: list[OspfNeighbor] = field(default_factory=list)
    vlans: dict[int, str] = field(default_factory=dict)  # VLAN id -> name, from "show vlan brief"
    management: ManagementConfig = field(default_factory=ManagementConfig)
    l2security: L2SecurityConfig = field(default_factory=L2SecurityConfig)
    dhcp_binding_ports: set[str] = field(default_factory=set)  # ports with a DHCP snooping binding
    ntp: NtpStatus | None = None  # None = NTP not running at all
    rsa_key_name: str = ""  # the SSH host key pair, from "show crypto key mypubkey rsa"
    ip_addresses: set[str] = field(default_factory=set)  # all interface IPs (to follow NTP chains)
    notes: list[str] = field(default_factory=list)  # e.g. "CDP is not enabled"
    collected_at: datetime = field(default_factory=datetime.now)


# ---------------------------------------------------------------- scan results


@dataclass
class Fix:
    """Config commands for ONE device that (help) solve a finding.

    phase: all phase-1 fixes are applied on all devices before any phase-2 fix. Needed when the
    two ends of a link must change in steps to stay compatible the whole time (see the DTP fix).
    """

    host_ip: str
    hostname: str
    commands: list[str]
    phase: int = 1


@dataclass
class FixTarget:
    """Something a fix-with-input will change: one interface on one device.
    params holds whatever the command builder needs, e.g. {"mode": "active"} - see
    scans/fix_inputs.py for what each kind of fix expects."""

    host_ip: str
    hostname: str
    interface: str
    params: dict[str, str] = field(default_factory=dict)


@dataclass
class FixQuestion:
    """A follow-up question of a FixInput (e.g. port security: max MACs, aging...).
    Checked generically: choices (one of a list) or a number range."""

    key: str  # name of the answer, e.g. "aging"
    question: str
    default: str = ""
    choices: list[str] = field(default_factory=list)  # allowed answers, if limited
    min_value: int | None = None  # set both for a number answer
    max_value: int | None = None


@dataclass
class FixInput:
    """A fix that needs values from the user before its commands can be built
    (e.g. which native VLAN to use). The scan only describes the questions; the menu asks them,
    and scans/fix_inputs.py turns the answers into Fix objects.

    The main question's answer is stored under the key "value"; followups add more answers.
    """

    kind: str  # "native-vlan", "allowed-vlans", "ospf-timers", "channel-group", ...
    question: str
    default: str = ""  # "" = no default, the user must type a value
    targets: list[FixTarget] = field(default_factory=list)
    followups: list[FixQuestion] = field(default_factory=list)


@dataclass
class Finding:
    """One problem found by a scan.

    A finding can be fixed in one of three ways:
      - fixes:     ready-made commands
      - fix_input: commands are built once the user has supplied a value
      - neither:   no automatic fix (e.g. which OSPF area a link belongs to) - fix by hand
    """

    check: str  # short id, e.g. "native-vlan-mismatch"
    severity: str  # "high", "medium", "low"
    location: str  # "SW1 Et0/1 <-> SW2 Et0/1" or "SW1 Et0/1"
    message: str
    fix_description: str = ""  # human summary of what the fixes do
    fixes: list[Fix] = field(default_factory=list)
    fix_input: FixInput | None = None

    @property
    def key(self) -> tuple[str, str]:
        """Identifies "the same problem" across scans - used to see what a fix solved."""
        return (self.check, self.location)

    @property
    def fixable(self) -> bool:
        return bool(self.fixes) or self.fix_input is not None
