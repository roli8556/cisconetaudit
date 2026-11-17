"""
Realistic IOS show-command output for two switches, SW1 and SW2, with deliberate faults.

The output is built by small functions instead of pasted, so each device's interfaces are easy
to read and change. The text formats match what IOS / IOL prints.

Cabling (all SW1 <-> SW2, same interface on both ends, plus SW1 Et2/1 -> R3):
    Et0/1  trunk       native VLAN 99 vs 1, allowed VLANs 10,20,99 vs 10,99
    Et0/2  EtherChannel member, both ends LACP passive           -> no bundle
    Et0/3  EtherChannel member, SW1 Po1 but SW2 Po2              -> split bundle
    Et1/0  routed, OSPF area 0 vs 1, hello/dead 10/40 vs 5/20, MTU 1500 vs 1400
    Et1/1  routed, OSPF, SW2 passive; SW1 hardcoded 100/full, SW2 auto -> half duplex
    Et1/2  SW1 access port, SW2 trunk
    Et1/3  SW1 only: OSPF towards hosts, no neighbor             -> should be passive
    Et2/0  OSPFv2 on SW1, OSPFv3 on SW2
    Et2/1  SW1 -> R3 (not in the project), OSPF stuck in EXSTART
    Et2/2  trunk, both ends still on native VLAN 1
    Et3/2  mode negotiated with DTP: SW1 dynamic desirable, SW2 dynamic auto -> trunk
Single ports:
    SW1 Et3/0  down, IOS default (dynamic auto, VLAN 1)          -> unused, not hardened
    SW1 Et3/1  shut, static access, nonegotiate, VLAN 999        -> already parked (no finding)
    SW1 Et3/3  up, dynamic auto, a PC behind it                  -> DTP on an edge port
    SW2 Et3/0  down, access VLAN 10                              -> unused, not hardened
Management:
    SW1  domain lab.local, NTP synced to 192.168.100.1, syslog, logging synchronous on con only
    SW2  domain lab.example ("ip domain name" syntax), no NTP, no syslog, no logging synchronous
"""

from __future__ import annotations

SW1_IP, SW2_IP = "192.168.100.11", "192.168.100.12"


def show_interface(name: str, status: str = "up", mtu: int = 1500, duplex: str = "Full-duplex",
                   speed: str = "100Mb/s", ip: str | None = None) -> str:
    protocol = "up" if status == "up" else "down"
    ip_line = f"  Internet address is {ip}\n" if ip else ""
    return f"""{name} is {status}, line protocol is {protocol} (connected)
  Hardware is AmdP2, address is aabb.cc00.0110 (bia aabb.cc00.0110)
{ip_line}  MTU {mtu} bytes, BW 100000 Kbit/sec, DLY 100 usec,
     reliability 255/255, txload 1/255, rxload 1/255
  Encapsulation ARPA, loopback not set
  Keepalive set (10 sec)
  {duplex}, {speed}, media type is unknown
  input flow-control is off, output flow-control is unsupported
  ARP type: ARPA, ARP Timeout 04:00:00
  Last input 00:00:01, output 00:00:00, output hang never
  Last clearing of "show interface" counters never
  Input queue: 0/2000/0/0 (size/max/drops/flushes); Total output drops: 0
  Queueing strategy: fifo
  Output queue: 0/40 (size/max)
  5 minute input rate 0 bits/sec, 0 packets/sec
  5 minute output rate 0 bits/sec, 0 packets/sec
     1234 packets input, 123456 bytes, 0 no buffer
     Received 12 broadcasts (0 IP multicasts)
     0 runts, 0 giants, 0 throttles
     0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored
     2345 packets output, 234567 bytes, 0 underruns
     0 output errors, 0 collisions, 0 interface resets
"""


def switchport(name: str, admin: str = "", oper: str = "", native: int = 1, allowed: str = "ALL",
               enabled: bool = True, access: int = 1, nonegotiate: bool = False, encap: str = "dot1q") -> str:
    if not enabled:
        return f"Name: {name}\nSwitchport: Disabled\n\n"
    # IOS: trunk and dynamic ports negotiate (DTP) unless "switchport nonegotiate"; access ports don't
    dtp = "On" if (admin == "trunk" or admin.startswith("dynamic")) and not nonegotiate else "Off"
    return f"""Name: {name}
Switchport: Enabled
Administrative Mode: {admin}
Operational Mode: {oper}
Administrative Trunking Encapsulation: {encap}
Negotiation of Trunking: {dtp}
Access Mode VLAN: {access} (VLAN{access:04d})
Trunking Native Mode VLAN: {native} (VLAN{native:04d})
Voice VLAN: none
Trunking VLANs Enabled: {allowed}
Pruning VLANs Enabled: 2-1001
Protected: false

"""


def vlan_brief(vlans: dict[int, str]) -> str:
    lines = ["VLAN Name                             Status    Ports",
             "---- -------------------------------- --------- -------------------------------"]
    lines += [f"{vid:<4} {name:<32} active" for vid, name in vlans.items()]
    lines += [f"{vid} {name:<32} act/unsup" for vid, name in
              ((1002, "fddi-default"), (1003, "token-ring-default"), (1004, "fddinet-default"), (1005, "trnet-default"))]
    return "\n".join(lines) + "\n"


def ntp_synced(reference: str) -> str:
    return f"""Clock is synchronized, stratum 4, reference is {reference}
nominal freq is 250.0000 Hz, actual freq is 250.0000 Hz, precision is 2**18
ntp uptime is 1500 (1/100 of seconds), resolution is 4000
reference time is E8F5A1B2.3C4D5E6F (12:00:02.235 UTC Tue Nov 17 2026)
clock offset is 0.5000 msec, root delay is 1.00 msec
root dispersion is 3.20 msec, peer dispersion is 1.00 msec
loopfilter state is 'CTRL' (Normal Controlled Loop), drift is 0.000000000 s/s
system poll interval is 64, last update was 30 sec ago.
"""


def rsa_keys(name: str) -> str:
    # Note the "% Key pair was generated" lines: informational, NOT an error
    return f"""% Key pair was generated at: 10:00:00 UTC Nov 17 2026
Key name: {name}
Key type: RSA KEYS
 Storage Device: not specified
 Usage: General Purpose Key
 Key is not exportable. Redundancy enabled.
 Key Data:
  30820122 300D0609 2A864886 F70D0101 01050003 82010F00 3082010A 02820101
% Key pair was generated at: 10:00:05 UTC Nov 17 2026
Key name: {name}.server
Key type: RSA KEYS
Temporary key
 Usage: Encryption Key
 Key is not exportable.
 Key Data:
  307C300D 06092A86 4886F70D 01010105 00036B00 30680261 00A1B2C3 D4E5F607
"""


def cdp_entry(device: str, ip: str, local: str, remote: str) -> str:
    return f"""-------------------------
Device ID: {device}
Entry address(es):
  IP address: {ip}
Platform: Linux Unix,  Capabilities: Router Switch IGMP
Interface: {local},  Port ID (outgoing port): {remote}
Holdtime : 158 sec

Version :
Cisco IOS Software, Linux Software (I86BI_LINUXL2-ADVENTERPRISEK9-M), Version 15.2
Technical Support: http://www.cisco.com/techsupport

advertisement version: 2
Duplex: full
Management address(es):
  IP address: {ip}

"""


def ospf_interface(name: str, ip: str, area: str, hello: int = 10, dead: int = 40, passive: bool = False,
                   loopback: bool = False) -> str:
    net_type = "LOOPBACK" if loopback else "BROADCAST"
    head = f"""{name} is up, line protocol is up
  Internet Address {ip}, Area {area}, Attached via Network Statement
  Process ID 1, Router ID 1.1.1.1, Network Type {net_type}, Cost: 10
  Topology-MTID    Cost    Disabled    Shutdown      Topology Name
        0           10        no          no            Base
"""
    if loopback:
        return head + "  Loopback interface is treated as a stub Host\n"
    body = f"""  Transmit Delay is 1 sec, State DR, Priority 1
  Designated Router (ID) 1.1.1.1, Interface address {ip.split('/')[0]}
  Timer intervals configured, Hello {hello}, Dead {dead}, Wait {dead}, Retransmit 5
    oob-resync timeout {dead}
"""
    body += "    No Hellos (Passive interface)\n" if passive else "    Hello due in 00:00:03\n"
    return head + body + "  Supports Link-local Signaling (LLS)\n  Index 1/1/1, flood queue length 0\n"


ETHERCHANNEL_HEADER = """Flags:  D - down        P - bundled in port-channel
        I - stand-alone s - suspended
        H - Hot-standby (LACP only)
        R - Layer3      S - Layer2
        U - in use      N - not in use, no aggregation

Number of channel-groups in use: 1
Number of aggregators:           1

Group  Port-channel  Protocol    Ports
------+-------------+-----------+-----------------------------------------------
"""


# ---------------------------------------------------------------- SW1

SW1 = {
    "show running-config": """Building configuration...

Current configuration : 2000 bytes
!
hostname SW1
!
ip domain-name lab.local
ip ssh version 2
ntp server 192.168.100.1
logging buffered 16384
logging host 192.168.100.1
!
interface Port-channel1
 switchport trunk native vlan 99
 switchport trunk allowed vlan 10,99
 switchport mode trunk
!
interface Ethernet0/1
 switchport trunk native vlan 99
 switchport trunk allowed vlan 10,20,99
 switchport mode trunk
!
interface Ethernet0/2
 switchport mode trunk
 channel-group 1 mode passive
!
interface Ethernet0/3
 switchport mode trunk
 channel-group 1 mode passive
!
interface Ethernet1/0
 no switchport
 ip address 10.0.12.1 255.255.255.252
!
interface Ethernet1/1
 no switchport
 ip address 10.0.21.1 255.255.255.252
 speed 100
 duplex full
!
interface Ethernet1/2
 switchport access vlan 10
 switchport mode access
!
interface Ethernet1/3
 no switchport
 ip address 10.1.0.1 255.255.255.0
!
interface Ethernet2/0
 no switchport
 ip address 10.0.30.1 255.255.255.252
!
interface Ethernet2/1
 no switchport
 ip address 10.0.13.1 255.255.255.252
!
interface Ethernet2/2
 switchport mode trunk
!
interface Ethernet3/0
!
interface Ethernet3/1
 switchport access vlan 999
 switchport mode access
 switchport nonegotiate
 shutdown
!
interface Ethernet3/2
 switchport mode dynamic desirable
!
interface Ethernet3/3
 switchport access vlan 10
!
interface Loopback0
 ip address 1.1.1.1 255.255.255.255
!
router ospf 1
 network 0.0.0.0 255.255.255.255 area 0
!
line con 0
 exec-timeout 0 0
 logging synchronous
line vty 0 4
 transport input ssh
!
end
""",
    "show interfaces": "".join([
        show_interface("Ethernet0/1"),
        show_interface("Ethernet0/2"),
        show_interface("Ethernet0/3"),
        show_interface("Ethernet1/0", mtu=1500, ip="10.0.12.1/30"),
        show_interface("Ethernet1/1", ip="10.0.21.1/30"),
        show_interface("Ethernet1/2"),
        show_interface("Ethernet1/3", ip="10.1.0.1/24"),
        show_interface("Ethernet2/0", ip="10.0.30.1/30"),
        show_interface("Ethernet2/1", ip="10.0.13.1/30"),
        show_interface("Ethernet2/2"),
        show_interface("Ethernet3/0", status="down", duplex="Auto-duplex", speed="Auto-speed"),
        show_interface("Ethernet3/1", status="administratively down", duplex="Auto-duplex", speed="Auto-speed"),
        show_interface("Ethernet3/2"),
        show_interface("Ethernet3/3"),
        show_interface("Port-channel1", status="down"),
    ]),
    "show interfaces switchport": "".join([
        switchport("Et0/1", "trunk", "trunk", native=99, allowed="10,20,99"),
        switchport("Et0/2", "trunk", "trunk", native=99, allowed="10,99"),
        switchport("Et0/3", "trunk", "trunk", native=99, allowed="10,99"),
        switchport("Et1/0", enabled=False),
        switchport("Et1/2", "static access", "static access"),
        switchport("Et2/2", "trunk", "trunk"),
        switchport("Et3/0", "dynamic auto", "down"),
        switchport("Et3/1", "static access", "down", access=999, nonegotiate=True),
        switchport("Et3/2", "dynamic desirable", "trunk"),
        switchport("Et3/3", "dynamic auto", "static access", access=10),
        switchport("Po1", "trunk", "down", native=99, allowed="10,99"),
    ]),
    "show vlan brief": vlan_brief({1: "default", 10: "USERS", 20: "SERVERS", 99: "MGMT", 999: "PARKING"}),
    "show etherchannel summary": ETHERCHANNEL_HEADER + "1      Po1(SD)         LACP      Et0/2(I)    Et0/3(I)\n",
    "show cdp neighbors detail": "".join(
        [cdp_entry("SW2.lab.local", SW2_IP, f"Ethernet{p}", f"Ethernet{p}")
         for p in ("0/1", "0/2", "0/3", "1/0", "1/1", "1/2", "2/0", "2/2", "3/2")]
        + [cdp_entry("R3", "10.0.13.2", "Ethernet2/1", "Ethernet0/0")]
    ) + "\nTotal cdp entries displayed : 10\n",
    "show ip ospf interface": "".join([
        ospf_interface("Loopback0", "1.1.1.1/32", "0", loopback=True),
        ospf_interface("Ethernet1/0", "10.0.12.1/30", "0"),
        ospf_interface("Ethernet1/1", "10.0.21.1/30", "0"),
        ospf_interface("Ethernet1/3", "10.1.0.1/24", "0"),
        ospf_interface("Ethernet2/0", "10.0.30.1/30", "0"),
        ospf_interface("Ethernet2/1", "10.0.13.1/30", "0"),
    ]),
    "show ip ospf neighbor": """
Neighbor ID     Pri   State           Dead Time   Address         Interface
3.3.3.3           1   EXSTART/DR      00:00:33    10.0.13.2       Ethernet2/1
""",
    "show ntp status": ntp_synced("192.168.100.1"),
    "show crypto key mypubkey rsa": rsa_keys("SW1.lab.local"),
}


# ---------------------------------------------------------------- SW2

SW2 = {
    "show running-config": """Building configuration...

hostname SW2
!
ip domain name lab.example
logging buffered 16384
!
interface Port-channel1
 switchport trunk native vlan 99
 switchport trunk allowed vlan 10,99
 switchport mode trunk
!
interface Port-channel2
 switchport trunk native vlan 99
 switchport trunk allowed vlan 10,99
 switchport mode trunk
!
interface Ethernet0/1
 switchport trunk allowed vlan 10,99
 switchport mode trunk
!
interface Ethernet0/2
 switchport mode trunk
 channel-group 1 mode passive
!
interface Ethernet0/3
 switchport mode trunk
 channel-group 2 mode passive
!
interface Ethernet1/0
 no switchport
 ip address 10.0.12.2 255.255.255.252
 ip ospf hello-interval 5
 ip ospf dead-interval 20
 mtu 1400
!
interface Ethernet1/1
 no switchport
 ip address 10.0.21.2 255.255.255.252
!
interface Ethernet1/2
 switchport trunk native vlan 99
 switchport mode trunk
!
interface Ethernet2/0
 no switchport
 ipv6 address 2001:db8:30::2/64
 ipv6 ospf 1 area 0
!
interface Ethernet2/2
 switchport mode trunk
!
interface Ethernet3/0
 switchport access vlan 10
 switchport mode access
!
interface Ethernet3/2
!
router ospf 1
 passive-interface Ethernet1/1
 network 10.0.12.0 0.0.0.3 area 1
 network 10.0.21.0 0.0.0.3 area 0
!
line con 0
line vty 0 4
 transport input ssh
!
end
""",
    "show interfaces": "".join([
        show_interface("Ethernet0/1"),
        show_interface("Ethernet0/2"),
        show_interface("Ethernet0/3"),
        show_interface("Ethernet1/0", mtu=1400, ip="10.0.12.2/30"),
        show_interface("Ethernet1/1", duplex="Half-duplex", ip="10.0.21.2/30"),
        show_interface("Ethernet1/2"),
        show_interface("Ethernet2/0"),
        show_interface("Ethernet2/2"),
        show_interface("Ethernet3/0", status="down", duplex="Auto-duplex", speed="Auto-speed"),
        show_interface("Ethernet3/2"),
        show_interface("Port-channel1", status="down"),
        show_interface("Port-channel2", status="down"),
    ]),
    "show interfaces switchport": "".join([
        switchport("Et0/1", "trunk", "trunk", native=1, allowed="10,99"),
        switchport("Et0/2", "trunk", "trunk", native=99, allowed="10,99"),
        switchport("Et0/3", "trunk", "trunk", native=99, allowed="10,99"),
        switchport("Et1/2", "trunk", "trunk", native=99, allowed="ALL"),
        switchport("Et2/2", "trunk", "trunk"),
        switchport("Et3/0", "static access", "down", access=10),
        switchport("Et3/2", "dynamic auto", "trunk", encap="negotiate"),
        switchport("Po1", "trunk", "down", native=99, allowed="10,99"),
        switchport("Po2", "trunk", "down", native=99, allowed="10,99"),
    ]),
    "show vlan brief": vlan_brief({1: "default", 10: "USERS", 99: "MGMT"}),
    "show etherchannel summary": ETHERCHANNEL_HEADER
    + "1      Po1(SD)         LACP      Et0/2(I)\n"
    + "2      Po2(SD)         LACP      Et0/3(I)\n",
    "show cdp neighbors detail": "".join(
        cdp_entry("SW1.lab.local", SW1_IP, f"Ethernet{p}", f"Ethernet{p}")
        for p in ("0/1", "0/2", "0/3", "1/0", "1/1", "1/2", "2/0", "2/2", "3/2")
    ) + "\nTotal cdp entries displayed : 9\n",
    "show ip ospf interface": "".join([
        ospf_interface("Ethernet1/0", "10.0.12.2/30", "0.0.0.1", hello=5, dead=20),
        ospf_interface("Ethernet1/1", "10.0.21.2/30", "0", passive=True),
    ]),
    "show ip ospf neighbor": "",
    "show ntp status": "%NTP is not enabled.\n",
    "show crypto key mypubkey rsa": rsa_keys("SW2.lab.example"),
}
