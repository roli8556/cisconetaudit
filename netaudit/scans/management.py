"""
Management-plane checks: hostname, domain name, logging synchronous, NTP and syslog.

Device checks look at one device; network checks compare all scanned devices (e.g. "every device
should have the same domain name"). Both are generators that yield Findings, like baseline.py.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterator

from ..models import DeviceSnapshot, Finding, Fix, FixInput, FixTarget

DEFAULT_HOSTNAMES = {"router", "switch"}  # what IOS shows when no hostname is configured


def device_target(device: DeviceSnapshot, **params: str) -> FixTarget:
    """A whole-device fix target. Carries the SSH key info, because a hostname or domain change
    can disable SSH (see fix_inputs.pin_ssh_key). **params collects keyword arguments into a dict."""
    return FixTarget(device.host_ip, device.hostname, "", {
        "rsa_key": device.rsa_key_name,
        "pinned": "yes" if device.management.ssh_keypair_pinned else "no",
        **params,  # ** unpacks a dict into this one
    })


def most_common(values: list[str]) -> str:
    """The value most devices use, or "" - Counter counts how often each value occurs."""
    counts = Counter(v for v in values if v)
    return counts.most_common(1)[0][0] if counts else ""


# ---------------------------------------------------------------- per device


def check_hostname(device: DeviceSnapshot, others: list[DeviceSnapshot]) -> Iterator[Finding]:
    configured = device.management.hostname
    if configured and configured.lower() not in DEFAULT_HOSTNAMES:
        return
    taken = ",".join(d.hostname for d in others if d is not device)
    yield Finding(
        "hostname-not-set", "low", f"{device.hostname} ({device.host_ip})",
        "No hostname is configured (the device uses the default '"
        f"{device.hostname}'). Logs, CDP and SSH keys can't tell this device apart from others.",
        "Set a unique hostname. The current SSH key is pinned first, so SSH keeps working.",
        fix_input=FixInput("hostname", f"Hostname for {device.host_ip}", "",
                           [device_target(device, taken=taken)]),
    )


def check_logging_synchronous(device: DeviceSnapshot, others: list[DeviceSnapshot]) -> Iterator[Finding]:
    missing = device.management.lines_without_logging_sync
    if not missing:
        return
    commands = [cmd for line in missing for cmd in (line, "logging synchronous")]
    yield Finding(
        "logging-synchronous", "low", f"{device.hostname} lines",
        f"'logging synchronous' is missing on: {', '.join(missing)}. Log messages then interrupt "
        "whatever is being typed on the CLI, which makes mistakes during changes more likely.",
        "Add 'logging synchronous' to those lines.",
        [Fix(device.host_ip, device.hostname, commands)],
    )


def check_ntp(device: DeviceSnapshot, others: list[DeviceSnapshot]) -> Iterator[Finding]:
    servers = device.management.ntp_servers
    location = f"{device.hostname} NTP"
    if not servers:
        suggestion = most_common([s for d in others for s in d.management.ntp_servers])
        yield Finding(
            "ntp-not-configured", "medium", location,
            "No NTP server is configured. Log timestamps can't be correlated between devices, and "
            "certificates and time-based ACLs depend on a correct clock.",
            "Configure an NTP server" + (f" ({suggestion} is used by the other devices)." if suggestion else "."),
            fix_input=FixInput("ntp-server", f"NTP server for {device.hostname} (IP address)", suggestion,
                               [device_target(device)]),
        )
    elif device.ntp is None or not device.ntp.synchronized:
        yield Finding(
            "ntp-not-synchronized", "medium", location,
            f"NTP server(s) {', '.join(servers)} configured, but the clock is NOT synchronized"
            + (f" (stratum {device.ntp.stratum})" if device.ntp and device.ntp.stratum else "") + ".",
            "No automatic fix: check that the server is reachable from this device (routing, ACLs, "
            "NTP authentication keys) - 'show ntp associations' shows what the device sees.",
        )
    elif device.ntp.offset_ms is not None and abs(device.ntp.offset_ms) > 1000:
        yield Finding(
            "ntp-large-offset", "low", location,
            f"Synchronized, but the clock is {device.ntp.offset_ms:.0f} ms off its NTP reference.",
            "No automatic fix: usually settles by itself; if not, check the path to the NTP server.",
        )


def check_syslog(device: DeviceSnapshot, others: list[DeviceSnapshot]) -> Iterator[Finding]:
    if device.management.logging_hosts:
        return
    suggestion = most_common([h for d in others for h in d.management.logging_hosts])
    yield Finding(
        "no-syslog-server", "medium", f"{device.hostname} syslog",
        "No syslog server is configured. Logs only live in the device's small buffer and are lost "
        "on reload - an attacker's actions (or a failing link) leave no lasting trace.",
        "Send logs to a syslog server" + (f" ({suggestion} is used by the other devices)." if suggestion else "."),
        fix_input=FixInput("syslog-server", f"Syslog server for {device.hostname} (IP address)", suggestion,
                           [device_target(device)]),
    )


DEVICE_CHECKS = [check_hostname, check_logging_synchronous, check_ntp, check_syslog]


# ---------------------------------------------------------------- across all devices


def check_domain_names(devices: list[DeviceSnapshot]) -> Iterator[Finding]:
    domains = {d.hostname: d.management.domain_name for d in devices}
    if all(domains.values()) and len(set(domains.values())) == 1:
        return  # all set, all the same
    suggestion = most_common(list(domains.values()))
    overview = ", ".join(f"{host}: {domain or '(none)'}" for host, domain in domains.items())
    yield Finding(
        "domain-name-mismatch", "low", "all devices: ip domain name",
        f"Not every device has the same IP domain name ({overview}). The domain is part of the "
        "devices' SSH key names and DNS lookups; mixed or missing domains make both inconsistent.",
        "Set the same domain name on every device that differs. The current SSH key is pinned "
        "first, so SSH keeps working.",
        fix_input=FixInput(
            "domain-name", "IP domain name for all devices", suggestion,
            [device_target(d, current=d.management.domain_name, command=d.management.domain_command)
             for d in devices],
        ),
    )


def _time_source(device: DeviceSnapshot, by_ip: dict[str, DeviceSnapshot]) -> str:
    """Follow the NTP chain through scanned devices to its root: if SW2 syncs to SW1 and SW1
    syncs to 10.0.0.1, both get their time from 10.0.0.1."""
    seen = set()
    current = device
    while current.ntp and current.ntp.synchronized and current.ntp.reference:
        reference = current.ntp.reference
        upstream = by_ip.get(reference)
        if upstream is None or upstream.host_ip in seen:
            return reference  # an outside server (or a loop) - this is the root
        seen.add(upstream.host_ip)
        current = upstream
    return ""


def check_time_sources(devices: list[DeviceSnapshot]) -> Iterator[Finding]:
    """Devices that are synchronized should share ONE time source."""
    by_ip = {ip: d for d in devices for ip in d.ip_addresses}  # every interface IP -> its device
    sources = {d.hostname: _time_source(d, by_ip) for d in devices}
    synced = {host: src for host, src in sources.items() if src}
    if len(set(synced.values())) > 1:
        overview = ", ".join(f"{host} -> {src}" for host, src in synced.items())
        yield Finding(
            "ntp-different-sources", "medium", "all devices: NTP source",
            f"Devices are synchronized to different time sources ({overview}). Their clocks can "
            "drift apart, so log timestamps from different devices don't line up.",
            "No automatic fix: point every device (directly or through each other) at the same NTP servers.",
        )


NETWORK_CHECKS = [check_domain_names, check_time_sources]
