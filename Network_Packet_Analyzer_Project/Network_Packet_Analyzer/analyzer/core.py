"""Packet decoding, display filters, bounded storage and atomic file exports.

This module has no GUI dependency. All counters describe retained packets,
not all traffic on the network. No packet transmission is performed here.
"""
from __future__ import annotations

import csv
import ipaddress
import os
import tempfile
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from scapy.all import ARP, DNS, ICMP, IP, IPv6, TCP, UDP, PcapReader, PcapWriter, conf
from scapy.packet import Packet

PROTOCOLS = ("ALL", "TCP", "UDP", "DNS", "ICMP", "ICMPv6", "ARP", "IPv4", "IPv6", "OTHER")
MAX_PACKETS = 5_000
MAX_CAPTURE_BYTES = 32 * 1024 * 1024


def clean_text(value: object, limit: int = 240) -> str:
    """Keep untrusted packet text on one printable line."""
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    return "".join(ch if ch.isprintable() else " " for ch in str(value))[:limit]


@dataclass(frozen=True)
class PacketRecord:
    number: int
    timestamp: float
    source: str
    destination: str
    protocol: str
    transport: str
    source_port: int | None
    destination_port: int | None
    length: int
    ip_version: int | None
    info: str
    packet: Packet = field(repr=False, compare=False)

    @property
    def time_text(self) -> str:
        return datetime.fromtimestamp(self.timestamp, timezone.utc).strftime("%H:%M:%S.%f")[:-3]

    @property
    def ports_text(self) -> str:
        if self.source_port is None:
            return "-"
        return f"{self.source_port} > {self.destination_port}"


def decode_packet(packet: Packet, number: int) -> PacketRecord:
    """Extract metadata while leaving full decoding to Scapy on selection."""
    source = clean_text(packet.fields.get("src", "-"))
    destination = clean_text(packet.fields.get("dst", "-"))
    version = None
    protocol = "OTHER"
    transport = ""
    source_port = destination_port = None
    info = clean_text(packet.summary())
    if IP in packet:
        ip = packet[IP]
        source, destination, version = str(ip.src), str(ip.dst), 4
        protocol = "IPv4"
    elif IPv6 in packet:
        ip = packet[IPv6]
        source, destination, version = str(ip.src), str(ip.dst), 6
        protocol = "IPv6"
    elif ARP in packet:
        arp = packet[ARP]
        source, destination = str(arp.psrc), str(arp.pdst)
        protocol = "ARP"
        info = f"{'Request' if int(arp.op) == 1 else 'Reply'}  {source} > {destination}"
    if TCP in packet:
        tcp = packet[TCP]
        protocol = transport = "TCP"
        source_port, destination_port = int(tcp.sport), int(tcp.dport)
        info = f"{source_port} > {destination_port}  Flags [{tcp.flags}]  Seq {tcp.seq}  Ack {tcp.ack}"
    elif UDP in packet:
        udp = packet[UDP]
        protocol = transport = "UDP"
        source_port, destination_port = int(udp.sport), int(udp.dport)
        info = f"{source_port} > {destination_port}  Datagram"
    elif ICMP in packet:
        protocol = transport = "ICMP"
        icmp = packet[ICMP]
        info = f"Type {icmp.type}  Code {icmp.code}  Id {getattr(icmp, 'id', '-')}"
    elif version == 6:
        # Includes common ICMPv6 messages even behind IPv6 extension headers.
        for layer in packet.iterpayloads():
            if layer.__class__.__name__.startswith("ICMPv6"):
                protocol = transport = "ICMPv6"
                info = clean_text(layer.summary())
                break
    if DNS in packet and transport in ("TCP", "UDP"):
        dns = packet[DNS]
        protocol = "DNS"
        name = ""
        try:
            if dns.qd:
                name = clean_text(dns.qd[0].qname, 140).rstrip(".")
        except (AttributeError, IndexError, TypeError):
            name = "unavailable question"
        info = f"{'Response' if dns.qr else 'Query'}  {name}  ID {dns.id}  over {transport}"
    timestamp = float(packet.time)
    # Validate timestamps early so one invalid packet cannot break GUI formatting.
    datetime.fromtimestamp(timestamp, timezone.utc)
    return PacketRecord(number, timestamp, clean_text(source), clean_text(destination),
                        protocol, transport, source_port, destination_port,
                        len(bytes(packet)), version, clean_text(info), packet)


@dataclass(frozen=True)
class DisplayFilter:
    """All nonempty conditions are ANDed; ports match either endpoint."""
    protocol: str = "ALL"
    ip: str = ""
    port: str = ""
    search: str = ""
    _network: object = field(init=False, repr=False, compare=False, default=None)
    _port_number: int | None = field(init=False, repr=False, compare=False, default=None)

    def __post_init__(self):
        if self.protocol not in PROTOCOLS:
            raise ValueError("Choose a supported protocol from the list.")
        if self.ip.strip():
            try:
                network = ipaddress.ip_network(self.ip.strip(), strict=False)
            except ValueError as error:
                raise ValueError("Enter a valid IPv4/IPv6 address or CIDR network.") from error
            object.__setattr__(self, "_network", network)
        if self.port.strip():
            if not self.port.strip().isascii() or not self.port.strip().isdigit():
                raise ValueError("Port must be a whole number from 0 to 65535.")
            number = int(self.port.strip())
            if not 0 <= number <= 65535:
                raise ValueError("Port must be between 0 and 65535.")
            object.__setattr__(self, "_port_number", number)

    def matches(self, record: PacketRecord) -> bool:
        if self.protocol in ("TCP", "UDP"):
            if record.transport != self.protocol:
                return False
        elif self.protocol in ("IPv4", "IPv6"):
            if record.ip_version != (4 if self.protocol == "IPv4" else 6):
                return False
        elif self.protocol != "ALL" and record.protocol != self.protocol:
            return False
        if self._network is not None:
            found = False
            for address in (record.source, record.destination):
                try:
                    found |= ipaddress.ip_address(address) in self._network
                except ValueError:
                    pass
            if not found:
                return False
        if self._port_number is not None and self._port_number not in (
                record.source_port, record.destination_port):
            return False
        if self.search.strip():
            haystack = f"{record.source} {record.destination} {record.protocol} {record.transport} {record.ports_text} {record.info}"
            if self.search.strip().casefold() not in haystack.casefold():
                return False
        return True


class PacketStore:
    """GUI-thread-owned session store with packet and captured-byte bounds."""
    def __init__(self, max_packets=MAX_PACKETS, max_bytes=MAX_CAPTURE_BYTES):
        if max_packets <= 0 or max_bytes <= 0:
            raise ValueError("Retention limits must be positive.")
        self.max_packets, self.max_bytes = max_packets, max_bytes
        self.records: list[PacketRecord] = []
        self.total_bytes = 0
        self.limit_reached = False
        self.decode_errors = 0

    def add(self, packet: Packet) -> PacketRecord | None:
        if self.limit_reached:
            return None
        if len(self.records) >= self.max_packets:
            self.limit_reached = True
            return None
        try:
            record = decode_packet(packet, len(self.records) + 1)
        except Exception:
            self.decode_errors += 1
            return None
        if self.total_bytes + record.length > self.max_bytes:
            self.limit_reached = True
            return None
        self.records.append(record)
        self.total_bytes += record.length
        return record

    def filtered(self, display_filter: DisplayFilter) -> list[PacketRecord]:
        return [record for record in self.records if display_filter.matches(record)]

    def statistics(self) -> dict:
        times = [record.timestamp for record in self.records]
        duration = max(times) - min(times) if len(times) > 1 else 0.0
        return {
            "packets": len(self.records), "captured_bytes": self.total_bytes,
            "duration_seconds": round(duration, 6),
            "average_packet_bytes": round(self.total_bytes / len(self.records), 2) if self.records else 0,
            "protocols": dict(Counter(record.protocol for record in self.records)),
            "ip_versions": dict(Counter(f"IPv{record.ip_version}" if record.ip_version else "Non IP"
                                        for record in self.records)),
            "top_sources": Counter(record.source for record in self.records).most_common(5),
            "top_destinations": Counter(record.destination for record in self.records).most_common(5),
            "decode_errors": self.decode_errors, "retention_limit_reached": self.limit_reached,
        }


def read_capture(path: str | Path, max_packets=MAX_PACKETS) -> PacketStore:
    store = PacketStore(max_packets=max_packets)
    with Path(path).open("rb") as stream, PcapReader(stream) as reader:
        for packet in reader:
            store.add(packet)
            if store.limit_reached:
                break
    return store


def _temporary_path(destination: Path) -> Path:
    handle = tempfile.NamedTemporaryFile(prefix=".packet-export-", dir=destination.parent, delete=False)
    handle.close()
    return Path(handle.name)


def _csv_safe(text: str) -> str:
    # CSV files may be opened in spreadsheets; packet text is untrusted input.
    return "'" + text if text.lstrip().startswith(("=", "+", "-", "@")) else text


def export_csv(records: Iterable[PacketRecord], path: str | Path) -> int:
    destination = Path(path)
    temporary = _temporary_path(destination)
    count = 0
    try:
        with temporary.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.writer(stream)
            writer.writerow(["Number", "Timestamp UTC", "Source", "Destination", "Protocol",
                             "Transport", "Source port", "Destination port", "Captured bytes", "Info"])
            for record in records:
                timestamp = datetime.fromtimestamp(record.timestamp, timezone.utc).isoformat(timespec="microseconds")
                writer.writerow([record.number, timestamp, _csv_safe(record.source),
                                 _csv_safe(record.destination), record.protocol, record.transport,
                                 record.source_port if record.source_port is not None else "",
                                 record.destination_port if record.destination_port is not None else "",
                                 record.length, _csv_safe(record.info)])
                count += 1
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)
    return count


def export_pcap(records: Iterable[PacketRecord], path: str | Path) -> int:
    records = list(records)
    if not records:
        raise ValueError("No matching packets to export.")
    linktypes = {conf.l2types.layer2num.get(type(record.packet)) for record in records}
    if None in linktypes or len(linktypes) != 1:
        raise ValueError("These packets use different or unsupported link types. Export CSV, or select one link type before saving PCAP.")
    destination = Path(path)
    temporary = _temporary_path(destination)
    try:
        with PcapWriter(str(temporary), linktype=next(iter(linktypes)), sync=True) as writer:
            for record in records:
                writer.write(record.packet)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)
    return len(records)
