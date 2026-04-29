'''
@ASSESSME.USERID: YOUR_GROUP_NAME
@ASSESSME.AUTHOR: Your Name - yourRIT, Teammate Name - teammateRIT
@ASSESSME.DESCRIPTION: Problem Solving 9
@ASSESSME.ANALYZE: YES
@ASSESSME.INTENSITY:LOW
'''

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, Sequence

import bootstrap  # noqa: F401
from scapy.all import Packet, Raw
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6, IPv6ExtHdrFragment
from scapy.layers.l2 import ARP, Ether


@dataclass(frozen=True)
class PacketSummary:
    number: int
    timestamp: float
    time_text: str
    protocol: str
    src_mac: str
    dst_mac: str
    src_ip: str
    dst_ip: str
    src_port: str
    dst_port: str
    length: int
    fragmentation: str


@dataclass
class FilterCriteria:
    protocol: str = "All"
    source_ip: str = ""
    destination_ip: str = ""
    source_port: str = ""
    destination_port: str = ""


def build_packet_summary(packet: Packet, number: int) -> PacketSummary:
    timestamp = float(getattr(packet, "time", 0.0) or 0.0)
    src_mac, dst_mac = _extract_mac_addresses(packet)
    src_ip, dst_ip = _extract_network_addresses(packet)
    src_port, dst_port = _extract_transport_ports(packet)

    return PacketSummary(
        number=number,
        timestamp=timestamp,
        time_text=_format_timestamp(timestamp),
        protocol=detect_protocol(packet),
        src_mac=src_mac,
        dst_mac=dst_mac,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        length=len(bytes(packet)),
        fragmentation=_fragmentation_summary(packet),
    )


def detect_protocol(packet: Packet) -> str:
    if packet.haslayer(TCP):
        return "TCP"
    if packet.haslayer(UDP):
        return "UDP"
    if packet.haslayer(ICMP):
        return "ICMP"
    if packet.haslayer(ARP):
        return "ARP"
    if packet.haslayer(IPv6):
        return "IPv6"
    if packet.haslayer(IP):
        return "IPv4"
    if packet.haslayer(Ether):
        return "Ethernet"
    return packet.lastlayer().name if packet.lastlayer() else "Unknown"


def packet_matches(summary: PacketSummary, criteria: FilterCriteria) -> bool:
    protocol = criteria.protocol.strip().upper()
    source_ip = criteria.source_ip.strip().lower()
    destination_ip = criteria.destination_ip.strip().lower()
    source_port = criteria.source_port.strip()
    destination_port = criteria.destination_port.strip()

    if protocol and protocol != "ALL" and summary.protocol.upper() != protocol:
        return False
    if source_ip and source_ip not in summary.src_ip.lower():
        return False
    if destination_ip and destination_ip not in summary.dst_ip.lower():
        return False
    if source_port and summary.src_port != source_port:
        return False
    if destination_port and summary.dst_port != destination_port:
        return False

    return True


def format_packet_details(packet: Packet, summary: PacketSummary) -> str:
    lines = [
        "Packet Overview",
        "=" * 80,
        f"Packet Number: {summary.number}",
        f"Captured At: {summary.time_text}",
        f"Protocol: {summary.protocol}",
        f"Source: {summary.src_ip}:{summary.src_port}",
        f"Destination: {summary.dst_ip}:{summary.dst_port}",
        f"Source MAC: {summary.src_mac}",
        f"Destination MAC: {summary.dst_mac}",
        f"Length: {summary.length} bytes",
        f"Fragmentation: {summary.fragmentation}",
        "",
        "Layer Breakdown",
        "=" * 80,
    ]

    for layer in _iter_layers(packet):
        lines.extend(_format_layer(layer))
        lines.append("")

    lines.extend(
        [
            "Hex + ASCII",
            "=" * 80,
            _format_hex_ascii(bytes(packet)),
        ]
    )

    return "\n".join(lines).rstrip()


def format_statistics(
    all_summaries: Sequence[PacketSummary],
    visible_summaries: Sequence[PacketSummary],
) -> str:
    displayed_count = len(visible_summaries)
    total_count = len(all_summaries)
    displayed_bytes = sum(summary.length for summary in visible_summaries)

    lines = [
        f"Displayed packets: {displayed_count} / {total_count}",
        f"Displayed bytes: {displayed_bytes}",
    ]

    if not visible_summaries:
        lines.append("")
        lines.append("No packets match the current filters.")
        return "\n".join(lines)

    timestamps = [summary.timestamp for summary in visible_summaries if summary.timestamp]
    capture_span = max(timestamps) - min(timestamps) if len(timestamps) >= 2 else 0.0
    average_packets_per_second = displayed_count / capture_span if capture_span > 0 else float(displayed_count)
    average_bytes_per_second = displayed_bytes / capture_span if capture_span > 0 else float(displayed_bytes)

    if timestamps:
        latest_timestamp = max(timestamps)
        recent_summaries = [
            summary
            for summary in visible_summaries
            if summary.timestamp >= latest_timestamp - 5.0
        ]
        recent_packets_per_second = len(recent_summaries) / 5.0
        recent_bytes_per_second = sum(summary.length for summary in recent_summaries) / 5.0
    else:
        recent_packets_per_second = 0.0
        recent_bytes_per_second = 0.0

    lines.extend(
        [
            f"Capture span: {capture_span:.2f} s",
            f"Average packet rate: {average_packets_per_second:.2f} pkt/s",
            f"Average traffic rate: {average_bytes_per_second:.2f} B/s",
            f"Recent packet rate (5 s): {recent_packets_per_second:.2f} pkt/s",
            f"Recent traffic rate (5 s): {recent_bytes_per_second:.2f} B/s",
            "",
            "Packet count by protocol:",
        ]
    )

    protocol_counts = Counter(summary.protocol for summary in visible_summaries)
    for protocol, count in sorted(protocol_counts.items()):
        lines.append(f"  {protocol}: {count}")

    top_talkers = Counter(
        summary.src_ip
        for summary in visible_summaries
        if summary.src_ip not in {"N/A", "-"}
    ).most_common(3)
    if top_talkers:
        lines.extend(["", "Top talkers:"])
        for source_ip, count in top_talkers:
            lines.append(f"  {source_ip}: {count} packet(s)")

    return "\n".join(lines)


def _extract_mac_addresses(packet: Packet) -> tuple[str, str]:
    if packet.haslayer(Ether):
        ethernet = packet[Ether]
        return ethernet.src, ethernet.dst
    if packet.haslayer(ARP):
        arp = packet[ARP]
        return arp.hwsrc, arp.hwdst
    return "N/A", "N/A"


def _extract_network_addresses(packet: Packet) -> tuple[str, str]:
    if packet.haslayer(IP):
        ip = packet[IP]
        return ip.src, ip.dst
    if packet.haslayer(IPv6):
        ipv6 = packet[IPv6]
        return ipv6.src, ipv6.dst
    if packet.haslayer(ARP):
        arp = packet[ARP]
        return arp.psrc, arp.pdst
    return "N/A", "N/A"


def _extract_transport_ports(packet: Packet) -> tuple[str, str]:
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        return str(tcp.sport), str(tcp.dport)
    if packet.haslayer(UDP):
        udp = packet[UDP]
        return str(udp.sport), str(udp.dport)
    return "-", "-"


def _fragmentation_summary(packet: Packet) -> str:
    if packet.haslayer(IP):
        ip = packet[IP]
        flags = str(ip.flags) or "None"
        offset = int(ip.frag)
        if flags == "None" and offset == 0:
            return "None"
        return f"flags={flags}, offset={offset}"

    if packet.haslayer(IPv6ExtHdrFragment):
        fragment = packet[IPv6ExtHdrFragment]
        return f"offset={fragment.offset}, more={fragment.m}, id={fragment.id}"

    return "N/A"


def _format_timestamp(timestamp: float) -> str:
    if timestamp <= 0:
        return "--:--:--.---"
    return datetime.fromtimestamp(timestamp).strftime("%H:%M:%S.%f")[:-3]


def _iter_layers(packet: Packet) -> Iterable[Packet]:
    layer = packet
    while layer is not None and layer.__class__.__name__ != "NoPayload":
        yield layer
        layer = getattr(layer, "payload", None)


def _format_layer(layer: Packet) -> list[str]:
    if isinstance(layer, Ether):
        return [
            "[Ethernet]",
            f"  Destination MAC: {layer.dst}",
            f"  Source MAC: {layer.src}",
            f"  EtherType: {_safe_value(getattr(layer, 'type', 'N/A'))}",
        ]

    if isinstance(layer, ARP):
        return [
            "[ARP]",
            f"  Operation: {_safe_value(layer.op)}",
            f"  Sender MAC: {layer.hwsrc}",
            f"  Sender IP: {layer.psrc}",
            f"  Target MAC: {layer.hwdst}",
            f"  Target IP: {layer.pdst}",
        ]

    if isinstance(layer, IP):
        return [
            "[IPv4]",
            f"  Version: {layer.version}",
            f"  Header Length: {layer.ihl * 4 if layer.ihl else 'N/A'} bytes",
            f"  Type of Service: {layer.tos}",
            f"  Total Length: {layer.len if layer.len is not None else 'N/A'}",
            f"  Identification: {layer.id}",
            f"  Flags: {str(layer.flags) or 'None'}",
            f"  Fragment Offset: {layer.frag}",
            f"  TTL: {layer.ttl}",
            f"  Protocol Number: {layer.proto}",
            f"  Header Checksum: {_format_hex_value(layer.chksum)}",
            f"  Source IP: {layer.src}",
            f"  Destination IP: {layer.dst}",
        ]

    if isinstance(layer, IPv6):
        return [
            "[IPv6]",
            f"  Version: {layer.version}",
            f"  Traffic Class: {layer.tc}",
            f"  Flow Label: {layer.fl}",
            f"  Payload Length: {layer.plen}",
            f"  Next Header: {layer.nh}",
            f"  Hop Limit: {layer.hlim}",
            f"  Source IP: {layer.src}",
            f"  Destination IP: {layer.dst}",
        ]

    if isinstance(layer, IPv6ExtHdrFragment):
        return [
            "[IPv6 Fragment]",
            f"  Next Header: {layer.nh}",
            f"  Offset: {layer.offset}",
            f"  More Fragments: {layer.m}",
            f"  Identification: {layer.id}",
        ]

    if isinstance(layer, TCP):
        return [
            "[TCP]",
            f"  Source Port: {layer.sport}",
            f"  Destination Port: {layer.dport}",
            f"  Sequence Number: {layer.seq}",
            f"  Acknowledgement Number: {layer.ack}",
            f"  Data Offset: {layer.dataofs * 4 if layer.dataofs else 'N/A'} bytes",
            f"  Flags: {layer.sprintf('%TCP.flags%')}",
            f"  Window Size: {layer.window}",
            f"  Checksum: {_format_hex_value(layer.chksum)}",
            f"  Urgent Pointer: {layer.urgptr}",
        ]

    if isinstance(layer, UDP):
        return [
            "[UDP]",
            f"  Source Port: {layer.sport}",
            f"  Destination Port: {layer.dport}",
            f"  Length: {layer.len}",
            f"  Checksum: {_format_hex_value(layer.chksum)}",
        ]

    if isinstance(layer, ICMP):
        lines = [
            "[ICMP]",
            f"  Type: {layer.type}",
            f"  Code: {layer.code}",
            f"  Checksum: {_format_hex_value(layer.chksum)}",
        ]
        if hasattr(layer, "id"):
            lines.append(f"  Identifier: {_safe_value(getattr(layer, 'id', 'N/A'))}")
        if hasattr(layer, "seq"):
            lines.append(f"  Sequence: {_safe_value(getattr(layer, 'seq', 'N/A'))}")
        return lines

    if isinstance(layer, Raw):
        payload = bytes(layer.load)
        return [
            "[Raw Payload]",
            f"  Payload Length: {len(payload)} bytes",
            f"  Preview: {_ascii_preview(payload)}",
        ]

    lines = [f"[{layer.name}]"]
    for field_name, field_value in sorted(layer.fields.items()):
        lines.append(f"  {field_name}: {_safe_value(field_value)}")
    if len(lines) == 1:
        lines.append("  No explicit fields present")
    return lines


def _format_hex_ascii(data: bytes) -> str:
    lines = []
    for offset in range(0, len(data), 16):
        chunk = data[offset : offset + 16]
        hex_part = " ".join(f"{byte:02x}" for byte in chunk).ljust(47)
        ascii_part = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in chunk)
        lines.append(f"{offset:04x}  {hex_part}  {ascii_part}")
    return "\n".join(lines) if lines else "(empty packet)"


def _ascii_preview(data: bytes, limit: int = 64) -> str:
    preview = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in data[:limit])
    if len(data) > limit:
        preview += "..."
    return preview or "(no printable payload)"


def _format_hex_value(value: object) -> str:
    if isinstance(value, int):
        return hex(value)
    return _safe_value(value)


def _safe_value(value: object) -> str:
    if isinstance(value, bytes):
        return value.hex()
    return str(value)
