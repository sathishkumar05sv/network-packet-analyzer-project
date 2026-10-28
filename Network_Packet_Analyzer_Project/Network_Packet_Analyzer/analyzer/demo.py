"""Deterministic synthetic packets. They are written to a file, never sent."""
from pathlib import Path

from scapy.all import ARP, DNS, DNSQR, DNSRR, ICMP, IP, IPv6, TCP, UDP, Ether, Raw, wrpcap
from scapy.layers.inet6 import ICMPv6EchoRequest, ICMPv6EchoReply


def demo_packets():
    client, server, resolver = "192.0.2.10", "198.51.100.20", "203.0.113.53"
    mac_a, mac_b = "02:00:00:00:00:10", "02:00:00:00:00:20"
    def frame(payload, reverse=False):
        return Ether(src=mac_b if reverse else mac_a,
                     dst=mac_a if reverse else mac_b) / payload
    packets = [
        frame(ARP(op=1, psrc=client, pdst="192.0.2.1", hwsrc=mac_a, hwdst="00:00:00:00:00:00")),
        frame(ARP(op=2, psrc="192.0.2.1", pdst=client, hwsrc=mac_b, hwdst=mac_a), True),
    ]
    for number, name in enumerate(["portal.example", "library.example", "college.example", "lab.example"]):
        question = DNSQR(qname=name)
        packets.append(frame(IP(src=client, dst=resolver) / UDP(sport=53000 + number, dport=53) /
                             DNS(id=100 + number, rd=1, qd=question)))
        packets.append(frame(IP(src=resolver, dst=client) / UDP(sport=53, dport=53000 + number) /
                             DNS(id=100 + number, qr=1, aa=1, qd=question,
                                 an=DNSRR(rrname=name, ttl=300, rdata=server)), True))
    for number in range(2):
        port = 51000 + number
        for reverse, flags, sequence, acknowledgment in [
            (False, "S", 1000, 0), (True, "SA", 9000, 1001),
            (False, "A", 1001, 9001), (False, "PA", 1001, 9001),
            (True, "A", 9001, 1024), (True, "FA", 9001, 1024),
        ]:
            payload = IP(src=server if reverse else client, dst=client if reverse else server) / TCP(
                sport=443 if reverse else port, dport=port if reverse else 443,
                flags=flags, seq=sequence, ack=acknowledgment)
            if flags == "PA":
                payload /= Raw(b"Synthetic demo payload.")
            packets.append(frame(payload, reverse))
    for number in range(4):
        packets.append(frame(IP(src=client, dst=server) / UDP(sport=54000 + number, dport=9999) /
                             Raw(f"Lab datagram {number + 1}".encode())))
    for number in range(2):
        packets.append(frame(IP(src=client, dst=server) / ICMP(type=8, id=7, seq=number) / Raw(b"demo echo")))
        packets.append(frame(IP(src=server, dst=client) / ICMP(type=0, id=7, seq=number) / Raw(b"demo echo"), True))
    packets.extend([
        frame(IPv6(src="2001:db8::10", dst="2001:db8::20") / ICMPv6EchoRequest(id=9, data=b"IPv6 demo")),
        frame(IPv6(src="2001:db8::20", dst="2001:db8::10") / ICMPv6EchoReply(id=9, data=b"IPv6 demo"), True),
        frame(IPv6(src="2001:db8::10", dst="2001:db8::20") / TCP(sport=55000, dport=443, flags="S")),
        frame(IPv6(src="2001:db8::20", dst="2001:db8::10") / TCP(sport=443, dport=55000, flags="SA"), True),
        frame(IP(src=client, dst=server, proto=253) / Raw(b"Experimental IPv4 payload")),
        frame(IPv6(src="2001:db8::10", dst="2001:db8::20", nh=59) / Raw(b"No next header demo")),
        Ether(src=mac_a, dst=mac_b, type=0x88B5) / Raw(b"Local experimental Ethernet frame"),
    ])
    # Re-dissection produces the same fields and checksums as opening the PCAP.
    normalized = []
    for index, packet in enumerate(packets):
        decoded = Ether(bytes(packet))
        decoded.time = 1793091600.0 + index * 0.125
        normalized.append(decoded)
    return normalized


def write_demo(path: str | Path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(path), demo_packets())
