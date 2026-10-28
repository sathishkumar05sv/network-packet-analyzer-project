from tests import offline_bootstrap  # noqa: F401 - import before Scapy

import contextlib
import csv
import io
import json
import queue
import tempfile
import threading
import time
import unittest
from pathlib import Path

from scapy.all import DNS, DNSQR, IP, TCP, UDP, Ether, Raw, PcapNgWriter, PcapReader

from analyzer.capture import CaptureWorker
from analyzer.core import DisplayFilter, PacketStore, decode_packet, export_csv, export_pcap, read_capture
from analyzer.demo import demo_packets, write_demo
from main import main


class AnalyzerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.packets = demo_packets()
        cls.store = PacketStore()
        for packet in cls.packets:
            cls.store.add(packet)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.folder = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_demo_has_expected_independent_protocol_counts(self):
        self.assertEqual(len(self.packets), 37)
        self.assertEqual(self.store.statistics()["protocols"], {
            "ARP": 2, "DNS": 8, "TCP": 14, "UDP": 4, "ICMP": 4,
            "ICMPv6": 2, "IPv4": 1, "IPv6": 1, "OTHER": 1})

    def test_ipv4_tcp_addresses_ports_and_flags(self):
        record = self.store.filtered(DisplayFilter("TCP"))[0]
        self.assertEqual((record.source, record.destination), ("192.0.2.10", "198.51.100.20"))
        self.assertEqual((record.source_port, record.destination_port), (51000, 443))
        self.assertIn("Flags [S]", record.info)
        self.assertEqual(record.ip_version, 4)

    def test_ipv6_addresses_and_icmpv6(self):
        records = self.store.filtered(DisplayFilter("ICMPv6"))
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0].source, "2001:db8::10")
        self.assertEqual(records[0].ip_version, 6)

    def test_dns_query_name_and_transport(self):
        record = self.store.filtered(DisplayFilter("DNS"))[0]
        self.assertIn("portal.example", record.info)
        self.assertEqual(record.transport, "UDP")
        self.assertEqual(record.destination_port, 53)

    def test_port_443_is_not_inferred_as_https(self):
        records = self.store.filtered(DisplayFilter(port="443"))
        self.assertTrue(records)
        self.assertEqual({record.protocol for record in records}, {"TCP"})

    def test_dns_over_tcp_is_a_tcp_filter_match(self):
        packet = Ether(src="02:00:00:00:00:10", dst="02:00:00:00:00:20")/IP(src="192.0.2.10", dst="203.0.113.53")/TCP(sport=51000, dport=53)/DNS(qd=DNSQR(qname="lab.example"))
        record = decode_packet(packet, 1)
        self.assertEqual(record.protocol, "DNS")
        self.assertTrue(DisplayFilter("TCP").matches(record))
        self.assertFalse(DisplayFilter("UDP").matches(record))

    def test_udp_filter_includes_dns_over_udp(self):
        self.assertEqual(len(self.store.filtered(DisplayFilter("UDP"))), 12)

    def test_exact_ip_matches_either_endpoint(self):
        records = self.store.filtered(DisplayFilter(ip="203.0.113.53"))
        self.assertEqual(len(records), 8)

    def test_ipv6_cidr_filter(self):
        records = self.store.filtered(DisplayFilter(ip="2001:db8::/32"))
        self.assertEqual(len(records), 5)

    def test_filters_combine_with_and(self):
        records = self.store.filtered(DisplayFilter("DNS", ip="192.0.2.10", port="53", search="PORTAL"))
        self.assertEqual(len(records), 2)

    def test_invalid_filter_is_rejected(self):
        for arguments in ({"ip":"not-an-ip"}, {"port":"-1"}, {"port":"65536"}, {"port":"abc"}, {"protocol":"HTTPS"}):
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                DisplayFilter(**arguments)

    def test_zero_port_is_supported(self):
        packet = Ether(src="02:00:00:00:00:10", dst="02:00:00:00:00:20")/IP(src="192.0.2.10", dst="198.51.100.20")/UDP(sport=0, dport=9999)
        self.assertTrue(DisplayFilter(port="0").matches(decode_packet(packet, 1)))

    def test_unknown_frame_is_retained(self):
        record = self.store.records[-1]
        self.assertEqual(record.protocol, "OTHER")
        self.assertIsNone(record.source_port)

    def test_packet_count_limit_is_exact(self):
        store = PacketStore(max_packets=2)
        for packet in self.packets[:5]:
            store.add(packet)
        self.assertEqual(len(store.records), 2)
        self.assertTrue(store.limit_reached)

    def test_byte_limit_stops_future_retention(self):
        store = PacketStore(max_bytes=len(bytes(self.packets[0])))
        store.add(self.packets[0])
        store.add(self.packets[1])
        store.add(self.packets[0])
        self.assertEqual(len(store.records), 1)
        self.assertTrue(store.limit_reached)

    def test_invalid_packet_is_skipped(self):
        store = PacketStore()
        self.assertIsNone(store.add(object()))
        self.assertEqual(store.decode_errors, 1)

    def test_statistics_are_consistent(self):
        stats = self.store.statistics()
        self.assertEqual(sum(stats["protocols"].values()), 37)
        self.assertEqual(stats["duration_seconds"], 4.5)
        self.assertEqual(stats["captured_bytes"], sum(len(bytes(packet)) for packet in self.packets))

    def test_out_of_order_timestamps_use_minimum_and_maximum(self):
        store = PacketStore()
        for stamp in (30, 10, 20):
            packet = self.packets[0].copy()
            packet.time = stamp
            store.add(packet)
        self.assertEqual(store.statistics()["duration_seconds"], 20)

    def test_csv_exports_only_filtered_packets(self):
        output = self.folder/"dns.csv"
        self.assertEqual(export_csv(self.store.filtered(DisplayFilter("DNS")), output), 8)
        with output.open(newline="", encoding="utf-8") as stream:
            rows = list(csv.DictReader(stream))
        self.assertEqual(len(rows), 8)
        self.assertEqual({row["Protocol"] for row in rows}, {"DNS"})

    def test_pcap_export_round_trip_preserves_bytes_and_timestamps(self):
        output = self.folder/"roundtrip.pcap"
        self.assertEqual(export_pcap(self.store.records, output), 37)
        reopened = read_capture(output)
        self.assertEqual([bytes(record.packet) for record in reopened.records], [bytes(packet) for packet in self.packets])
        self.assertEqual([record.timestamp for record in reopened.records], [float(packet.time) for packet in self.packets])

    def test_mixed_link_type_export_is_rejected_without_overwriting(self):
        output = self.folder/"existing.pcap"
        output.write_bytes(b"keep original")
        records = [self.store.records[0], decode_packet(IP(src="192.0.2.10", dst="198.51.100.20")/TCP(), 2)]
        with self.assertRaises(ValueError):
            export_pcap(records, output)
        self.assertEqual(output.read_bytes(), b"keep original")

    def test_pcapng_import(self):
        output = self.folder/"demo.pcapng"
        with PcapNgWriter(str(output)) as writer:
            for packet in self.packets:
                writer.write(packet)
        self.assertEqual(len(read_capture(output).records), 37)

    def test_invalid_file_reports_error(self):
        output = self.folder/"bad.pcap"
        output.write_bytes(b"not a capture")
        with self.assertRaises(Exception):
            read_capture(output)

    def test_cli_filters_and_exports(self):
        capture = self.folder/"demo.pcap"
        write_demo(capture)
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            result = main(["--analyze", str(capture), "--protocol", "DNS", "--csv", str(self.folder/"dns.csv")])
        self.assertEqual(result, 0)
        summary = json.loads(stdout.getvalue())
        self.assertEqual(summary["matching_packets"], 8)
        self.assertEqual(summary["statistics"]["packets"], 37)

    def test_cli_invalid_ip_returns_error(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            result = main(["--analyze", "unused.pcap", "--ip", "bad-ip"])
        self.assertEqual(result, 2)
        self.assertIn("valid IPv4", stderr.getvalue())

    def test_offline_worker_streams_without_dropping(self):
        path = self.folder/"demo.pcap"
        write_demo(path)
        worker = CaptureWorker(queue_size=2)
        worker.start_file(path)
        packets = []
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and (worker.busy or not worker.packets.empty()):
            try:
                packets.append(worker.packets.get(timeout=0.1))
            except queue.Empty:
                pass
        self.assertFalse(worker.busy)
        self.assertEqual(len(packets), 37)
        self.assertEqual(worker.queue_drops, 0)

    def test_offline_worker_cancels_when_queue_is_full(self):
        path = self.folder/"demo.pcap"
        write_demo(path)
        worker = CaptureWorker(queue_size=1)
        worker.start_file(path)
        deadline = time.monotonic() + 3
        while worker.packets.empty() and time.monotonic() < deadline:
            time.sleep(0.01)
        worker.stop()
        worker.thread.join(timeout=2)
        self.assertFalse(worker.busy)

    def test_live_handoff_queue_counts_application_drops(self):
        worker = CaptureWorker(queue_size=1)
        worker._offer_live(self.packets[0])
        worker._offer_live(self.packets[1])
        self.assertEqual(worker.queue_drops, 1)
        self.assertEqual(worker.packets.qsize(), 1)

    def test_live_startup_error_reaches_event_queue(self):
        class FailingSniffer:
            def __init__(self, **kwargs):
                pass
            def start(self):
                raise PermissionError("test capture permission denied")
        worker = CaptureWorker(sniffer_factory=FailingSniffer)
        worker.start_live("test-interface")
        worker.thread.join(timeout=2)
        events = list(worker.events.queue)
        self.assertEqual(events[0][0], "error")
        self.assertIn("permission denied", events[0][1])
        self.assertEqual(events[-1][0], "done")


if __name__ == "__main__":
    unittest.main(verbosity=2)
