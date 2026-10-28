"""Launch the desktop app or analyze a capture without a display."""
from __future__ import annotations

import argparse
import json
import sys


def main(argv=None):
    parser = argparse.ArgumentParser(description="Network Packet Analyzer - Sathish Kumar and Team")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--demo", action="store_true", help="Open desktop app with the synthetic demo")
    source.add_argument("--pcap", metavar="FILE", help="Open a PCAP/PCAPNG in the desktop app")
    source.add_argument("--analyze", metavar="FILE", help="Analyze a saved capture in the terminal")
    parser.add_argument("--protocol", default="ALL", help="ALL, TCP, UDP, DNS, ICMP, ICMPv6, ARP, IPv4, IPv6 or OTHER")
    parser.add_argument("--ip", default="", help="Endpoint IP or CIDR")
    parser.add_argument("--port", default="", help="Source or destination port")
    parser.add_argument("--search", default="", help="Case insensitive metadata search")
    parser.add_argument("--csv", metavar="FILE", help="Export matching CLI records to CSV")
    parser.add_argument("--save-pcap", metavar="FILE", help="Export matching CLI packets to PCAP")
    parser.add_argument("--limit", type=int, default=5000, help="CLI packet retention limit, 1 through 5000")
    args = parser.parse_args(argv)
    if not 1 <= args.limit <= 5000:
        parser.error("--limit must be between 1 and 5000")
    if not args.analyze and (args.csv or args.save_pcap or args.protocol != "ALL" or args.ip or args.port or args.search or args.limit != 5000):
        parser.error("Filtering and export arguments require --analyze FILE")
    try:
        from analyzer.core import DisplayFilter, export_csv, export_pcap, read_capture
        if args.analyze:
            display_filter = DisplayFilter(args.protocol, args.ip, args.port, args.search)
            store = read_capture(args.analyze, max_packets=args.limit)
            records = store.filtered(display_filter)
            result = {"source": args.analyze, "statistics_scope": "all retained packets",
                      "statistics": store.statistics(), "matching_packets": len(records)}
            if args.csv:
                result["csv_exported_packets"] = export_csv(records, args.csv)
            if args.save_pcap:
                result["pcap_exported_packets"] = export_pcap(records, args.save_pcap)
            print(json.dumps(result, indent=2))
        else:
            from analyzer.gui import launch
            launch(demo=args.demo, capture_path=args.pcap)
    except ModuleNotFoundError as error:
        print(f"Missing dependency: {error.name}. Run: python -m pip install -r requirements.txt\n"
              "Linux GUI users may also need their distribution's python3-tk package.", file=sys.stderr)
        return 2
    except Exception as error:
        print(f"Could not complete operation: {error}", file=sys.stderr)
        if "display" in str(error).lower():
            print("Use a graphical desktop, or run: python main.py --analyze samples/demo_capture.pcap", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
