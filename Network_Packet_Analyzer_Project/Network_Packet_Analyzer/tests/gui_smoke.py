"""Exercise the real desktop widgets; optional Pillow screenshots for the report.

Run from the project folder on a graphical desktop:
  python -m tests.gui_smoke
  python -m tests.gui_smoke --screenshots-dir docs/screenshots
Pillow is needed only for the optional screenshots, not for the application.
"""
from tests import offline_bootstrap  # noqa: F401

import argparse
import os
import tempfile
import time
import tkinter as tk
from pathlib import Path

from analyzer.core import read_capture
from analyzer.gui import AnalyzerApp


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--screenshots-dir")
    args = parser.parse_args()
    root = tk.Tk()
    app = AnalyzerApp(root)
    root.geometry("1440x940+0+0")
    root.update()
    screenshots = Path(args.screenshots_dir) if args.screenshots_dir else None
    if screenshots:
        screenshots.mkdir(parents=True, exist_ok=True)

    def settle():
        for _ in range(4):
            root.update()
            time.sleep(0.03)

    def screenshot(name):
        if screenshots:
            from PIL import Image, ImageGrab
            settle()
            box = (root.winfo_rootx(), root.winfo_rooty(), root.winfo_rootx() + root.winfo_width(),
                   root.winfo_rooty() + root.winfo_height())
            destination = screenshots/name
            temporary = screenshots/("tmp_" + name)
            ImageGrab.grab(bbox=box).save(temporary, format="PNG")
            with Image.open(temporary) as check:
                check.verify()
            os.replace(temporary, destination)

    try:
        app.demo_button.invoke()
        deadline = time.monotonic() + 10
        while app.active and time.monotonic() < deadline:
            root.update()
            time.sleep(0.02)
        assert not app.active, "Demo import did not finish"
        assert len(app.store.records) == 37
        assert len(app.table.get_children()) == 37
        assert app.metric_vars["bytes"].get() == "2,384 B"
        app.table.selection_set("3")
        app.table.focus("3")
        app.inspect_selected()
        assert "portal.example" in app.decoded_text.get("1.0", "end")
        screenshot("01_packet_explorer.png")
        app.protocol_var.set("DNS")
        assert app.apply_filter()
        assert len(app.table.get_children()) == 8
        app.table.selection_set("3")
        app.inspect_selected()
        screenshot("02_dns_filter.png")
        app.detail_tabs.select(1)
        screenshot("03_hex_preview.png")
        with tempfile.TemporaryDirectory() as folder:
            destination = Path(folder)
            assert app.export_view("csv", destination/"dns.csv", notify=False) == 8
            assert app.export_view("pcap", destination/"dns.pcap", notify=False) == 8
            assert len(read_capture(destination/"dns.pcap").records) == 8
        app.tabs.select(1)
        settle()
        app.draw_statistics()
        screenshot("04_traffic_statistics.png")
        app.tabs.select(0)
        app.reset_filter()
        app.ip_var.set("2001:db8::/32")
        app.apply_filter()
        assert len(app.table.get_children()) == 5
        app.reset_filter()
        assert len(app.table.get_children()) == 37
        print("GUI CHECKS PASSED: demo import, table, metrics, decoded selection, DNS filter, hex view, CSV export, PCAP reopen, statistics, IPv6 filter and reset.")
        if screenshots:
            print(f"Saved four real application screenshots to {screenshots}")
    finally:
        app.close()


if __name__ == "__main__":
    main()
