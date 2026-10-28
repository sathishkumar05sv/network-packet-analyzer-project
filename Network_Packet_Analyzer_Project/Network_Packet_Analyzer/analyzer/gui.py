"""Tkinter desktop interface. Only the main thread touches Tk widgets."""
from __future__ import annotations

import queue
import time
import tkinter as tk
import tkinter.font as tkfont
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from scapy.all import conf, get_if_list, hexdump

from .capture import CaptureWorker
from .core import DisplayFilter, MAX_CAPTURE_BYTES, MAX_PACKETS, PROTOCOLS, PacketStore, export_csv, export_pcap
from .demo import write_demo

ROOT = Path(__file__).resolve().parent.parent
COLORS = {"navy": "#142b45", "blue": "#245c96", "teal": "#007b78", "bg": "#eef2f6",
          "ink": "#19334d", "muted": "#597084", "line": "#d5dee7", "white": "#ffffff"}
PROTOCOL_COLORS = {"TCP": "#2b63a0", "UDP": "#956221", "DNS": "#00857b", "ICMP": "#7558a4",
                   "ICMPv6": "#a04c7b", "ARP": "#687b31", "IPv4": "#677889", "IPv6": "#526b87", "OTHER": "#858585"}


class AnalyzerApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Network Packet Analyzer | Sathish Kumar and Team")
        width = max(1100, min(1440, self.root.winfo_screenwidth() - 70))
        height = max(720, min(940, self.root.winfo_screenheight() - 80))
        self.root.geometry(f"{width}x{height}")
        self.root.minsize(1100, 720)
        self.root.configure(bg=COLORS["bg"])
        self.store = PacketStore()
        self.worker = CaptureWorker()
        self.active = False
        self.worker_done = False
        self.completion_message = ""
        self.current_filter = DisplayFilter()
        self.visible_records = []
        self.source_label = "No capture loaded"
        self._last_metrics = 0.0
        self._closing = False
        self._style()
        self._build()
        self.refresh_interfaces()
        self.refresh_metrics()
        self.root.after(80, self._poll)
        self.root.protocol("WM_DELETE_WINDOW", self.close)
        self.root.bind("<Control-o>", lambda event: self.open_capture())
        self.root.bind("<Control-d>", lambda event: self.load_demo())
        self.root.bind("<Escape>", lambda event: self.stop_capture())

    def _style(self):
        self.style = ttk.Style(self.root)
        self.style.theme_use("clam")
        families = {family.casefold(): family for family in tkfont.families(self.root)}
        self.font = next((families[name.casefold()] for name in ("Segoe UI", "DejaVu Sans", "Arial", "Helvetica")
                          if name.casefold() in families), tkfont.nametofont("TkDefaultFont").actual("family"))
        self.mono_font = next((families[name.casefold()] for name in ("Consolas", "DejaVu Sans Mono", "Courier")
                               if name.casefold() in families), tkfont.nametofont("TkFixedFont").actual("family"))
        tkfont.nametofont("TkDefaultFont").configure(family=self.font, size=10)
        self.style.configure("TFrame", background=COLORS["bg"])
        self.style.configure("White.TFrame", background="white")
        self.style.configure("TLabel", background=COLORS["bg"], foreground=COLORS["ink"], font=(self.font, 10))
        self.style.configure("Small.TLabel", foreground=COLORS["muted"], font=(self.font, 9))
        self.style.configure("White.TLabel", background="white", foreground=COLORS["ink"])
        self.style.configure("Metric.TLabel", background="white", foreground=COLORS["navy"], font=(self.font, 22, "bold"))
        self.style.configure("Caption.TLabel", background="white", foreground=COLORS["muted"], font=(self.font, 9))
        self.style.configure("TButton", padding=(12, 8), font=(self.font, 9))
        self.style.configure("Primary.TButton", background=COLORS["blue"], foreground="white", font=(self.font, 9, "bold"))
        self.style.map("Primary.TButton", background=[("active", "#1a4978"), ("disabled", "#b9c7d4")],
                       foreground=[("disabled", "#f8fafb")])
        self.style.configure("TEntry", padding=5)
        self.style.configure("TCombobox", padding=5)
        self.style.configure("Treeview", background="white", fieldbackground="white", foreground=COLORS["ink"],
                             rowheight=29, font=(self.font, 9), borderwidth=0)
        self.style.configure("Treeview.Heading", background="#e7edf3", foreground=COLORS["navy"],
                             font=(self.font, 9, "bold"), padding=(5, 8))
        self.style.map("Treeview", background=[("selected", "#cfdfef")], foreground=[("selected", "#142b45")])
        self.style.configure("TNotebook", background=COLORS["bg"], borderwidth=0)
        self.style.configure("TNotebook.Tab", padding=(18, 9), font=(self.font, 10))
        self.style.map("TNotebook.Tab", background=[("selected", "white")])
        self.style.configure("Horizontal.TProgressbar", troughcolor="#dbe5ee", background=COLORS["teal"])

    def _build(self):
        header = tk.Frame(self.root, bg=COLORS["navy"], padx=22, pady=16)
        header.pack(fill="x")
        tk.Label(header, text="NPA", font=(self.font, 16, "bold"), bg="#235271", fg="white", padx=12, pady=8).pack(side="left", padx=(0, 15))
        names = tk.Frame(header, bg=COLORS["navy"])
        names.pack(side="left")
        tk.Label(names, text="Network Packet Analyzer", bg=COLORS["navy"], fg="white", font=(self.font, 21, "bold")).pack(anchor="w")
        tk.Label(names, text="Sathish Kumar and Team  |  Computer Networks Mini Project", bg=COLORS["navy"], fg="#c5d7e6", font=(self.font, 10)).pack(anchor="w", pady=(4, 0))
        self.badge = tk.Label(header, text="READY", bg="#25465d", fg="#dceaf4", font=(self.font, 10, "bold"), padx=14, pady=8)
        self.badge.pack(side="right")

        body = ttk.Frame(self.root, padding=(18, 12, 18, 4))
        body.pack(fill="both", expand=True)
        actions = ttk.Frame(body)
        actions.pack(fill="x", pady=(0, 9))
        self.demo_button = ttk.Button(actions, text="Load demo", command=self.load_demo, style="Primary.TButton")
        self.demo_button.pack(side="left", padx=(0, 7))
        self.open_button = ttk.Button(actions, text="Open PCAP", command=self.open_capture)
        self.open_button.pack(side="left", padx=(0, 7))
        self.csv_button = ttk.Button(actions, text="Export view as CSV", command=lambda: self.export_view("csv"))
        self.csv_button.pack(side="left", padx=(0, 7))
        self.pcap_button = ttk.Button(actions, text="Save view as PCAP", command=lambda: self.export_view("pcap"))
        self.pcap_button.pack(side="left", padx=(0, 7))
        self.clear_button = ttk.Button(actions, text="Clear", command=self.clear)
        self.clear_button.pack(side="left")
        ttk.Label(actions, text="Offline demo never sends packets", style="Small.TLabel").pack(side="right")

        live = ttk.Frame(body)
        live.pack(fill="x", pady=(0, 12))
        ttk.Label(live, text="Interface").pack(side="left", padx=(0, 7))
        self.interface_var = tk.StringVar()
        self.interface_box = ttk.Combobox(live, textvariable=self.interface_var, state="readonly", width=26)
        self.interface_box.pack(side="left", padx=(0, 6))
        self.refresh_button = ttk.Button(live, text="Refresh", command=self.refresh_interfaces)
        self.refresh_button.pack(side="left", padx=(0, 14))
        ttk.Label(live, text="Capture filter BPF").pack(side="left", padx=(0, 7))
        self.bpf_var = tk.StringVar()
        self.bpf_entry = ttk.Entry(live, textvariable=self.bpf_var, width=25)
        self.bpf_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self.start_button = ttk.Button(live, text="Start capture", command=self.start_capture, style="Primary.TButton")
        self.start_button.pack(side="left", padx=(0, 7))
        self.stop_button = ttk.Button(live, text="Stop", command=self.stop_capture, state="disabled")
        self.stop_button.pack(side="left")

        metrics = ttk.Frame(body)
        metrics.pack(fill="x", pady=(0, 12))
        self.metric_vars = {}
        for index, (key, title) in enumerate([("packets", "RETAINED PACKETS"), ("bytes", "CAPTURED BYTES"),
                                              ("visible", "MATCHING PACKETS"), ("span", "CAPTURE SPAN")]):
            metrics.columnconfigure(index, weight=1, uniform="metric")
            card = ttk.Frame(metrics, style="White.TFrame", padding=(16, 10))
            card.grid(row=0, column=index, sticky="nsew", padx=(0 if index == 0 else 5, 0 if index == 3 else 5))
            ttk.Label(card, text=title, style="Caption.TLabel").pack(anchor="w")
            variable = tk.StringVar(value="0")
            ttk.Label(card, textvariable=variable, style="Metric.TLabel").pack(anchor="w", pady=(5, 0))
            self.metric_vars[key] = variable

        self.status_var = tk.StringVar(value="Ready. Load the demo, open a capture, or select an interface.")
        self.health_var = tk.StringVar(value="")
        ttk.Label(body, textvariable=self.health_var, style="Small.TLabel").pack(side="bottom", fill="x", pady=(0, 4))
        ttk.Label(body, textvariable=self.status_var, style="Small.TLabel").pack(side="bottom", fill="x", pady=(8, 4))
        self.tabs = ttk.Notebook(body)
        self.tabs.pack(fill="both", expand=True)
        self.explorer = ttk.Frame(self.tabs, style="White.TFrame", padding=12)
        self.statistics_tab = ttk.Frame(self.tabs, style="White.TFrame", padding=18)
        self.help_tab = ttk.Frame(self.tabs, style="White.TFrame", padding=18)
        self.tabs.add(self.explorer, text="Packet explorer")
        self.tabs.add(self.statistics_tab, text="Traffic statistics")
        self.tabs.add(self.help_tab, text="Run and demonstrate")
        self.tabs.bind("<<NotebookTabChanged>>", lambda event: self.draw_statistics())
        self._build_explorer()
        self._build_statistics()
        self._build_help()

    def _build_explorer(self):
        filters = ttk.Frame(self.explorer, style="White.TFrame")
        filters.pack(fill="x", pady=(0, 9))
        self.protocol_var = tk.StringVar(value="ALL")
        self.ip_var, self.port_var, self.search_var = tk.StringVar(), tk.StringVar(), tk.StringVar()
        for label, variable, width, values in [
            ("Protocol", self.protocol_var, 9, PROTOCOLS), ("IP or CIDR", self.ip_var, 22, None),
            ("Port", self.port_var, 7, None), ("Search", self.search_var, 22, None)]:
            ttk.Label(filters, text=label, style="White.TLabel").pack(side="left", padx=(0, 6))
            widget = ttk.Combobox(filters, textvariable=variable, values=values, state="readonly", width=width) if values else ttk.Entry(filters, textvariable=variable, width=width)
            widget.pack(side="left", padx=(0, 12), fill="x", expand=label == "Search")
            widget.bind("<Return>", lambda event: self.apply_filter())
        ttk.Button(filters, text="Apply", command=self.apply_filter, style="Primary.TButton").pack(side="left", padx=(0, 6))
        ttk.Button(filters, text="Reset", command=self.reset_filter).pack(side="left")
        self.view_label_var = tk.StringVar(value="Select a packet to inspect its decoded fields and bytes. Times are UTC.")
        ttk.Label(self.explorer, textvariable=self.view_label_var, style="Caption.TLabel").pack(anchor="w", pady=(0, 8))
        panes = ttk.Panedwindow(self.explorer, orient="vertical")
        panes.pack(fill="both", expand=True)
        upper = ttk.Frame(panes, style="White.TFrame")
        lower = ttk.Frame(panes, style="White.TFrame")
        panes.add(upper, weight=3)
        panes.add(lower, weight=2)
        columns = ("number", "time", "source", "destination", "protocol", "ports", "length", "info")
        self.table = ttk.Treeview(upper, columns=columns, show="headings", selectmode="browse", height=10)
        specs = [("No", 45, False), ("Time UTC", 110, False), ("Source", 165, True), ("Destination", 165, True),
                 ("Protocol", 76, False), ("Ports", 112, False), ("Bytes", 60, False), ("Information", 290, True)]
        for column, (title, width, stretch) in zip(columns, specs):
            self.table.heading(column, text=title)
            self.table.column(column, width=width, minwidth=40, stretch=stretch,
                              anchor="center" if column in ("number", "protocol", "length") else "w")
        scroll = ttk.Scrollbar(upper, orient="vertical", command=self.table.yview)
        horizontal = ttk.Scrollbar(upper, orient="horizontal", command=self.table.xview)
        self.table.configure(yscrollcommand=scroll.set, xscrollcommand=horizontal.set)
        self.table.grid(row=0, column=0, sticky="nsew")
        scroll.grid(row=0, column=1, sticky="ns")
        horizontal.grid(row=1, column=0, sticky="ew")
        upper.rowconfigure(0, weight=1)
        upper.columnconfigure(0, weight=1)
        for protocol in PROTOCOL_COLORS:
            self.table.tag_configure(protocol, foreground=PROTOCOL_COLORS[protocol])
        self.table.bind("<<TreeviewSelect>>", self.inspect_selected)
        self.detail_title_var = tk.StringVar(value="Packet inspector")
        ttk.Label(lower, textvariable=self.detail_title_var, style="White.TLabel", font=(self.font, 10, "bold")).pack(anchor="w", pady=(9, 6))
        self.detail_tabs = ttk.Notebook(lower)
        self.detail_tabs.pack(fill="both", expand=True)
        self.decoded_text = self._text_tab(self.detail_tabs, "Decoded fields")
        self.hex_text = self._text_tab(self.detail_tabs, "Hex preview")
        self._set_text(self.decoded_text, "Load demo to begin. Select a row to view its protocol fields.\n\n"
                       "Retention: 5,000 packets or 32 MiB of captured bytes per session.\n"
                       "Exports contain the current matching view.")

    def _text_tab(self, notebook, title):
        frame = ttk.Frame(notebook, style="White.TFrame")
        notebook.add(frame, text=title)
        text = tk.Text(frame, wrap="none", font=(self.mono_font, 9),
                       bg="#f8fafc", fg=COLORS["ink"], relief="flat", padx=10, pady=8, height=8)
        scroll = ttk.Scrollbar(frame, orient="vertical", command=text.yview)
        xscroll = ttk.Scrollbar(frame, orient="horizontal", command=text.xview)
        text.configure(yscrollcommand=scroll.set, xscrollcommand=xscroll.set)
        text.grid(row=0, column=0, sticky="nsew")
        scroll.grid(row=0, column=1, sticky="ns")
        xscroll.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        return text

    @staticmethod
    def _set_text(widget, text):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.configure(state="disabled")

    def _build_statistics(self):
        ttk.Label(self.statistics_tab, text="Protocol distribution", style="White.TLabel", font=(self.font, 16, "bold")).pack(anchor="w")
        ttk.Label(self.statistics_tab, text="All retained packets. Each packet has one display label; DNS is counted separately from TCP and UDP.",
                  style="Caption.TLabel").pack(anchor="w", pady=(5, 8))
        self.chart = tk.Canvas(self.statistics_tab, height=295, bg="white", highlightthickness=0)
        self.chart.pack(fill="x")
        self.chart.bind("<Configure>", lambda event: self.draw_statistics())
        endpoints = ttk.Frame(self.statistics_tab, style="White.TFrame")
        endpoints.pack(fill="both", expand=True, pady=(8, 0))
        self.source_tree = self._endpoint_table(endpoints, "Top source addresses", 0)
        self.destination_tree = self._endpoint_table(endpoints, "Top destination addresses", 1)
        self.statistics_summary = tk.StringVar()
        ttk.Label(self.statistics_tab, textvariable=self.statistics_summary, style="Caption.TLabel").pack(anchor="w", pady=(10, 0))

    def _endpoint_table(self, parent, title, column):
        parent.columnconfigure(column, weight=1, uniform="endpoints")
        parent.rowconfigure(0, weight=1)
        frame = ttk.Frame(parent, style="White.TFrame", padding=(0 if column == 0 else 16, 0, 0, 0))
        frame.grid(row=0, column=column, sticky="nsew")
        ttk.Label(frame, text=title, style="White.TLabel", font=(self.font, 11, "bold")).pack(anchor="w", pady=(0, 8))
        table = ttk.Treeview(frame, columns=("address", "count"), show="headings", height=5)
        table.heading("address", text="Address")
        table.heading("count", text="Packets")
        table.column("address", width=260)
        table.column("count", width=80, anchor="center", stretch=False)
        table.pack(fill="both", expand=True)
        return table

    def _build_help(self):
        title = ttk.Label(self.help_tab, text="A five minute project demonstration", style="White.TLabel", font=(self.font, 17, "bold"))
        title.pack(anchor="w", pady=(0, 14))
        content = (
            "1. LOAD THE DEMO\n"
            "Click Load demo. It opens synthetic Ethernet, IPv4, IPv6, TCP, UDP, DNS, ICMP and ARP packets.\n"
            "No traffic is transmitted and no administrator permission is needed for demo/file analysis.\n\n"
            "2. EXPLAIN A PACKET\n"
            "Select a DNS row. Read its source, destination, transport ports, query name and decoded layers.\n"
            "Protocol labels come from decoded headers. Port 443 alone does not prove HTTPS.\n\n"
            "3. FILTER AND EXPORT\n"
            "Choose DNS, apply it, then export the matching view as CSV or PCAP.\n"
            "IP accepts an exact address or CIDR, for example 192.0.2.10 or 2001:db8::/32.\n"
            "Port matches source OR destination. Different filter fields are combined with AND.\n\n"
            "4. COMPARE IN WIRESHARK\n"
            "Open samples/demo_capture.pcap in Wireshark. Compare the packet count, addresses, DNS and TCP fields.\n"
            "Wireshark display filters such as dns or tcp.port == 443 differ from BPF capture filters.\n\n"
            "5. TRY LIVE CAPTURE\n"
            "Use a network interface you are allowed to inspect. Start capture, browse your own test page, then Stop.\n"
            "Windows needs Npcap. Capture permissions depend on its installation settings.\n"
            "Linux/macOS need appropriate capture permissions. BPF examples: tcp, udp port 53, host 192.0.2.10.\n\n"
            "MEASUREMENT LIMITS\n"
            "The table shows traffic visible to the selected interface, not every device on a switched network.\n"
            "HTTPS application contents remain encrypted. This project does not reassemble TCP streams,\n"
            "decrypt TLS, validate all checksums, or claim to detect intrusions.\n"
            "Session retention stops at 5,000 packets or 32 MiB captured bytes; Python memory use is higher.\n"
            "Queue drops are application handoff drops, not a measurement of all operating-system packet loss.\n"
        )
        help_text = tk.Text(self.help_tab, wrap="word", bg="white", fg=COLORS["ink"], relief="flat", font=(self.font, 10), spacing1=3, spacing3=3)
        help_text.pack(fill="both", expand=True)
        self._set_text(help_text, content)

    def refresh_interfaces(self):
        try:
            conf.ifaces.reload()
            interfaces = list(get_if_list())
        except Exception:
            interfaces = []
        self.interface_box.configure(values=interfaces)
        if interfaces and self.interface_var.get() not in interfaces:
            self.interface_var.set(interfaces[0])
        elif not interfaces:
            self.interface_var.set("")

    def _confirm_replace(self, ask=True):
        return not self.store.records or not ask or messagebox.askyesno("Replace current session", "The current session will be cleared. Export it first if you want to keep it. Continue?", parent=self.root)

    def _reset_session(self, source):
        self.store = PacketStore()
        self.visible_records = []
        self.table.delete(*self.table.get_children())
        self.source_label = source
        self.worker_done = False
        self.completion_message = ""
        self.detail_title_var.set("Packet inspector")
        self._set_text(self.decoded_text, "Select a packet to inspect its decoded fields.")
        self._set_text(self.hex_text, "")
        self.reset_filter()

    def _set_active(self, active):
        self.active = active
        for button in (self.demo_button, self.open_button, self.clear_button, self.start_button, self.refresh_button):
            button.configure(state="disabled" if active else "normal")
        self.interface_box.configure(state="disabled" if active else "readonly")
        self.bpf_entry.configure(state="disabled" if active else "normal")
        self.stop_button.configure(state="normal" if active else "disabled")
        self.badge.configure(text="RUNNING" if active else "READY", bg="#086d70" if active else "#25465d")

    def load_demo(self, ask=True):
        if self.active:
            return
        path = ROOT / "samples" / "demo_capture.pcap"
        if not path.exists():
            try:
                write_demo(path)
            except Exception as error:
                messagebox.showerror("Demo unavailable", str(error), parent=self.root)
                return
        self.open_capture(path, ask=ask, demo=True)

    def open_capture(self, path=None, ask=True, demo=False):
        if self.active:
            return
        if path is None:
            path = filedialog.askopenfilename(title="Open packet capture", filetypes=[("Capture files", "*.pcap *.pcapng *.cap"), ("All files", "*.*")], parent=self.root)
        if not path or not self._confirm_replace(ask):
            return
        self._reset_session("Synthetic demo capture" if demo else Path(path).name)
        self._set_active(True)
        self.status_var.set(f"Reading {self.source_label} ...")
        self.worker.start_file(path)

    def start_capture(self):
        if self.active:
            return
        if not self.interface_var.get():
            messagebox.showinfo("Choose an interface", "No capture interface was found. You can still open PCAP files or load the demo.", parent=self.root)
            return
        if not self._confirm_replace():
            return
        self._reset_session(f"Live interface {self.interface_var.get()}")
        self._set_active(True)
        self.status_var.set(f"Capturing from {self.interface_var.get()}. Click Stop to finish.")
        self.worker.start_live(self.interface_var.get(), self.bpf_var.get())

    def stop_capture(self):
        if self.active:
            self.worker.stop()
            self.stop_button.configure(state="disabled")
            self.status_var.set("Stopping capture or import; processing queued packets ...")

    def clear(self):
        if not self.active and self._confirm_replace():
            self._reset_session("No capture loaded")
            self.status_var.set("Session cleared. Load a demo or open a capture.")
            self.refresh_metrics()

    def _insert_record(self, record):
        self.table.insert("", "end", iid=str(record.number), values=(record.number, record.time_text, record.source,
                          record.destination, record.protocol, record.ports_text, record.length, record.info), tags=(record.protocol,))

    def apply_filter(self, quiet=False):
        try:
            new_filter = DisplayFilter(self.protocol_var.get(), self.ip_var.get(), self.port_var.get(), self.search_var.get())
        except ValueError as error:
            if not quiet:
                messagebox.showerror("Check display filter", str(error), parent=self.root)
            return False
        self.current_filter = new_filter
        self.visible_records = self.store.filtered(new_filter)
        self.table.delete(*self.table.get_children())
        for record in self.visible_records:
            self._insert_record(record)
        self.detail_title_var.set("Packet inspector")
        self._set_text(self.decoded_text, "Select a matching packet to inspect its fields.")
        self._set_text(self.hex_text, "")
        self.refresh_metrics()
        return True

    def reset_filter(self):
        self.protocol_var.set("ALL")
        self.ip_var.set("")
        self.port_var.set("")
        self.search_var.set("")
        self.apply_filter(quiet=True)

    def inspect_selected(self, event=None):
        selected = self.table.selection()
        if not selected:
            return
        record = self.store.records[int(selected[0]) - 1]
        self.detail_title_var.set(f"Packet {record.number}  |  {record.protocol}  |  {record.length} captured bytes")
        try:
            details = record.packet.show(dump=True)
            if len(details) > 14000:
                details = details[:14000] + "\n[Decoded preview truncated]"
            self._set_text(self.decoded_text, details)
            preview = bytes(record.packet)[:256]
            text = hexdump(preview, dump=True)
            if record.length > 256:
                text += f"\n\nFirst 256 of {record.length} captured bytes. PCAP export preserves the captured packet."
            self._set_text(self.hex_text, text)
        except Exception as error:
            self._set_text(self.decoded_text, f"Packet details unavailable: {error}")

    def export_view(self, kind, path=None, notify=True):
        snapshot = list(self.visible_records)
        if not snapshot:
            if notify:
                messagebox.showinfo("No matching packets", "Load packets or change your display filter before exporting.", parent=self.root)
            return 0
        if path is None:
            path = filedialog.asksaveasfilename(title="Export current matching view", defaultextension=f".{kind}",
                    initialfile=f"packet_view.{kind}", filetypes=[(kind.upper(), f"*.{kind}")], parent=self.root)
        if not path:
            return 0
        try:
            count = (export_csv if kind == "csv" else export_pcap)(snapshot, path)
        except Exception as error:
            if notify:
                messagebox.showerror("Export failed", str(error), parent=self.root)
            else:
                raise
            return 0
        self.status_var.set(f"Exported {count} matching packets to {Path(path).name}.")
        return count

    def refresh_metrics(self):
        stats = self.store.statistics()
        count, size = stats["packets"], stats["captured_bytes"]
        self.metric_vars["packets"].set(f"{count:,}")
        self.metric_vars["bytes"].set(f"{size:,} B" if size < 100_000 else f"{size / 1024:.1f} KiB")
        self.metric_vars["visible"].set(f"{len(self.visible_records):,}")
        self.metric_vars["span"].set(f"{stats['duration_seconds']:.3f} s")
        self.view_label_var.set(f"{self.source_label}  |  Showing {len(self.visible_records):,} of {count:,} retained packets  |  UTC timestamps")
        self.health_var.set(f"Retention limit: {MAX_PACKETS:,} packets / {MAX_CAPTURE_BYTES // (1024 * 1024)} MiB captured bytes"
                            f"    |    Queue drops: {self.worker.queue_drops:,}    |    Decode skips: {self.store.decode_errors:,}"
                            + ("    |    RETENTION LIMIT REACHED" if self.store.limit_reached else ""))
        if self.tabs.index(self.tabs.select()) == 1:
            self.draw_statistics()

    def draw_statistics(self):
        if not hasattr(self, "chart"):
            return
        self.chart.delete("all")
        stats = self.store.statistics()
        total = stats["packets"]
        if not total:
            self.chart.create_text(20, 45, text="Load a capture to see protocol statistics.", anchor="w", fill=COLORS["muted"], font=(self.font, 11))
        width = max(self.chart.winfo_width(), 600)
        for index, (protocol, count) in enumerate(sorted(stats["protocols"].items(), key=lambda item: (-item[1], item[0]))):
            y = 8 + index * 30
            self.chart.create_text(0, y + 10, text=protocol, anchor="w", fill=COLORS["ink"], font=(self.font, 10, "bold"))
            self.chart.create_rectangle(100, y + 2, width - 155, y + 19, fill="#edf2f6", outline="")
            self.chart.create_rectangle(100, y + 2, 100 + (width - 255) * count / total, y + 19, fill=PROTOCOL_COLORS.get(protocol, "#687889"), outline="")
            self.chart.create_text(width - 135, y + 10, text=f"{count:>3}   {count / total:5.1%}", anchor="w", fill=COLORS["ink"], font=(self.font, 10))
        for table, key in ((self.source_tree, "top_sources"), (self.destination_tree, "top_destinations")):
            table.delete(*table.get_children())
            for address, count in stats[key]:
                table.insert("", "end", values=(address, count))
        self.statistics_summary.set(f"Captured bytes: {stats['captured_bytes']:,}    |    Average packet: {stats['average_packet_bytes']:.2f} bytes"
                                    f"    |    Capture timestamp span: {stats['duration_seconds']:.3f} seconds")

    def _poll(self):
        if self._closing:
            return
        changed = False
        start = time.monotonic()
        for _ in range(200):
            if time.monotonic() - start > 0.025:
                break
            try:
                packet = self.worker.packets.get_nowait()
            except queue.Empty:
                break
            record = self.store.add(packet)
            changed = True
            if record is not None and self.current_filter.matches(record):
                self.visible_records.append(record)
                self._insert_record(record)
            if self.store.limit_reached:
                self.worker.stop()
        while True:
            try:
                kind, text = self.worker.events.get_nowait()
            except queue.Empty:
                break
            if kind == "error":
                messagebox.showerror("Capture or import error", text, parent=self.root)
            elif kind == "done":
                self.worker_done = True
                self.completion_message = text
        if self.active and self.worker_done and self.worker.packets.empty() and not self.worker.busy:
            self._set_active(False)
            self.status_var.set(f"{self.completion_message}. {len(self.store.records):,} packets retained."
                                + (" Retention limit reached; remaining packets were not retained." if self.store.limit_reached else ""))
            changed = True
        if changed or time.monotonic() - self._last_metrics > 1:
            self.refresh_metrics()
            self._last_metrics = time.monotonic()
        self.root.after(80, self._poll)

    def close(self):
        self._closing = True
        self.worker.stop()
        self.root.destroy()


def launch(demo=False, capture_path=None):
    root = tk.Tk()
    app = AnalyzerApp(root)
    if demo:
        root.after(150, lambda: app.load_demo(ask=False))
    elif capture_path:
        root.after(150, lambda: app.open_capture(capture_path, ask=False))
    root.mainloop()
