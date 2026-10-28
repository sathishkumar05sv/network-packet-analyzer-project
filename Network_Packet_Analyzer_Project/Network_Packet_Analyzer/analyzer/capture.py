"""Background live capture and offline reading with bounded packet handoff."""
from __future__ import annotations

import queue
import threading
from pathlib import Path

from scapy.all import AsyncSniffer, PcapReader


class CaptureWorker:
    def __init__(self, queue_size=1_000, sniffer_factory=AsyncSniffer):
        self.packets = queue.Queue(maxsize=queue_size)
        self.events = queue.Queue()
        self.stop_event = threading.Event()
        self.thread = None
        self.queue_drops = 0
        self._sniffer_factory = sniffer_factory

    @property
    def busy(self):
        return self.thread is not None and self.thread.is_alive()

    def _start(self, target, *args):
        if self.busy:
            raise RuntimeError("A capture or import is already running.")
        self.stop_event.clear()
        self.queue_drops = 0
        self.packets = queue.Queue(maxsize=self.packets.maxsize)
        self.events = queue.Queue()
        self.thread = threading.Thread(target=target, args=args, daemon=True)
        self.thread.start()

    def start_file(self, path: str | Path):
        self._start(self._read_file, str(path))

    def start_live(self, interface: str, capture_filter: str = ""):
        self._start(self._capture_live, interface, capture_filter.strip())

    def stop(self):
        self.stop_event.set()

    def _offer_live(self, packet):
        if self.stop_event.is_set():
            return
        try:
            self.packets.put_nowait(packet)
        except queue.Full:
            self.queue_drops += 1

    def _read_file(self, path):
        try:
            with Path(path).open("rb") as stream, PcapReader(stream) as reader:
                for packet in reader:
                    if self.stop_event.is_set():
                        break
                    while not self.stop_event.is_set():
                        try:
                            self.packets.put(packet, timeout=0.1)
                            break
                        except queue.Full:
                            continue
        except Exception as error:
            self.events.put(("error", f"Could not read capture: {error}"))
        finally:
            self.events.put(("done", "Import stopped" if self.stop_event.is_set() else "Import complete"))

    def _capture_live(self, interface, capture_filter):
        try:
            sniffer = self._sniffer_factory(iface=interface, filter=capture_filter or None,
                                             store=False, prn=self._offer_live)
            sniffer.start()
            while sniffer.thread.is_alive():
                if self.stop_event.wait(0.05):
                    # stop_cb is installed once the socket is ready. Waiting for
                    # it avoids the AsyncSniffer start/stop initialization race.
                    if sniffer.running and hasattr(sniffer, "stop_cb"):
                        sniffer.stop()
                        break
            sniffer.join()  # Propagates startup/socket/filter errors to the UI.
        except Exception as error:
            self.events.put(("error", f"Live capture could not continue: {error}\n\n"
                             "Windows: install Npcap and check its capture permissions. "
                             "Linux/macOS: check packet-capture permissions. "
                             "For a BPF filter, libpcap/Npcap must be available. "
                             "Demo and saved-file analysis do not need live capture."))
        finally:
            self.events.put(("done", "Capture stopped"))
