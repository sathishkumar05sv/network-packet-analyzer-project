# Network Packet Analyzer Using Python

Computer Networks mini project for **Sathish Kumar and Team**.

This desktop application captures traffic from a selected interface or opens a saved packet capture. It shows source/destination addresses, transport ports, protocol labels, timestamps, captured lengths, decoded fields and hexadecimal bytes. A deterministic demo makes the project usable before live-capture drivers are installed.

## Start on Windows

1. Extract the ZIP completely into a writable folder.
2. Install **Python 3.10 or later** from <https://www.python.org/downloads/>. Include Tcl/Tk when installing Python.
3. Double-click **`launch_windows.bat`**. First setup creates a virtual environment and installs Scapy; it needs internet access.
4. The application opens with **37 synthetic demo packets**. No packet is sent to the network.

If the launcher reports a setup error, open Terminal in the project folder and run:

```bat
py -3 -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe main.py --demo
```

**Tanglish quick start:** ZIP-a extract pannunga. Python install pannitu `launch_windows.bat` double-click pannunga. Demo load aagum. Oru DNS packet-a select panni source IP, destination IP, ports and decoded fields explain pannalaam.

## Live capture on Windows

Install **Npcap** from <https://npcap.com/#download>. Follow Scapy's platform instructions at <https://scapy.readthedocs.io/en/stable/installation.html#windows>. If capture is restricted to administrators by the Npcap settings, run the terminal as Administrator and launch the same application from it. Demo and saved-file analysis do not require live-capture privileges.

Choose the Wi-Fi or Ethernet interface you are authorized to inspect, optionally enter a BPF filter, and click **Start capture**. Generate your own test traffic and click **Stop**. A switched network normally exposes traffic visible to the selected interface, not every other device's packets.

Wireshark is optional for running the app and is used as an independent analysis tool: <https://www.wireshark.org/download.html>.

## Linux and macOS

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python main.py --demo
```

Tkinter may need a separate OS package, such as `python3-tk` on Debian/Ubuntu. Check `python3 -m tkinter` if the window does not open. Live capture requires the operating system's packet-capture permissions; BPF filtering requires libpcap/Npcap. A terminal-only analysis mode works without Tkinter or a display.

## Features

- Background live capture using Scapy `AsyncSniffer`; Stop works on quiet interfaces after the socket is ready.
- Streaming PCAP/PCAPNG import with cancellation.
- IPv4, IPv6, TCP, UDP, DNS, ICMP, ICMPv6 and ARP metadata.
- Protocol, endpoint IP/CIDR, endpoint port and case-insensitive metadata filters.
- Decoded packet fields and a 256-byte hex preview.
- Protocol distribution, captured-byte totals, timestamp span and top addresses.
- CSV and PCAP export of **the current matching view**. Export uses a temporary file and replaces the destination only after a successful write.
- Per-session retention of 5,000 packets or 32 MiB of captured bytes, whichever limit is reached first.

## Filter rules

| Field | Example | Meaning |
|---|---|---|
| Protocol | `DNS` | Packets with a decoded DNS layer |
| Protocol | `UDP` | All UDP packets, including DNS over UDP |
| IP or CIDR | `192.0.2.10` | Source **or** destination matches |
| IP or CIDR | `2001:db8::/32` | IPv6 source **or** destination is in this network |
| Port | `443` | Source **or** destination port equals 443 |
| Search | `portal.example` | Case-insensitive search of displayed metadata |

Different fields are combined with **AND**. These controls filter retained data after capture. The separate **Capture filter BPF** field filters live acquisition, for example `tcp`, `udp port 53` or `host 192.0.2.10`. Wireshark display-filter expressions such as `tcp.port == 443` are not BPF expressions.

The protocol chart uses exclusive labels: a DNS-over-UDP packet is counted under DNS, while selecting the UDP display filter includes it. Source/destination rankings can contain MAC addresses for non-IP Ethernet packets and protocol addresses from ARP.

## Terminal usage

Run commands from the project directory with the virtual environment's Python:

```bash
python main.py --analyze samples/demo_capture.pcap
python main.py --analyze samples/demo_capture.pcap --protocol DNS --csv exports/dns.csv
python main.py --analyze samples/demo_capture.pcap --ip 2001:db8::/32 --save-pcap exports/ipv6.pcap
python main.py --analyze samples/demo_capture.pcap --protocol TCP --port 443
python main.py --pcap samples/demo_capture.pcap
```

The terminal prints JSON statistics for all retained packets and a separate matching-packet count. Export options apply to matching packets. Invalid input returns a nonzero exit code. `--limit` accepts 1 to 5,000 for terminal analysis.

## Reproducible demo results

The demo contains **37 packets**, **2,384 captured bytes**, and a synthetic timestamp span of **4.500 seconds**. File size differs from captured-byte totals because PCAP also stores file and record headers. Addresses use documentation ranges; the dataset is artificial.

| Exclusive display label | Packets |
|---|---:|
| TCP | 14 |
| DNS | 8 |
| UDP excluding DNS | 4 |
| ICMP | 4 |
| ARP | 2 |
| ICMPv6 | 2 |
| IPv4 with another upper protocol | 1 |
| IPv6 with no next header | 1 |
| Other Ethernet | 1 |

The UDP filter matches **12**, including 8 DNS packets. IPv4 matches **29**, IPv6 matches **5**, and the `DNS + port 53 + portal.example` combination matches **2**.

## Verify with Wireshark

Open `samples/demo_capture.pcap` in Wireshark. With no display filter there should be **37** frames. Use `dns` for **8**, `udp` for **12**, `tcp` for **14**, and `ipv6` for **5**. Frame 3 is a DNS query for `portal.example` from `192.0.2.10:53000` to `203.0.113.53:53`, with **74 captured bytes**. Export the DNS view from this app, reopen it in Wireshark and check for 8 frames.

The project intentionally uses a smaller set of labels than Wireshark. Compare decoded fields and matching frames rather than expecting every protocol-column label to be identical. The bundled reports distinguish completed checks from steps that require your own laptop.

## Tests

No extra test framework is required:

```bash
python -m unittest discover -s tests -t . -v
python -m tests.gui_smoke
```

The second command needs a graphical desktop. Optional screenshots require Pillow (`python -m pip install Pillow`) and can be captured with `python -m tests.gui_smoke --screenshots-dir docs/screenshots`.

On restricted CI hosts only, set `NPA_TEST_OFFLINE=1` before running the tests. The test-only adapter disables Scapy interface and route discovery. It leaves real Scapy decoding, capture-file I/O and GUI widgets intact. It neither grants raw-socket access nor simulates successful live capture. Normal desktop use does not need this variable.

## Project files

```text
main.py                   Desktop / terminal entry point
analyzer/core.py          Decoder, display filters, statistics and exports
analyzer/capture.py       Live and offline background workers
analyzer/gui.py           Desktop controls, packet table and charts
analyzer/demo.py          Deterministic synthetic dataset generator
samples/                  Demo PCAP and example filtered exports
tests/                    Automated checks and optional GUI smoke test
docs/                     Reports, real app screenshots and test evidence
exports/                  Suggested location for your own exported captures
requirements.txt          Tested Scapy version
launch_windows.bat        Windows setup and demo launcher
```

## Practical limits

HTTPS payloads remain encrypted. A port number alone is not proof of an application protocol. This app does not implement TCP stream reassembly, IP fragment reassembly, TLS decryption, complete checksum verification, intrusion detection, or high-rate lossless capture. Scapy and Python object overhead mean process memory exceeds the captured-byte budget. Queue-drop counters describe the app's handoff queue; operating-system/NIC drops are not measured. Mixed-link-type PCAPNG files can be read, but classic PCAP export rejects incompatible link types instead of producing a misleading file. CSV remains available.

The offline decoder, filters, exports and real GUI have been exercised in the supplied test evidence. Live capture and Windows-specific driver/launcher behavior need a final check on the target laptop. Do not claim a throughput benchmark or a completed live-capture test from the synthetic timestamp span.

## Report details to complete

The editable report uses **Sathish Kumar and Team** and the known college/department details. Fill the register numbers, additional team members, guide name, submission date and signatures. The certificate is an unsigned template for college review. See `docs/TEAM_DETAILS.md` and `docs/VIVA_GUIDE.md`.
