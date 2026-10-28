# Viva and demonstration guide

## Opening explanation

**English:** Our project is a Network Packet Analyzer developed using Python and Scapy. It captures packets or opens saved capture files, extracts addresses and protocol fields, and displays them in a Tkinter interface. Users can filter packets, inspect decoded headers and bytes, view statistics, and export the matching packets. Wireshark provides an independent way to check the saved capture.

**Tanglish:** Namma project Python and Scapy use panni network packets-a analyse pannum. Source IP, destination IP, protocol, port number and packet size display aagum. Filter panni specific packets mattum paarkalaam. CSV and PCAP-a save pannalaam. Wireshark-la open panni results compare pannalaam.

## Five minute demonstration

1. Open the app using `launch_windows.bat`. Explain that the demo is synthetic and does not send traffic.
2. Show 37 retained packets and 2,384 captured bytes. Explain the source/destination columns.
3. Select packet 3. Explain the DNS query name `portal.example`, source port 53000 and destination port 53.
4. Choose DNS and Apply. Show 8 matching packets. Open Hex preview.
5. Export the DNS view as PCAP. Open it in Wireshark and verify 8 frames on your own laptop.
6. Open Traffic statistics. Explain why the chart lists DNS separately while the UDP filter includes DNS-over-UDP.
7. If live capture is configured, capture your own short test session and stop it. Otherwise explain the driver requirement without claiming a successful live test.

## Questions and short answers

1. **What is a packet?** A unit of network data containing headers and usually a payload. Headers carry addresses, protocol identifiers and control information.
2. **Why Python?** It keeps the implementation readable and integrates with Scapy and Tkinter.
3. **What is Scapy?** A Python packet-processing library. This project uses its capture, decoding and file functions.
4. **Why Wireshark?** It gives an independent view of the saved packets for field-by-field comparison.
5. **TCP versus UDP?** TCP provides a reliable ordered byte stream. UDP sends datagrams without TCP's delivery and ordering guarantees.
6. **IP address versus port?** An IP address identifies a network endpoint/interface; a port identifies a transport endpoint used by an application.
7. **Why does DNS have a separate label?** The application gives a decoded DNS layer precedence for display. It still records UDP or TCP as the transport.
8. **What is PCAP?** A capture-file format that stores packet bytes and capture metadata. PCAPNG supports richer capture metadata and interfaces.
9. **Capture filter versus display filter?** A capture filter controls acquisition. A display filter selects packets from those already retained.
10. **Can it show HTTPS messages?** It can show captured addresses, ports and other visible fields. Encrypted application content remains unreadable without a separate authorized decryption setup, which this app does not implement.
11. **Why use a worker thread?** Waiting for live packets or reading a file should not block Tkinter's event loop. A bounded queue hands packets to the GUI thread.
12. **How is memory controlled?** The app bounds the handoff queue and stops retaining after 5,000 packets or 32 MiB of captured bytes. Python objects add memory overhead.
13. **Does it capture every device on Wi-Fi?** No. It captures traffic visible to the selected interface under the driver and network configuration.
14. **What is the project's contribution?** A focused educational interface connecting protocol theory to visible packet fields, reusable filters and reproducible exports.
15. **What was actually tested?** 29 automated cases and real desktop-widget checks using synthetic captures. Independent TShark verification also matched ten filter counts and compared metadata for all 37 frames. Live capture and Windows setup still require target-machine verification.
