# NSSA290 Network Packet Sniffer

This project implements a packet sniffer in Python using `tkinter` for the GUI and `scapy` for packet capture and packet parsing. It supports both live capture from a selected interface and offline analysis from `.pcap` / `.pcapng` files.

## Features

- Live packet capture from a selected network interface
- Offline packet loading from packet capture files
- Parsed packet table with protocol, IPs, ports, MAC addresses, length, and fragmentation info
- Filter controls for protocol, source IP, destination IP, source port, and destination port
- Detailed per-packet inspection with layered header breakdown
- Hexadecimal and ASCII payload view for the selected packet
- Live statistics for packet totals, protocol counts, and traffic rate
- PCAP export for the current packet buffer

## Requirements

- Python 3.9+ recommended
- `scapy==2.7.0`
- `tkinter` available in the Python installation

## Installation

Install dependencies with one of the following approaches:

```bash
python3 -m pip install -r requirements.txt
```

If you prefer to keep dependencies inside the project directory:

```bash
python3 -m pip install --target .deps -r requirements.txt
```

The application automatically adds `.deps/` to `sys.path` when that folder exists.

## Running the Application

```bash
python3 main.py
```

## How To Use

1. Select a network interface and click `Start Capture` for live sniffing.
2. Click `Stop Capture` to end the live session.
3. Use `Load PCAP` to inspect previously captured traffic offline.
4. Apply filters from the right-hand panel to narrow the displayed packet list.
5. Click a packet row to inspect its parsed headers plus the hex / ASCII payload.
6. Use `Save PCAP` to export the currently loaded packet buffer.

## Notes

- Live capture may require elevated permissions depending on the OS configuration.
- The `Clear` button removes the current packet buffer and resets the view.
- Replace the placeholder AssessMe metadata in the source-file headers before submission.
