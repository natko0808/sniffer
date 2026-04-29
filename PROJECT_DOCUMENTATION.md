# Project Documentation: NSSA290 Network Packet Sniffer

## 1. Application Functionality

This application captures, analyzes, filters, and displays network packets through a desktop GUI. It supports two operating modes:

- Live capture from a selected local network interface
- Offline analysis by loading packets from a `.pcap` or `.pcapng` file

Each packet is parsed into a structured summary and shown in a packet table. Selecting a packet opens a detailed view that includes:

- Layer-by-layer protocol breakdown
- Source and destination MAC addresses
- Source and destination IP addresses
- Source and destination ports when present
- IPv4 fragmentation flags and offsets when present
- Full packet bytes rendered in hexadecimal and ASCII format

## 2. GUI Components

The GUI includes the required components from the assignment:

- Packet Capture Controls
  - Refresh interface list
  - Start capture
  - Stop capture
  - Load PCAP
  - Save PCAP
  - Clear packet buffer
- Filter Options
  - Protocol filter
  - Source IP filter
  - Destination IP filter
  - Source port filter
  - Destination port filter
- Packet Table
  - Columns include packet number, capture time, protocol, IPs, ports, MAC addresses, length, and fragmentation information
- Details Panel
  - Parsed, layered packet breakdown
  - Hexadecimal and ASCII payload dump
- Statistics Panel
  - Displayed packet count
  - Total displayed bytes
  - Average and recent traffic rates
  - Packet count by protocol
  - Top talkers

The application keeps the GUI responsive during live capture by handling packet capture on a background sniffer thread and updating the interface through a queue on the main Tkinter thread.

## 3. Protocols Handled

### Ethernet

Displayed fields:

- Source MAC address
- Destination MAC address
- EtherType

### ARP

Displayed fields:

- Operation
- Sender MAC
- Sender IP
- Target MAC
- Target IP

### IPv4

Displayed fields:

- Version
- Header length
- Type of service
- Total length
- Identification
- Flags
- Fragment offset
- TTL
- Protocol number
- Header checksum
- Source and destination IP

### IPv6

Displayed fields:

- Version
- Traffic class
- Flow label
- Payload length
- Next header
- Hop limit
- Source and destination IP

### TCP

Displayed fields:

- Source port
- Destination port
- Sequence number
- Acknowledgement number
- Data offset
- Flags
- Window size
- Checksum
- Urgent pointer

### UDP

Displayed fields:

- Source port
- Destination port
- Length
- Checksum

### ICMP

Displayed fields:

- Type
- Code
- Checksum
- Identifier when present
- Sequence when present

## 4. User Guide

### Start a Live Capture

1. Run `python3 main.py`
2. Select an interface from the drop-down list
3. Click `Start Capture`
4. Generate some network traffic
5. Watch packets appear in the table in real time
6. Click `Stop Capture` when finished

### Analyze a Saved Capture

1. Click `Load PCAP`
2. Choose a `.pcap` or `.pcapng` file
3. Browse packets in the table
4. Click a row to inspect its layers and payload

### Apply Filters

1. Choose a protocol or enter IP / port filters
2. Click `Apply`
3. Only matching packets remain visible in the packet table
4. Click `Reset` to return to the full packet list

## 5. Testing Methods and Results

The application was designed to support the testing plan required in the assignment:

- Live capture testing on a real interface
- Offline testing with saved packet captures
- Filter validation by comparing visible packet counts before and after applying filters
- Responsiveness testing by updating the GUI from a queue instead of directly from the capture thread
- Packet detail verification by checking parsed headers against the selected packet payload

Observed verification completed during development:

- The codebase was syntax-checked successfully with `python3 -m py_compile`.
- Packet parsing, filtering, statistics generation, and PCAP read/write support were validated with synthetic Scapy packets covering Ethernet, ARP, IPv4, TCP, UDP, and ICMP traffic.

Before submission, add short notes from your own live-capture testing session, including:

- The interface used
- Approximate traffic volume
- Whether the GUI stayed responsive for 1-2 minutes
- Any limitations or issues noticed
- Memory / CPU observations if measured

## 6. Screenshots To Add Before Submission

The assignment requires screenshots. Add these after running the application on your machine:

- Live packet capture with multiple packets visible
- A selected packet showing the detailed layered breakdown
- The same packet showing the hex and ASCII payload section
- A filtered view proving that non-matching packets are hidden

## 7. Installation and Run Instructions

Install dependencies:

```bash
python3 -m pip install -r requirements.txt
```

Run the application:

```bash
python3 main.py
```

If you want project-local dependencies instead of a global install:

```bash
python3 -m pip install --target .deps -r requirements.txt
python3 main.py
```

## 8. Submission Checklist

- Replace the placeholder AssessMe metadata in each Python file
- Add the required screenshots
- Add final testing observations from a live capture session
- Include source code, `requirements.txt`, and this documentation file in the submission ZIP
