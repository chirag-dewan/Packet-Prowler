# PacketProwler

## Overview
PacketProwler is a custom packet sniffer designed to capture and analyze network traffic in real time. Built using raw sockets in C, it enables users to filter packets by protocol or port, log traffic, and gain insights into their network environment.

---

## Features
- **Real-Time Packet Capture**: Monitor live network traffic at the packet level.
- **Protocol Filtering**: Focus on specific protocols such as TCP, UDP, or ICMP.
- **Customizable Port Filters**: Capture packets for specific ports (e.g., HTTP traffic on port 80).
- **Packet Logging**: Save captured packets to a file for offline analysis.
- **CLI Configuration**: Flexible options for configuring capture parameters.

---

## Installation

### Prerequisites
- GCC Compiler
- Linux Operating System
- Root Privileges (required for raw socket operations)

### Steps
1. Clone the repository:
   ```bash
   git clone https://github.com/chirag0728/Packet-Prowler
   cd PacketProwler
   ```
2. Compile the source code:
   ```bash
   make
   ```
3. Run PacketProwler:
   ```bash
   sudo ./PacketProwler -p 80 -o traffic.log
   ```

---

## Usage

### Command-Line Options
- `-p <port>`: Specify the port to filter packets.
- `-o <file>`: Output file for saving captured packets.

### Examples
- Capture all packets on port 80:
  ```bash
  sudo ./PacketProwler -p 80
  ```
- Save captured packets to a file:
  ```bash
  sudo ./PacketProwler -p 443 -o packets.pcap
  ```

---

## Documentation
Detailed documentation can be found in the [docs](./docs/) directory:
- [Design](./docs/design.md): Architectural overview.
- [Usage Guide](./docs/usage.md): Step-by-step usage instructions.
- [Future Roadmap](./docs/roadmap.md): Planned enhancements and features.

---

## Contributing
Contributions are welcome! 

## Contact
For questions or feedback, please reach out to:
- **Your Name**: [chirag0728@gmail.com](mailto:chirag0728@gmail.com)
- GitHub: [yourusername](https://github.com/chirag0728)
