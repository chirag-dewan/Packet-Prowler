### **PacketProwler - A Lightweight Network Packet Sniffer**  

---

### **Overview**  

**PacketProwler** is a lightweight, customizable network packet sniffer written in **C** using the **libpcap** library. It captures real-time network packets and provides details such as source and destination IP addresses, protocol types, and packet sizes.  

---

### **Features**  
- **Real-Time Packet Sniffing** – Capture live network traffic on specified interfaces.  
- **Protocol Filtering** – Apply filters to capture specific traffic types like TCP or UDP.  
- **Packet Analysis** – Extract and display key details such as source IP, destination IP, protocol, and size.  
- **Output Logging** – Log packet details into an output file for later review.  
- **Extensible Design** – Easily add support for new protocols and additional analysis features.  

---

### **Folder Structure**  

```plaintext
PacketProwler/
├── Makefile           # Build configuration
├── README.md          # Project documentation
├── src/
│   ├── main.c         # Program entry point
│   ├── packet_sniffer.c # Core packet sniffing logic
│   ├── utils.c        # Helper functions for packet processing
│   ├── headers.h      # Shared headers and function declarations
└── output.txt         # Output file for logs (created dynamically)
```

---

### **Getting Started**  

#### **Dependencies**  

- A Unix-like operating system (Linux or macOS).  
- GCC compiler.  
- **libpcap** library (Install it with `sudo apt install libpcap-dev` on Linux).  

#### **Build the Project**  

Clone the repository and navigate to the project directory:  

```bash
git clone https://github.com/chirag0728/PacketProwler.git
cd PacketProwler
make
```

#### **Run the Program**  

Run the program with the required options:  

```bash
sudo ./PacketProwler -o output.txt -n 100
```

- **`-o <file>`** – Specify an output file for packet logs (default: `output.txt`).  
- **`-n <count>`** – Limit the number of packets captured (default: unlimited).  

#### **View Captured Packets**  

Check the output file for logged packet details:  

```bash
cat output.txt
```

---

### **Usage Example**  

```bash
# Capture 50 packets and save the logs to packets.log
sudo ./PacketProwler -o packets.log -n 50
```

**Sample Output**  

```
========== Packet Details ==========
Source IP: 192.168.1.5
Destination IP: 192.168.1.10
Protocol: TCP
Packet Size: 1500 bytes
======================================
```

---

### **Customization**  

#### **Filter Protocols**  

Edit the `filter_exp` variable in `packet_sniffer.c` to modify the packet filter:  

```c
char filter_exp[256] = "udp";
```

#### **Add New Protocols**  

Extend the `utils.c` file to support additional protocols like ICMP or custom headers.  

#### **Optimize Performance**  

Adjust buffer sizes and fine-tune `pcap_open_live` parameters to handle high-speed traffic more efficiently.  

---

### **Technical Details**  

- **Core Technologies** – Written in **C** using the **libpcap** library.  
- **Platform Compatibility** – Works on macOS and Linux.  
- **Key Functions**:  
  - **`pcap_open_live`** – Opens a network device for capturing packets.  
  - **`pcap_compile`** and **`pcap_setfilter`** – Apply filters to capture specific traffic.  
  - **`print_packet_info`** – Logs packet details to the console and a file.  

---

### **Future Enhancements**  

- Add support for IPv6 packets.  
- Implement multi-threaded packet processing.  
- Create a real-time console dashboard for visualizing traffic.  
- Expand logging formats to include JSON and CSV outputs.  

---

### **Contributing**  

Contributions are welcome!  

If you’ve spotted a bug, have a feature suggestion, or want to contribute code, feel free to open an issue or submit a pull request.  

---
