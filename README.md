# Wireshark

# Wireshark Network Sniffing Project

##  Introduction

This project is an introduction to network analysis using **Wireshark** and **Tshark**. The goal is to capture, analyze, and interpret network traffic to better understand the OSI model and commonly used network protocols.

---

##  Part 1: Wireshark Basics & OSI Model

###  Step 1: What is Wireshark?

Wireshark is a network protocol analyzer that allows users to capture and interactively browse the traffic running on a computer network. It dissects packets and displays protocol information according to the OSI model.

###  Step 2: Frame vs. Packet

* **Frame**: Data unit at Layer 2 (Data Link)
* **Packet**: Data unit at Layer 3 (Network)

###  Step 3: PCAP / PCAPNG Formats

* **PCAP**: Standard capture format
* **PCAPNG**: Extended format with metadata, interface info, and comments

###  Step 4: Wireshark Installation & Launch

```bash
sudo apt update
sudo apt install wireshark
sudo wireshark
```

###  Step 5: Interface Selection

Selected interface connected to the Alcasar gateway (e.g., `eth0` or `wlan0`).

###  Step 6: Capture Packets

Used capture filters to isolate traffic types:

* ARP: `arp`
* UDP: `udp`
* TCP: `tcp`

###  Step 7: Analyze OSI Layers

Inspected Ethernet (Layer 2), IP (Layer 3), and TCP/UDP (Layer 4) headers.

###  Step 8: MAC & IP Addresses

Captured MAC/IP source and destination addresses for different protocols. Example:

* Source MAC: `00:11:22:33:44:55`
* Destination MAC: `66:77:88:99:AA:BB`
* Source IP: `192.168.1.10`
* Destination IP: `192.168.1.1`

###  Step 9: Other Protocols Observed

Detected DNS, ICMP, HTTP, and mDNS traffic. Interpreted protocol functions using the Wireshark Info column.

###  Step 10: Hexadecimal View

Used bottom pane of Wireshark to view raw bytes and matched fields to protocol specifications (e.g., ARP opcode 0x0001 = request).

###  Step 11: TCP Handshake

Captured TCP three-way handshake:

```
Client → [SYN] → Server
Client ← [SYN-ACK] ← Server
Client → [ACK] → Server
```

###  Step 12: Using Display Filters

Tested filters such as:

* `ip.addr == 192.168.1.10`
* `tcp.flags.syn == 1`
* `http.request`

---

##  Part 2: Protocol Capture on Local Network

###  Setup

Used two VMs in NAT mode:

* **Server** VM: Hosted services
* **Client** VM: Sent requests

###  Services & Protocols

Installed and tested:

* DHCP (via `isc-dhcp-server`)
* DNS (`bind9` or simulated queries)
* mDNS (Bonjour/Avahi)
* SSL/HTTPS (Apache with self-signed cert)
* FTP (`vsftpd`)
* SMB (`samba`)
* TLSv1.2 (OpenSSL-based testing)

###  Captures

Used filters to capture specific traffic:

* `bootp` (DHCP)
* `dns`
* `mdns`
* `ftp`
* `smb`
* `ssl || tls`

Saved captures as `.pcapng` files.

###  Interpretation

Matched captured headers to protocol specs.

###  Observations

* **FTP (no TLS)**: Usernames and passwords visible in plaintext.
* **SSL/TLS**: Encrypted payloads, credentials not visible.

---

##  Part 3: Scripting with Tshark

###  Installation

```bash
sudo apt install tshark
```

###  Basic Command

```bash
sudo tshark -i eth0
```

###  Save Specific Protocol

```bash
sudo tshark -i eth0 -f "port 21" -w ftp_traffic.pcap
```

###  Display Filter Examples

```bash
sudo tshark -i eth0 -Y "dns"
sudo tshark -i eth0 -Y "http" -T fields -e ip.src -e http.request.uri
```

###  Explanation of Options

* `-i`: Interface
* `-Y`: Display filter (like in Wireshark)
* `-f`: Capture filter
* `-w`: Save capture to file
* `-T fields -e`: Extract specific fields

---

##  Skills Demonstrated

* OSI Model analysis
* Network protocol inspection
* Use of Wireshark filters
* CLI capture with Tshark
* Network security awareness (e.g., FTP plaintext vulnerability)

---

##  Resources

* [Wireshark](https://www.wireshark.org)
* [Tshark Filters](https://hackertarget.com/tshark-tutorial-and-%EF%AC%81lter-examples/)
* [Hex Packet Decoder](https://hpd.gasmi.net/)
* [Base64 Decoder](https://www.base64decode.org/)
* [MD5 Decoder](https://www.dcode.fr/md5-hash)
* [Binary to ASCII](https://www.binaryhexconverter.com/binary-to-ascii-text-converter)

---

