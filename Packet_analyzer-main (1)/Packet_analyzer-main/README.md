# DPI Engine - Deep Packet Inspection System (Python)

This is the **Python rebuild** of the original C++ DPI Engine project. The concept, architecture, and all functionality are identical — only the implementation language has changed from C++ to Python.

---

## Table of Contents

1. [What is DPI?](#1-what-is-dpi)
2. [Networking Background](#2-networking-background)
3. [Project Overview](#3-project-overview)
4. [File Structure](#4-file-structure)
5. [The Journey of a Packet (Simple Version)](#5-the-journey-of-a-packet-simple-version)
6. [The Journey of a Packet (Multi-threaded Version)](#6-the-journey-of-a-packet-multi-threaded-version)
7. [Deep Dive: Each Component](#7-deep-dive-each-component)
8. [How SNI Extraction Works](#8-how-sni-extraction-works)
9. [How Blocking Works](#9-how-blocking-works)
10. [Running the Project](#10-running-the-project)
11. [Understanding the Output](#11-understanding-the-output)

---

## 1. What is DPI?

**Deep Packet Inspection (DPI)** is a technology used to examine the contents of network packets as they pass through a checkpoint. Unlike simple firewalls that only look at packet headers (source/destination IP), DPI looks *inside* the packet payload.

### Real-World Uses:
- **ISPs**: Throttle or block certain applications (e.g., BitTorrent)
- **Enterprises**: Block social media on office networks
- **Parental Controls**: Block inappropriate websites
- **Security**: Detect malware or intrusion attempts

### What Our DPI Engine Does:
```
User Traffic (PCAP) → [DPI Engine] → Filtered Traffic (PCAP)
                           ↓
                    - Identifies apps (YouTube, Facebook, etc.)
                    - Blocks based on rules
                    - Generates reports
```

---

## 2. Networking Background

### The Network Stack (Layers)

```
┌─────────────────────────────────────────────────────────┐
│ Layer 7: Application    │ HTTP, TLS, DNS               │
├─────────────────────────────────────────────────────────┤
│ Layer 4: Transport      │ TCP (reliable), UDP (fast)   │
├─────────────────────────────────────────────────────────┤
│ Layer 3: Network        │ IP addresses (routing)       │
├─────────────────────────────────────────────────────────┤
│ Layer 2: Data Link      │ MAC addresses (local network)│
└─────────────────────────────────────────────────────────┘
```

### A Packet's Structure

```
┌──────────────────────────────────────────────────────────────────┐
│ Ethernet Header (14 bytes)                                       │
│ ┌──────────────────────────────────────────────────────────────┐ │
│ │ IP Header (20 bytes)                                         │ │
│ │ ┌──────────────────────────────────────────────────────────┐ │ │
│ │ │ TCP Header (20 bytes)                                    │ │ │
│ │ │ ┌──────────────────────────────────────────────────────┐ │ │ │
│ │ │ │ Payload (Application Data)                           │ │ │ │
│ │ │ │ e.g., TLS Client Hello with SNI                      │ │ │ │
│ │ │ └──────────────────────────────────────────────────────┘ │ │ │
│ │ └──────────────────────────────────────────────────────────┘ │ │
│ └──────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

### The Five-Tuple

A **connection** (or "flow") is uniquely identified by 5 values:

| Field | Example | Purpose |
|-------|---------|---------|
| Source IP | 192.168.1.100 | Who is sending |
| Destination IP | 172.217.14.206 | Where it's going |
| Source Port | 54321 | Sender's application identifier |
| Destination Port | 443 | Service being accessed (443 = HTTPS) |
| Protocol | TCP (6) | TCP or UDP |

### What is SNI?

**Server Name Indication (SNI)** is part of the TLS/HTTPS handshake. When you visit `https://www.youtube.com`, the domain name is sent **in plaintext** before encryption begins. We extract this to identify the application.

---

## 3. Project Overview

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│ Wireshark   │     │ DPI Engine  │     │ Output      │
│ Capture     │ ──► │             │ ──► │ PCAP        │
│ (input.pcap)│     │ - Parse     │     │ (filtered)  │
└─────────────┘     │ - Classify  │     └─────────────┘
                    │ - Block     │
                    │ - Report    │
                    └─────────────┘
```

### Two Versions

| Version | File | Use Case |
|---------|------|----------|
| Simple (Single-threaded) | `src/main_working.py` | Learning, small captures |
| Multi-threaded | `src/dpi_mt.py` | Production, large captures |

---

## 4. File Structure

```
Packet_analyzer-main/
├── include/                    # Module files (Python "headers")
│   ├── pcap_reader.py         # PCAP file reading
│   ├── packet_parser.py       # Network protocol parsing
│   ├── sni_extractor.py       # TLS/HTTP inspection
│   ├── types.py               # Data structures (FiveTuple, AppType, etc.)
│   ├── rule_manager.py        # Blocking rules (multi-threaded version)
│   ├── connection_tracker.py  # Flow tracking (multi-threaded version)
│   ├── load_balancer.py       # LB thread (multi-threaded version)
│   ├── fast_path.py           # FP thread (multi-threaded version)
│   ├── thread_safe_queue.py   # Thread-safe queue
│   └── dpi_engine.py          # Main orchestrator
│
├── src/                        # Entry-point scripts
│   ├── main.py                # Simple packet viewer
│   ├── main_simple.py         # Simple single-threaded test version
│   ├── main_working.py        # ★ SIMPLE DPI VERSION ★
│   ├── main_dpi.py            # Full DPI Engine entry point
│   └── dpi_mt.py              # ★ MULTI-THREADED VERSION ★
│
├── generate_test_pcap.py      # Creates test data
├── test_dpi.pcap              # Sample capture with various traffic
└── README.md                  # This file!
```

---

## 5. The Journey of a Packet (Simple Version)

### Step 1: Read PCAP File

```python
reader = PcapReader()
reader.open("capture.pcap")
```

**PCAP File Format:**
```
┌────────────────────────────┐
│ Global Header (24 bytes)   │  ← Read once at start
├────────────────────────────┤
│ Packet Header (16 bytes)   │  ← Timestamp, length
│ Packet Data (variable)     │  ← Actual network bytes
├────────────────────────────┤
│ ... more packets ...       │
└────────────────────────────┘
```

### Step 2: Parse Protocol Headers

```python
PacketParser.parse(raw, parsed)
# parsed.src_ip   = "192.168.1.100"
# parsed.dest_ip  = "172.217.14.206"
# parsed.src_port = 54321
# parsed.dest_port = 443
```

### Step 3: Extract SNI (Deep Packet Inspection)

```python
if parsed.dest_port == 443:
    sni = SNIExtractor.extract(payload, payload_len)
    if sni:
        flow.sni      = sni               # "www.youtube.com"
        flow.app_type = sni_to_app_type(sni)  # AppType.YOUTUBE
```

### Step 4: Check Blocking Rules and Forward/Drop

```python
if rules.is_blocked(src_ip, flow.app_type, flow.sni):
    dropped += 1
else:
    forwarded += 1
    out_file.write(packet_data)
```

---

## 6. The Journey of a Packet (Multi-threaded Version)

```
                    ┌─────────────────┐
                    │  Reader Thread  │
                    └────────┬────────┘
                             │ hash(5-tuple) % num_lbs
              ┌──────────────┴──────────────┐
              ▼                             ▼
    ┌─────────────────┐           ┌─────────────────┐
    │  LB0 Thread     │           │  LB1 Thread     │
    └────────┬────────┘           └────────┬────────┘
             │ hash % fps_per_lb           │
      ┌──────┴──────┐               ┌──────┴──────┐
      ▼             ▼               ▼             ▼
┌──────────┐ ┌──────────┐   ┌──────────┐ ┌──────────┐
│FP0 Thread│ │FP1 Thread│   │FP2 Thread│ │FP3 Thread│
└─────┬────┘ └─────┬────┘   └─────┬────┘ └─────┬────┘
      └────────────┴──────────────┴────────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │   Output Queue        │
              └───────────┬───────────┘
                          ▼
              ┌───────────────────────┐
              │  Output Writer Thread │
              └───────────────────────┘
```

**Why consistent hashing matters:** Same 5-tuple always goes to same FP, so connection state is tracked correctly.

---

## 7. Deep Dive: Each Component

### pcap_reader.py
- `PcapReader.open(filename)` - Open PCAP, validate magic number
- `PcapReader.read_next_packet()` - Return next `RawPacket` or `None`
- Handles both native and byte-swapped PCAP files

### packet_parser.py
- `PacketParser.parse(raw, parsed)` - Extract all protocol fields
- Parses Ethernet → IPv4 → TCP/UDP headers
- Handles network byte order (big-endian) conversion

### sni_extractor.py
- `SNIExtractor.extract(payload, length)` - Extract hostname from TLS Client Hello
- `HTTPHostExtractor.extract(payload, length)` - Extract Host from HTTP
- `DNSExtractor.extract_query(payload, length)` - Extract DNS query name

### types.py
- `FiveTuple` - Frozen dataclass used as dict key; consistent hashing
- `AppType` - Enum of recognized applications
- `sni_to_app_type(sni)` - Map domain to AppType
- `Connection`, `PacketJob`, `DPIStats` - Core data structures

### rule_manager.py
- Thread-safe blocking rules: IP, App, Domain (wildcard), Port
- `should_block(src_ip, dst_port, app, domain)` → `BlockReason | None`
- `save_rules()` / `load_rules()` for persistence

### thread_safe_queue.py
- Bounded `ThreadSafeQueue[T]` backed by `queue.Queue`
- `push()` / `pop()` / `pop_with_timeout()` / `shutdown()`

### connection_tracker.py
- `ConnectionTracker` - Per-FP flow table (no locking needed - single owner)
- `GlobalConnectionTable` - Read-only aggregation across all FPs

### fast_path.py
- `FastPathProcessor` - Worker thread: DPI + classification + blocking
- `FPManager` - Creates and manages multiple FP threads
- `generate_classification_report()` - App distribution report

### load_balancer.py
- `LoadBalancer` - Distributes packets to FP queues by hash
- `LBManager` - Creates and manages multiple LB threads

### dpi_engine.py
- `DPIEngine` - Main orchestrator tying everything together
- `process_file(input, output)` - Complete pipeline
- Rule management API: `block_ip()`, `block_app()`, `block_domain()`, etc.

---

## 8. How SNI Extraction Works

```
TLS Client Hello (from TCP payload):

Byte 0:     Content Type = 0x16 (Handshake)
Bytes 1-2:  Version = 0x0301
Bytes 3-4:  Record Length
Byte 5:     Handshake Type = 0x01 (Client Hello)
Bytes 6-8:  Handshake Length
...skip version, random, session ID, cipher suites, compression...
Extensions:
  Type: 0x0000 (SNI Extension)
  Length: N
    SNI List Length: M
    SNI Type: 0x00 (hostname)
    SNI Length: L
    SNI Value: "www.youtube.com"  ← EXTRACTED!
```

**Key insight:** Even though HTTPS is encrypted, the domain name is visible in the FIRST packet of the handshake!

---

## 9. How Blocking Works

```
Packet arrives
      │
      ▼
┌─────────────────────────────────┐
│ Is source IP in blocked list?  │──Yes──► DROP
└───────────────┬─────────────────┘
                │No
                ▼
┌─────────────────────────────────┐
│ Is app type in blocked list?   │──Yes──► DROP
└───────────────┬─────────────────┘
                │No
                ▼
┌─────────────────────────────────┐
│ Does SNI match blocked domain? │──Yes──► DROP
└───────────────┬─────────────────┘
                │No
                ▼
            FORWARD
```

Blocking is **flow-based**: once a flow is identified and blocked, all subsequent packets in that flow are dropped immediately.

---

## 10. Running the Project

### Prerequisites

- Python 3.8+
- No external libraries needed! (uses only stdlib)

### View Individual Packets

```bash
python3 src/main.py test_dpi.pcap
python3 src/main.py test_dpi.pcap 10    # limit to 10 packets
```

### Simple Single-threaded DPI

```bash
python3 src/main_working.py test_dpi.pcap output.pcap

# With blocking:
python3 src/main_working.py test_dpi.pcap output.pcap \
    --block-app YouTube \
    --block-ip 192.168.1.50 \
    --block-domain facebook
```

### Multi-threaded DPI Engine

```bash
python3 src/dpi_mt.py test_dpi.pcap output.pcap

# With blocking and custom thread counts:
python3 src/dpi_mt.py test_dpi.pcap output.pcap \
    --block-app YouTube \
    --block-app TikTok \
    --block-ip 192.168.1.50 \
    --lbs 4 \
    --fps 4
```

### Full DPI Engine (with rules file support)

```bash
python3 src/main_dpi.py test_dpi.pcap output.pcap \
    --block-app YouTube \
    --block-domain *.tiktok.com \
    --rules my_rules.txt
```

### Create Test Data

```bash
python3 generate_test_pcap.py
# Creates test_dpi.pcap with sample traffic
```

---

## 11. Understanding the Output

```
╔══════════════════════════════════════════════════════════════╗
║              DPI ENGINE v2.0 (Multi-threaded)                 ║
╠══════════════════════════════════════════════════════════════╣
║ Load Balancers:  2    FPs per LB:  2    Total FPs:  4        ║
╚══════════════════════════════════════════════════════════════╝

[Rules] Blocked app: YouTube
[Rules] Blocked IP: 192.168.1.50

[Reader] Processing packets...
[Reader] Done reading 77 packets

╔══════════════════════════════════════════════════════════════╗
║                      PROCESSING REPORT                        ║
╠══════════════════════════════════════════════════════════════╣
║ Total Packets:                77                              ║
║ Forwarded:                    69                              ║
║ Dropped:                       8                              ║
╠══════════════════════════════════════════════════════════════╣
║                   APPLICATION BREAKDOWN                       ║
╠══════════════════════════════════════════════════════════════╣
║ HTTPS              39  50.6% ##########                       ║
║ YouTube             4   5.2% # (BLOCKED)                      ║
╚══════════════════════════════════════════════════════════════╝

[Detected Domains/SNIs]
  - www.youtube.com -> YouTube
  - www.facebook.com -> Facebook
```

---

## C++ → Python Mapping

| C++ File | Python Equivalent |
|----------|-------------------|
| `include/types.h` + `src/types.cpp` | `include/dpi_types.py` |
| `include/pcap_reader.h` + `src/pcap_reader.cpp` | `include/pcap_reader.py` |
| `include/packet_parser.h` + `src/packet_parser.cpp` | `include/packet_parser.py` |
| `include/sni_extractor.h` + `src/sni_extractor.cpp` | `include/sni_extractor.py` |
| `include/rule_manager.h` + `src/rule_manager.cpp` | `include/rule_manager.py` |
| `include/thread_safe_queue.h` | `include/thread_safe_queue.py` |
| `include/connection_tracker.h` + `src/connection_tracker.cpp` | `include/connection_tracker.py` |
| `include/fast_path.h` + `src/fast_path.cpp` | `include/fast_path.py` |
| `include/load_balancer.h` + `src/load_balancer.cpp` | `include/load_balancer.py` |
| `include/dpi_engine.h` + `src/dpi_engine.cpp` | `include/dpi_engine.py` |
| `src/main.cpp` | `src/main.py` |
| `src/main_simple.cpp` | `src/main_simple.py` |
| `src/main_working.cpp` | `src/main_working.py` |
| `src/main_dpi.cpp` | `src/main_dpi.py` |
| `src/dpi_mt.cpp` | `src/dpi_mt.py` |

Happy learning! 🚀
#   d e e p - p a c k e t - i n s p e c t i o n - s y s t e m  
 