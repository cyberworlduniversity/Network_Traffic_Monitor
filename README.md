# 🌐 Network Traffic Monitor

**Author:** hemanathan115  
**Language:** C++ (C++17)  
**Platform:** Linux / macOS  

---

## 📋 Overview

Network Traffic Monitor is a real-time command-line tool written in C++ that captures and displays live network traffic statistics. It uses raw sockets and system APIs to inspect packets at the IP layer, giving security analysts and developers full visibility into what's moving across their network.

---

## 🚀 Features

| Feature | Description |
|---|---|
| **Real-Time Bandwidth** | Shows current throughput in B/s, KB/s, MB/s, or GB/s |
| **Packet Rate** | Displays packets-per-second (pps) live |
| **Protocol Breakdown** | Visual bar chart for TCP, UDP, ICMP, and Other |
| **Active Connections** | Top 15 connections sorted by data volume |
| **Network Alerts** | Warns on bandwidth spikes or abnormal connection counts |
| **Simulation Mode** | Runs without root by generating realistic fake traffic |

---

## 🛠️ Build Instructions

### Linux
```bash
g++ -std=c++17 -O2 -o network_monitor Network_Traffic_Monitor.cpp -lpthread
```

### macOS
```bash
g++ -std=c++17 -O2 -o network_monitor Network_Traffic_Monitor.cpp -lpthread
```

> **Note:** Xcode Command Line Tools required on macOS (`xcode-select --install`).

---

## ▶️ Run

### With root (real packet capture)
```bash
sudo ./network_monitor
```

### Without root (simulation mode)
```bash
./network_monitor
```
The tool automatically falls back to simulation mode when raw-socket access is unavailable.

---

## 📊 Dashboard Layout

```
╔══════════════════════════════════════════════════════════════╗
║         NETWORK TRAFFIC MONITOR  —  hemanathan115            ║
╚══════════════════════════════════════════════════════════════╝

┌─ BANDWIDTH ──────────────────────────────────────────────────┐
│  Current :     3.21 MB/s   (2450.0 pkt/s)
│  Total   :    45.67 MB     (34821 packets)
└──────────────────────────────────────────────────────────────┘

┌─ PROTOCOL BREAKDOWN ─────────────────────────────────────────┐
│  TCP    [████████████████████████████████        ]   80.0%
│  UDP    [████████                                ]   20.0%
│  ICMP   [                                        ]    0.0%
│  OTHER  [                                        ]    0.0%
└──────────────────────────────────────────────────────────────┘

┌─ ACTIVE CONNECTIONS (42) ────────────────────────────────────┐
│  SRC IP         S.PORT  DST IP          D.PORT  PROTO  BYTES
│  ──────────────────────────────────────────────────────────
│  192.168.1.5    54321   10.0.0.1        443     TCP    1.2 MB
│  ...
└──────────────────────────────────────────────────────────────┘

✔  No anomalies detected.
```

---

## ⚠️ Alert Thresholds

| Alert | Default Threshold |
|---|---|
| Bandwidth spike | > 10 MB/s |
| Connection flood | > 500 active connections |

You can change these in the source file:
```cpp
constexpr uint64_t ALERT_BW_THRESHOLD_BYTES = 10 * 1024 * 1024; // 10 MB/s
constexpr uint32_t ALERT_CONN_THRESHOLD      = 500;
```

---

## 🔧 Technologies Used

- **C++17** — Modern C++ standard
- **POSIX Raw Sockets** — `AF_INET / SOCK_RAW / IPPROTO_IP`
- **Linux Netinet Headers** — `ip.h`, `tcp.h`, `udp.h`, `ip_icmp.h`
- **POSIX Threads** — Capture thread + Display thread run concurrently
- **System APIs** — `ifaddrs`, `arpa/inet`, `net/if`

---

## 📁 File Structure

```
Network_Traffic_Monitor/
├── Network_Traffic_Monitor.cpp   # Full C++ source
└── README.md                     # This file
```

---

## 🔒 Security Use Cases

- Detect **DDoS / SYN flood** attacks via connection count alerts
- Identify **data exfiltration** through unusual bandwidth spikes
- Monitor **protocol anomalies** (e.g., unexpected ICMP traffic)
- Track **top talkers** on the network in real time

---

## 📄 License

MIT License — Free to use, modify, and distribute.

---

*Built with ❤️ by hemanathan115*
