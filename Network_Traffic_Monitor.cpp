/*
 * ============================================================
 *  Network Traffic Monitor
 *  Author  : hemanathan115
 *  Purpose : Real-time network traffic monitoring tool
 *            Displays bandwidth, active connections, protocol
 *            statistics and raises alerts on anomalies.
 * ============================================================
 *
 *  Build (Linux):
 *    g++ -std=c++17 -O2 -o network_monitor Network_Traffic_Monitor.cpp -lpthread
 *
 *  Build (macOS):
 *    g++ -std=c++17 -O2 -o network_monitor Network_Traffic_Monitor.cpp -lpthread
 *
 *  Run (requires root for raw-socket capture):
 *    sudo ./network_monitor
 *
 * ============================================================
 */

#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <map>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <cstring>
#include <cstdlib>
#include <csignal>
#include <algorithm>

// ── POSIX / Socket headers ────────────────────────────────────
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <ifaddrs.h>

// ─────────────────────────────────────────────────────────────
//  Constants & Thresholds
// ─────────────────────────────────────────────────────────────
constexpr uint64_t ALERT_BW_THRESHOLD_BYTES = 10 * 1024 * 1024; // 10 MB/s
constexpr uint32_t ALERT_CONN_THRESHOLD      = 500;              // connections
constexpr int      REFRESH_INTERVAL_SEC      = 1;

// ─────────────────────────────────────────────────────────────
//  Data Structures
// ─────────────────────────────────────────────────────────────
struct ConnectionKey {
    std::string src_ip;
    std::string dst_ip;
    uint16_t    src_port;
    uint16_t    dst_port;
    std::string protocol;

    bool operator<(const ConnectionKey& o) const {
        return std::tie(src_ip, dst_ip, src_port, dst_port, protocol)
             < std::tie(o.src_ip, o.dst_ip, o.src_port, o.dst_port, o.protocol);
    }
};

struct ConnectionInfo {
    uint64_t bytes      = 0;
    uint64_t packets    = 0;
    std::chrono::steady_clock::time_point last_seen;
};

struct Stats {
    uint64_t total_bytes    = 0;
    uint64_t total_packets  = 0;
    uint64_t tcp_packets    = 0;
    uint64_t udp_packets    = 0;
    uint64_t icmp_packets   = 0;
    uint64_t other_packets  = 0;
    std::map<ConnectionKey, ConnectionInfo> connections;
};

// ─────────────────────────────────────────────────────────────
//  Globals
// ─────────────────────────────────────────────────────────────
static std::mutex       g_mutex;
static Stats            g_stats;
static std::atomic<bool> g_running{true};

// ─────────────────────────────────────────────────────────────
//  Signal handler
// ─────────────────────────────────────────────────────────────
void handle_signal(int) {
    g_running = false;
}

// ─────────────────────────────────────────────────────────────
//  Helpers
// ─────────────────────────────────────────────────────────────
std::string format_bytes(uint64_t bytes) {
    std::ostringstream oss;
    if (bytes >= 1024ULL * 1024 * 1024)
        oss << std::fixed << std::setprecision(2) << bytes / (1024.0 * 1024 * 1024) << " GB";
    else if (bytes >= 1024ULL * 1024)
        oss << std::fixed << std::setprecision(2) << bytes / (1024.0 * 1024) << " MB";
    else if (bytes >= 1024ULL)
        oss << std::fixed << std::setprecision(2) << bytes / 1024.0 << " KB";
    else
        oss << bytes << " B";
    return oss.str();
}

void clear_screen() {
    std::cout << "\033[2J\033[H";
}

// ─────────────────────────────────────────────────────────────
//  Packet capture thread
// ─────────────────────────────────────────────────────────────
void capture_thread() {
    // Create raw socket to capture all IP packets
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    if (sock < 0) {
        // Fallback: no root privileges
        std::cerr << "[WARN] Raw socket requires root. Running in simulation mode.\n";

        // ── Simulation mode ──────────────────────────────────
        std::srand(static_cast<unsigned>(std::time(nullptr)));
        while (g_running) {
            // Simulate random traffic
            uint64_t pkt_size = 64 + std::rand() % 1436;
            int proto_roll    = std::rand() % 10;

            std::lock_guard<std::mutex> lk(g_mutex);
            g_stats.total_bytes   += pkt_size;
            g_stats.total_packets += 1;

            ConnectionKey key;
            key.src_ip   = "192.168." + std::to_string(std::rand() % 5 + 1)
                         + "." + std::to_string(std::rand() % 254 + 1);
            key.dst_ip   = "10.0.0." + std::to_string(std::rand() % 10 + 1);
            key.src_port = static_cast<uint16_t>(1024 + std::rand() % 60000);

            if (proto_roll < 6) {
                key.protocol = "TCP";
                key.dst_port = (std::rand() % 3 == 0) ? 443 :
                               (std::rand() % 2 == 0) ? 80 : 22;
                g_stats.tcp_packets++;
            } else if (proto_roll < 9) {
                key.protocol = "UDP";
                key.dst_port = (std::rand() % 2 == 0) ? 53 : 123;
                g_stats.udp_packets++;
            } else {
                key.protocol = "ICMP";
                key.dst_port = 0;
                g_stats.icmp_packets++;
            }

            auto& conn       = g_stats.connections[key];
            conn.bytes      += pkt_size;
            conn.packets    += 1;
            conn.last_seen   = std::chrono::steady_clock::now();

            std::this_thread::sleep_for(std::chrono::microseconds(200));
        }
        return;
    }

    // ── Real capture mode ────────────────────────────────────
    char buffer[65536];
    while (g_running) {
        ssize_t len = recv(sock, buffer, sizeof(buffer), 0);
        if (len <= 0) continue;

        struct iphdr* iph = reinterpret_cast<struct iphdr*>(buffer);
        if (static_cast<size_t>(len) < sizeof(struct iphdr)) continue;

        char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
        struct in_addr src_addr, dst_addr;
        src_addr.s_addr = iph->saddr;
        dst_addr.s_addr = iph->daddr;
        inet_ntop(AF_INET, &src_addr, src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &dst_addr, dst_ip, INET_ADDRSTRLEN);

        ConnectionKey key;
        key.src_ip = src_ip;
        key.dst_ip = dst_ip;

        uint64_t pkt_len = static_cast<uint64_t>(ntohs(iph->tot_len));
        int ip_hdr_len   = iph->ihl * 4;

        std::lock_guard<std::mutex> lk(g_mutex);
        g_stats.total_bytes   += pkt_len;
        g_stats.total_packets += 1;

        switch (iph->protocol) {
            case IPPROTO_TCP: {
                g_stats.tcp_packets++;
                key.protocol = "TCP";
                if (static_cast<ssize_t>(ip_hdr_len + (int)sizeof(struct tcphdr)) <= len) {
                    struct tcphdr* tcph = reinterpret_cast<struct tcphdr*>(buffer + ip_hdr_len);
                    key.src_port = ntohs(tcph->th_sport);
                    key.dst_port = ntohs(tcph->th_dport);
                }
                break;
            }
            case IPPROTO_UDP: {
                g_stats.udp_packets++;
                key.protocol = "UDP";
                if (static_cast<ssize_t>(ip_hdr_len + (int)sizeof(struct udphdr)) <= len) {
                    struct udphdr* udph = reinterpret_cast<struct udphdr*>(buffer + ip_hdr_len);
                    key.src_port = ntohs(udph->uh_sport);
                    key.dst_port = ntohs(udph->uh_dport);
                }
                break;
            }
            case IPPROTO_ICMP:
                g_stats.icmp_packets++;
                key.protocol = "ICMP";
                key.src_port = key.dst_port = 0;
                break;
            default:
                g_stats.other_packets++;
                key.protocol = "OTHER";
                key.src_port = key.dst_port = 0;
        }

        auto& conn     = g_stats.connections[key];
        conn.bytes    += pkt_len;
        conn.packets  += 1;
        conn.last_seen = std::chrono::steady_clock::now();
    }
    close(sock);
}

// ─────────────────────────────────────────────────────────────
//  Display thread
// ─────────────────────────────────────────────────────────────
void display_thread() {
    Stats prev_stats{};
    auto  prev_time = std::chrono::steady_clock::now();

    while (g_running) {
        std::this_thread::sleep_for(std::chrono::seconds(REFRESH_INTERVAL_SEC));

        Stats  cur;
        auto   cur_time = std::chrono::steady_clock::now();
        {
            std::lock_guard<std::mutex> lk(g_mutex);
            cur = g_stats;
        }

        double elapsed = std::chrono::duration<double>(cur_time - prev_time).count();
        uint64_t delta_bytes   = cur.total_bytes   - prev_stats.total_bytes;
        uint64_t delta_packets = cur.total_packets - prev_stats.total_packets;
        double   bw_bps        = (elapsed > 0) ? delta_bytes / elapsed : 0;
        double   pps           = (elapsed > 0) ? delta_packets / elapsed : 0;

        // ── Remove stale connections (not seen for 30 s) ─────
        auto now = std::chrono::steady_clock::now();
        {
            std::lock_guard<std::mutex> lk(g_mutex);
            for (auto it = g_stats.connections.begin(); it != g_stats.connections.end(); ) {
                auto age = std::chrono::duration_cast<std::chrono::seconds>(
                               now - it->second.last_seen).count();
                it = (age > 30) ? g_stats.connections.erase(it) : std::next(it);
            }
        }

        // ── Build sorted top-connections list ─────────────────
        std::vector<std::pair<ConnectionKey, ConnectionInfo>> top_conns(
            cur.connections.begin(), cur.connections.end());
        std::sort(top_conns.begin(), top_conns.end(),
            [](const auto& a, const auto& b){ return a.second.bytes > b.second.bytes; });

        // ── Render ────────────────────────────────────────────
        clear_screen();

        std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
        std::cout << "║         NETWORK TRAFFIC MONITOR  —  hemanathan115            ║\n";
        std::cout << "╚══════════════════════════════════════════════════════════════╝\n\n";

        // Bandwidth
        std::cout << "┌─ BANDWIDTH ─────────────────────────────────────────────────┐\n";
        std::cout << "│  Current : " << std::setw(12) << format_bytes(static_cast<uint64_t>(bw_bps))
                  << "/s   (" << std::fixed << std::setprecision(1) << pps << " pkt/s)\n";
        std::cout << "│  Total   : " << std::setw(12) << format_bytes(cur.total_bytes)
                  << "   (" << cur.total_packets << " packets)\n";
        std::cout << "└─────────────────────────────────────────────────────────────┘\n\n";

        // Protocol stats
        uint64_t total_pkt = cur.total_packets > 0 ? cur.total_packets : 1;
        std::cout << "┌─ PROTOCOL BREAKDOWN ────────────────────────────────────────┐\n";
        auto proto_bar = [&](const char* name, uint64_t count) {
            double pct = 100.0 * count / total_pkt;
            int    bar = static_cast<int>(pct / 2.5);
            std::cout << "│  " << std::left << std::setw(6) << name
                      << " [" << std::string(bar, '█') << std::string(40 - bar, ' ')
                      << "] " << std::right << std::setw(6) << std::fixed
                      << std::setprecision(1) << pct << "%  (" << count << ")\n";
        };
        proto_bar("TCP",   cur.tcp_packets);
        proto_bar("UDP",   cur.udp_packets);
        proto_bar("ICMP",  cur.icmp_packets);
        proto_bar("OTHER", cur.other_packets);
        std::cout << "└─────────────────────────────────────────────────────────────┘\n\n";

        // Active connections
        size_t conn_count = cur.connections.size();
        std::cout << "┌─ ACTIVE CONNECTIONS (" << conn_count << ") "
                  << "────────────────────────────────────┐\n";
        std::cout << "│  " << std::left
                  << std::setw(16) << "SRC IP"
                  << std::setw(7)  << "S.PORT"
                  << std::setw(16) << "DST IP"
                  << std::setw(7)  << "D.PORT"
                  << std::setw(6)  << "PROTO"
                  << std::setw(10) << "BYTES"
                  << "\n│  " << std::string(62, '-') << "\n";

        size_t display_max = std::min(top_conns.size(), size_t(15));
        for (size_t i = 0; i < display_max; ++i) {
            const auto& [k, v] = top_conns[i];
            std::cout << "│  " << std::left
                      << std::setw(16) << k.src_ip
                      << std::setw(7)  << k.src_port
                      << std::setw(16) << k.dst_ip
                      << std::setw(7)  << k.dst_port
                      << std::setw(6)  << k.protocol
                      << std::setw(10) << format_bytes(v.bytes)
                      << "\n";
        }
        if (top_conns.size() > display_max)
            std::cout << "│  ... and " << (top_conns.size() - display_max) << " more\n";
        std::cout << "└─────────────────────────────────────────────────────────────┘\n\n";

        // ── Alerts ───────────────────────────────────────────
        bool alert = false;
        if (static_cast<uint64_t>(bw_bps) > ALERT_BW_THRESHOLD_BYTES) {
            std::cout << "⚠  ALERT: Bandwidth spike detected! ("
                      << format_bytes(static_cast<uint64_t>(bw_bps)) << "/s)\n";
            alert = true;
        }
        if (conn_count > ALERT_CONN_THRESHOLD) {
            std::cout << "⚠  ALERT: Unusually high connection count! (" << conn_count << ")\n";
            alert = true;
        }
        if (!alert)
            std::cout << "✔  No anomalies detected.\n";

        std::cout << "\n[Press Ctrl+C to exit]\n";

        prev_stats = cur;
        prev_time  = cur_time;
    }
}

// ─────────────────────────────────────────────────────────────
//  Main
// ─────────────────────────────────────────────────────────────
int main() {
    std::signal(SIGINT,  handle_signal);
    std::signal(SIGTERM, handle_signal);

    std::cout << "Starting Network Traffic Monitor...\n";
    std::cout << "Press Ctrl+C to stop.\n\n";
    std::this_thread::sleep_for(std::chrono::seconds(1));

    std::thread cap_t(capture_thread);
    std::thread disp_t(display_thread);

    cap_t.join();
    disp_t.join();

    std::cout << "\nMonitor stopped. Goodbye!\n";
    return 0;
}
