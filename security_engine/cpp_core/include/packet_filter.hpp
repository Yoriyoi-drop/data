#pragma once

#include "common.hpp"
#include <immintrin.h> // AVX/SSE intrinsics
#include <regex>
#include <bloom_filter.hpp>

namespace infinite_security {

class PacketFilter {
public:
    explicit PacketFilter(const SecurityConfig& config);
    ~PacketFilter();

    // High-performance packet filtering
    bool should_block_packet(const PacketInfo& packet);
    ThreatLevel analyze_packet_threat(const PacketInfo& packet, const u8* payload);
    
    // Batch processing for SIMD optimization
    void filter_packet_batch(std::span<PacketInfo> packets, std::span<bool> results);
    
    // Rule management
    void add_ip_rule(u32 ip, bool allow);
    void add_port_rule(u16 port, bool allow);
    void add_pattern_rule(const std::string& pattern, ThreatLevel threat_level);
    
    // Statistics
    u64 get_packets_filtered() const { return packets_filtered_.load(); }
    u64 get_threats_detected() const { return threats_detected_.load(); }

private:
    // Configuration
    SecurityConfig config_;
    
    // High-performance data structures
    tbb::concurrent_hash_map<u32, bool> ip_rules_;
    tbb::concurrent_hash_map<u16, bool> port_rules_;
    std::vector<std::pair<std::regex, ThreatLevel>> pattern_rules_;
    
    // Bloom filters for fast lookups
    bloom_filter blocked_ips_bloom_;
    bloom_filter malicious_patterns_bloom_;
    
    // SIMD-optimized lookup tables
    alignas(64) std::array<bool, 65536> port_lookup_table_;
    alignas(64) std::array<ThreatLevel, 256> protocol_threat_levels_;
    
    // Performance counters
    std::atomic<u64> packets_filtered_{0};
    std::atomic<u64> threats_detected_{0};
    
    // Private methods
    bool is_ip_blocked_simd(u32 ip) const;
    bool is_port_blocked_simd(u16 port) const;
    ThreatLevel detect_payload_threats_avx2(const u8* payload, size_t size);
    bool match_malicious_patterns(const u8* payload, size_t size);
    
    // DPI (Deep Packet Inspection) methods
    ThreatLevel analyze_http_payload(const u8* payload, size_t size);
    ThreatLevel analyze_dns_payload(const u8* payload, size_t size);
    ThreatLevel detect_sql_injection(const u8* payload, size_t size);
    ThreatLevel detect_xss_attack(const u8* payload, size_t size);
    ThreatLevel detect_command_injection(const u8* payload, size_t size);
    
    // Statistical analysis
    void update_packet_statistics(const PacketInfo& packet);
    bool is_anomalous_traffic_pattern(const PacketInfo& packet);
    
    // Hardware acceleration helpers
    void initialize_simd_tables();
    void prefetch_lookup_data(u32 ip, u16 port) const;
};

// SIMD-optimized string matching
class SIMDStringMatcher {
public:
    explicit SIMDStringMatcher(const std::vector<std::string>& patterns);
    
    // AVX2-optimized pattern matching
    bool match_any_avx2(const u8* text, size_t length) const;
    std::vector<size_t> find_all_matches_avx2(const u8* text, size_t length) const;
    
private:
    std::vector<std::string> patterns_;
    std::vector<__m256i> simd_patterns_;
    
    void prepare_simd_patterns();
    bool match_pattern_avx2(const u8* text, size_t length, const __m256i& pattern) const;
};

// High-performance IP address operations
class IPAddressUtils {
public:
    // SIMD-optimized IP operations
    static bool is_in_subnet_avx2(u32 ip, u32 subnet, u32 mask);
    static u32 calculate_subnet_hash_avx2(u32 ip, u32 mask);
    
    // Batch IP processing
    static void classify_ips_batch(
        std::span<const u32> ips,
        std::span<bool> results,
        const std::vector<std::pair<u32, u32>>& subnets
    );
    
    // Geographic IP analysis
    static std::string get_country_code(u32 ip);
    static bool is_tor_exit_node(u32 ip);
    static bool is_known_malicious_ip(u32 ip);
};

// Packet capture and processing
class HighPerformanceCapture {
public:
    explicit HighPerformanceCapture(const std::string& interface);
    ~HighPerformanceCapture();
    
    // Start/stop capture
    bool start_capture();
    void stop_capture();
    
    // Set packet handler
    void set_packet_handler(std::function<void(const PacketInfo&, const u8*)> handler);
    
    // Performance tuning
    void set_buffer_size(size_t size);
    void set_timeout(int timeout_ms);
    void enable_immediate_mode(bool enable);
    
private:
    std::string interface_;
    pcap_t* pcap_handle_;
    std::function<void(const PacketInfo&, const u8*)> packet_handler_;
    std::atomic<bool> capturing_;
    std::thread capture_thread_;
    
    // Ring buffer for zero-copy packet processing
    LockFreeRingBuffer<PacketInfo, RING_BUFFER_SIZE> packet_buffer_;
    
    // Packet processing methods
    static void packet_callback(u_char* user, const struct pcap_pkthdr* header, const u_char* packet);
    void process_packet(const struct pcap_pkthdr* header, const u_char* packet);
    PacketInfo parse_packet_headers(const u_char* packet, size_t length);
    
    // Performance optimization
    void optimize_capture_settings();
    void setup_bpf_filter(const std::string& filter);
};

// Memory-mapped file for fast rule loading
class FastRuleLoader {
public:
    explicit FastRuleLoader(const std::string& filename);
    ~FastRuleLoader();
    
    // Load rules efficiently
    std::vector<std::pair<u32, bool>> load_ip_rules();
    std::vector<std::pair<u16, bool>> load_port_rules();
    std::vector<std::pair<std::string, ThreatLevel>> load_pattern_rules();
    
private:
    std::string filename_;
    void* mapped_memory_;
    size_t file_size_;
    
    bool map_file();
    void unmap_file();
};

} // namespace infinite_security