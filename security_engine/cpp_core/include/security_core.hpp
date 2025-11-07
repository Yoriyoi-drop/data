#pragma once

#include "common.hpp"
#include "packet_filter.hpp"
#include "crypto_engine.hpp"
#include "memory_guard.hpp"
#include "threat_detector.hpp"
#include "performance_monitor.hpp"
#include "api_server.hpp"

namespace infinite_security {

// Performance capabilities structure
struct PerformanceCapabilities {
    f64 max_packet_rate;           // Packets per second
    f64 crypto_throughput_gbps;    // Crypto throughput in Gbps
    f64 memory_bandwidth_gbps;     // Memory bandwidth in GB/s
    bool has_hardware_acceleration;
    bool has_simd_support;
    bool has_aes_ni;
    bool has_avx2;
    std::string cpu_model;
    u32 cpu_cores;
    u64 total_memory_gb;
};

// Main security core class
class SecurityCore {
public:
    explicit SecurityCore(const SecurityConfig& config);
    ~SecurityCore();

    // Lifecycle management
    bool initialize();
    bool start();
    void stop();
    bool is_running() const { return running_.load(); }

    // Component access
    PacketFilter& get_packet_filter() { return *packet_filter_; }
    CryptoEngine& get_crypto_engine() { return *crypto_engine_; }
    MemoryGuard& get_memory_guard() { return *memory_guard_; }
    ThreatDetector& get_threat_detector() { return *threat_detector_; }
    PerformanceMonitor& get_performance_monitor() { return *performance_monitor_; }

    // Performance and statistics
    PerformanceMetrics get_performance_metrics() const;
    PerformanceCapabilities get_performance_capabilities() const;
    
    // Configuration management
    void update_config(const SecurityConfig& new_config);
    const SecurityConfig& get_config() const { return config_; }

    // Event handling
    void register_event_handler(SecurityEvent event, std::function<void(const std::string&)> handler);
    void emit_event(SecurityEvent event, const std::string& details);

    // Integration with other services
    void set_python_api_callback(std::function<void(const std::string&)> callback);
    void set_go_scanner_callback(std::function<void(const PacketInfo&)> callback);
    void set_rust_labyrinth_callback(std::function<void(u32, ThreatLevel)> callback);

private:
    // Configuration
    SecurityConfig config_;
    
    // Core components
    std::unique_ptr<PacketFilter> packet_filter_;
    std::unique_ptr<CryptoEngine> crypto_engine_;
    std::unique_ptr<MemoryGuard> memory_guard_;
    std::unique_ptr<ThreatDetector> threat_detector_;
    std::unique_ptr<PerformanceMonitor> performance_monitor_;
    std::unique_ptr<APIServer> api_server_;
    
    // Thread management
    std::vector<std::thread> worker_threads_;
    tbb::task_scheduler_init tbb_init_;
    
    // State management
    std::atomic<bool> running_{false};
    std::atomic<bool> initialized_{false};
    
    // Event system
    std::unordered_map<SecurityEvent, std::vector<std::function<void(const std::string&)>>> event_handlers_;
    std::mutex event_handlers_mutex_;
    
    // Integration callbacks
    std::function<void(const std::string&)> python_api_callback_;
    std::function<void(const PacketInfo&)> go_scanner_callback_;
    std::function<void(u32, ThreatLevel)> rust_labyrinth_callback_;
    
    // Performance capabilities
    mutable std::once_flag capabilities_flag_;
    mutable PerformanceCapabilities capabilities_;
    
    // Private methods
    bool initialize_components();
    void start_worker_threads();
    void stop_worker_threads();
    void worker_thread_main(size_t thread_id);
    
    // Packet processing pipeline
    void process_packet_pipeline(const PacketInfo& packet, const u8* payload);
    void handle_threat_detection(const PacketInfo& packet, ThreatLevel threat_level);
    void notify_external_services(const PacketInfo& packet, ThreatLevel threat_level);
    
    // Performance optimization
    void optimize_for_hardware();
    void detect_performance_capabilities() const;
    void setup_cpu_affinity();
    void setup_memory_pools();
    
    // Configuration validation
    bool validate_config(const SecurityConfig& config) const;
    void apply_config_changes(const SecurityConfig& old_config, const SecurityConfig& new_config);
};

// Security service manager for integration
class SecurityServiceManager {
public:
    SecurityServiceManager();
    ~SecurityServiceManager();
    
    // Service registration
    void register_python_service(const std::string& endpoint);
    void register_go_service(const std::string& endpoint);
    void register_rust_service(const std::string& endpoint);
    
    // Inter-service communication
    bool send_to_python(const std::string& message);
    bool send_to_go(const PacketInfo& packet);
    bool send_to_rust(u32 source_ip, ThreatLevel threat_level);
    
    // Health monitoring
    bool check_service_health(const std::string& service_name);
    std::unordered_map<std::string, bool> get_all_service_status();
    
private:
    // Service endpoints
    std::string python_endpoint_;
    std::string go_endpoint_;
    std::string rust_endpoint_;
    
    // HTTP client for communication
    std::unique_ptr<boost::beast::http::client> http_client_;
    
    // Health check state
    std::unordered_map<std::string, TimePoint> last_health_check_;
    std::unordered_map<std::string, bool> service_status_;
    std::mutex service_status_mutex_;
    
    // Background health monitoring
    std::thread health_monitor_thread_;
    std::atomic<bool> monitoring_active_{false};
    
    void health_monitor_loop();
    bool ping_service(const std::string& endpoint);
};

// High-performance packet processor
class PacketProcessor {
public:
    explicit PacketProcessor(SecurityCore& core);
    ~PacketProcessor();
    
    // Packet processing
    void process_packet(const PacketInfo& packet, const u8* payload);
    void process_packet_batch(std::span<const PacketInfo> packets, std::span<const u8*> payloads);
    
    // Performance tuning
    void set_batch_size(size_t batch_size) { batch_size_ = batch_size; }
    void enable_parallel_processing(bool enable) { parallel_processing_ = enable; }
    
    // Statistics
    u64 get_packets_processed() const { return packets_processed_.load(); }
    f64 get_processing_rate() const;
    
private:
    SecurityCore& core_;
    
    // Processing configuration
    size_t batch_size_{64};
    bool parallel_processing_{true};
    
    // Performance counters
    std::atomic<u64> packets_processed_{0};
    TimePoint start_time_;
    
    // Batch processing buffers
    std::vector<PacketInfo> packet_batch_;
    std::vector<const u8*> payload_batch_;
    std::vector<ThreatLevel> threat_levels_;
    
    // Processing methods
    void process_single_packet(const PacketInfo& packet, const u8* payload);
    void process_batch_parallel(std::span<const PacketInfo> packets, std::span<const u8*> payloads);
    void process_batch_sequential(std::span<const PacketInfo> packets, std::span<const u8*> payloads);
    
    // Optimization helpers
    void prefetch_packet_data(const PacketInfo& packet, const u8* payload);
    void update_processing_statistics();
};

// Memory-mapped configuration for hot reloading
class HotReloadConfig {
public:
    explicit HotReloadConfig(const std::string& config_file);
    ~HotReloadConfig();
    
    // Configuration monitoring
    bool has_config_changed() const;
    SecurityConfig load_updated_config();
    
    // Callback registration
    void set_config_change_callback(std::function<void(const SecurityConfig&)> callback);
    
private:
    std::string config_file_;
    mutable std::filesystem::file_time_type last_write_time_;
    std::function<void(const SecurityConfig&)> config_change_callback_;
    
    // File monitoring
    std::thread monitor_thread_;
    std::atomic<bool> monitoring_active_{false};
    
    void monitor_config_file();
    SecurityConfig parse_config_file();
};

} // namespace infinite_security