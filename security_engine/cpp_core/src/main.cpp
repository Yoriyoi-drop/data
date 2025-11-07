#include "security_core.hpp"
#include "logger.hpp"
#include "config_manager.hpp"
#include <csignal>
#include <iostream>

using namespace infinite_security;

// Global security core instance
std::unique_ptr<SecurityCore> g_security_core;

// Signal handler for graceful shutdown
void signal_handler(int signal) {
    Logger::info("Received signal {}, shutting down gracefully...", signal);
    
    if (g_security_core) {
        g_security_core->stop();
    }
    
    std::exit(0);
}

int main(int argc, char* argv[]) {
    try {
        // Initialize logger
        Logger::initialize(LogLevel::INFO);
        Logger::info("🔥 Infinite Security C++ Core Engine Starting...");
        
        // Load configuration
        ConfigManager config_manager;
        SecurityConfig config;
        
        if (argc > 1) {
            config = config_manager.load_from_file(argv[1]);
        } else {
            config = config_manager.load_default_config();
        }
        
        Logger::info("Configuration loaded successfully");
        Logger::info("Interface: {}", config.interface_name);
        Logger::info("Max packet rate: {}/sec", config.max_packet_rate);
        Logger::info("Thread count: {}", config.thread_count);
        Logger::info("API port: {}", config.api_port);
        
        // Set up signal handlers
        std::signal(SIGINT, signal_handler);
        std::signal(SIGTERM, signal_handler);
        
        // Create and initialize security core
        g_security_core = std::make_unique<SecurityCore>(config);
        
        if (!g_security_core->initialize()) {
            Logger::error("Failed to initialize security core");
            return 1;
        }
        
        Logger::info("✅ Security core initialized successfully");
        
        // Start all services
        if (!g_security_core->start()) {
            Logger::error("Failed to start security services");
            return 1;
        }
        
        Logger::info("🚀 All security services started");
        Logger::info("🌐 API server listening on port {}", config.api_port);
        Logger::info("📡 Packet filtering active on interface {}", config.interface_name);
        Logger::info("🔒 Crypto engine with hardware acceleration enabled");
        Logger::info("🛡️  Memory protection active");
        
        // Print performance capabilities
        auto capabilities = g_security_core->get_performance_capabilities();
        Logger::info("⚡ Performance Capabilities:");
        Logger::info("  - Max packet rate: {} Mpps", capabilities.max_packet_rate / 1000000.0);
        Logger::info("  - Crypto throughput: {} Gbps", capabilities.crypto_throughput_gbps);
        Logger::info("  - Memory bandwidth: {} GB/s", capabilities.memory_bandwidth_gbps);
        Logger::info("  - Hardware acceleration: {}", capabilities.has_hardware_acceleration ? "YES" : "NO");
        
        // Main event loop
        Logger::info("🎯 Security engine running. Press Ctrl+C to stop.");
        
        while (g_security_core->is_running()) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            
            // Print periodic statistics
            static int stats_counter = 0;
            if (++stats_counter >= 30) { // Every 30 seconds
                auto stats = g_security_core->get_performance_metrics();
                
                Logger::info("📊 Performance Stats:");
                Logger::info("  - Packets processed: {}", stats.packets_processed.load());
                Logger::info("  - Threats detected: {}", stats.threats_detected.load());
                Logger::info("  - Bytes processed: {} MB", stats.bytes_processed.load() / (1024 * 1024));
                Logger::info("  - Crypto operations: {}", stats.crypto_operations.load());
                Logger::info("  - CPU usage: {:.1f}%", stats.cpu_usage.load());
                Logger::info("  - Memory usage: {:.1f}%", stats.memory_usage.load());
                
                stats_counter = 0;
            }
        }
        
    } catch (const std::exception& e) {
        Logger::error("Fatal error: {}", e.what());
        return 1;
    } catch (...) {
        Logger::error("Unknown fatal error occurred");
        return 1;
    }
    
    Logger::info("🏁 Security engine shutdown complete");
    return 0;
}