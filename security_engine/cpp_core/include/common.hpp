#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <chrono>
#include <atomic>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <unordered_map>
#include <unordered_set>
#include <array>
#include <span>

// High-performance libraries
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/json.hpp>
#include <boost/circular_buffer.hpp>
#include <boost/lockfree/queue.hpp>
#include <boost/lockfree/stack.hpp>
#include <tbb/parallel_for.h>
#include <tbb/concurrent_hash_map.h>
#include <tbb/concurrent_queue.h>

// Crypto and security
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

// Network
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

namespace infinite_security {

// Type aliases for performance
using u8 = std::uint8_t;
using u16 = std::uint16_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;
using i8 = std::int8_t;
using i16 = std::int16_t;
using i32 = std::int32_t;
using i64 = std::int64_t;
using f32 = float;
using f64 = double;

using TimePoint = std::chrono::high_resolution_clock::time_point;
using Duration = std::chrono::nanoseconds;

// Constants
constexpr size_t MAX_PACKET_SIZE = 65536;
constexpr size_t RING_BUFFER_SIZE = 1024 * 1024;
constexpr size_t THREAD_POOL_SIZE = std::thread::hardware_concurrency();
constexpr u32 DEFAULT_PORT = 9090;

// Threat levels
enum class ThreatLevel : u8 {
    NONE = 0,
    LOW = 1,
    MEDIUM = 2,
    HIGH = 3,
    CRITICAL = 4
};

// Packet types
enum class PacketType : u8 {
    UNKNOWN = 0,
    TCP = 1,
    UDP = 2,
    ICMP = 3,
    HTTP = 4,
    HTTPS = 5,
    DNS = 6
};

// Security events
enum class SecurityEvent : u8 {
    PACKET_FILTERED = 1,
    THREAT_DETECTED = 2,
    CRYPTO_OPERATION = 3,
    MEMORY_VIOLATION = 4,
    PERFORMANCE_ALERT = 5
};

// Packet structure for high-performance processing
struct alignas(64) PacketInfo {
    u64 timestamp_ns;
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    PacketType type;
    ThreatLevel threat_level;
    u16 payload_size;
    u8 flags;
    u8 reserved[5];
    std::array<u8, 64> payload_hash;
};

// Performance metrics
struct PerformanceMetrics {
    std::atomic<u64> packets_processed{0};
    std::atomic<u64> threats_detected{0};
    std::atomic<u64> bytes_processed{0};
    std::atomic<u64> crypto_operations{0};
    std::atomic<u64> memory_allocations{0};
    std::atomic<f64> cpu_usage{0.0};
    std::atomic<f64> memory_usage{0.0};
    TimePoint start_time;
};

// Configuration structure
struct SecurityConfig {
    std::string interface_name = "eth0";
    u32 max_packet_rate = 1000000;
    u32 thread_count = THREAD_POOL_SIZE;
    bool enable_crypto_acceleration = true;
    bool enable_memory_protection = true;
    bool enable_packet_filtering = true;
    std::string log_level = "INFO";
    u16 api_port = DEFAULT_PORT;
    std::vector<std::string> blocked_ips;
    std::vector<std::string> allowed_ips;
};

// Utility functions
inline TimePoint now() {
    return std::chrono::high_resolution_clock::now();
}

inline u64 timestamp_ns() {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
        now().time_since_epoch()
    ).count();
}

inline std::string threat_level_to_string(ThreatLevel level) {
    switch (level) {
        case ThreatLevel::NONE: return "NONE";
        case ThreatLevel::LOW: return "LOW";
        case ThreatLevel::MEDIUM: return "MEDIUM";
        case ThreatLevel::HIGH: return "HIGH";
        case ThreatLevel::CRITICAL: return "CRITICAL";
        default: return "UNKNOWN";
    }
}

// Memory alignment helpers
template<typename T>
constexpr T* align_ptr(T* ptr, size_t alignment) {
    return reinterpret_cast<T*>(
        (reinterpret_cast<uintptr_t>(ptr) + alignment - 1) & ~(alignment - 1)
    );
}

// SIMD-friendly data structures
template<typename T, size_t N>
struct alignas(64) SIMDArray {
    std::array<T, N> data;
    
    T& operator[](size_t i) { return data[i]; }
    const T& operator[](size_t i) const { return data[i]; }
    
    auto begin() { return data.begin(); }
    auto end() { return data.end(); }
    auto begin() const { return data.begin(); }
    auto end() const { return data.end(); }
};

// Lock-free ring buffer for high-performance packet processing
template<typename T, size_t Size>
class LockFreeRingBuffer {
private:
    alignas(64) std::array<T, Size> buffer_;
    alignas(64) std::atomic<size_t> head_{0};
    alignas(64) std::atomic<size_t> tail_{0};

public:
    bool push(const T& item) {
        const size_t current_tail = tail_.load(std::memory_order_relaxed);
        const size_t next_tail = (current_tail + 1) % Size;
        
        if (next_tail == head_.load(std::memory_order_acquire)) {
            return false; // Buffer full
        }
        
        buffer_[current_tail] = item;
        tail_.store(next_tail, std::memory_order_release);
        return true;
    }
    
    bool pop(T& item) {
        const size_t current_head = head_.load(std::memory_order_relaxed);
        
        if (current_head == tail_.load(std::memory_order_acquire)) {
            return false; // Buffer empty
        }
        
        item = buffer_[current_head];
        head_.store((current_head + 1) % Size, std::memory_order_release);
        return true;
    }
    
    size_t size() const {
        const size_t current_tail = tail_.load(std::memory_order_acquire);
        const size_t current_head = head_.load(std::memory_order_acquire);
        return (current_tail - current_head + Size) % Size;
    }
    
    bool empty() const {
        return head_.load(std::memory_order_acquire) == 
               tail_.load(std::memory_order_acquire);
    }
};

} // namespace infinite_security