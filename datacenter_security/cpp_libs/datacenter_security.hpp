#pragma once

// ⚡ C++ DATA CENTER SECURITY CORE
#include <immintrin.h>
#include <x86intrin.h>

// High-Performance Libraries
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/lockfree/queue.hpp>
#include <tbb/parallel_for.h>
#include <tbb/concurrent_hash_map.h>

// Security & Crypto
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <sodium.h>
#include <cryptopp/aes.h>

// Networking
#include <pcap.h>
#include <dpdk/rte_eal.h>
#include <netfilter_queue/libnetfilter_queue.h>

// Database
#include <postgresql/libpq-fe.h>
#include <hiredis/hiredis.h>
#include <rocksdb/db.h>

// Monitoring
#include <prometheus/counter.h>
#include <spdlog/spdlog.h>

namespace datacenter_security {

class UltraFastPacketProcessor {
private:
    alignas(64) std::array<uint8_t, 65536> packet_buffer_;
    boost::lockfree::queue<PacketInfo, boost::lockfree::capacity<1024>> packet_queue_;
    tbb::concurrent_hash_map<uint32_t, ThreatLevel> ip_reputation_;
    
public:
    // SIMD-optimized packet filtering
    bool filter_packet_avx2(const uint8_t* packet, size_t length);
    
    // Hardware-accelerated crypto
    bool encrypt_aes_ni(const uint8_t* data, uint8_t* output);
    
    // 10Gbps+ throughput processing
    void process_packet_batch_dpdk(struct rte_mbuf** packets, uint16_t nb_packets);
};

class HardwareAcceleratedCrypto {
private:
    EVP_CIPHER_CTX* aes_ctx_;
    CryptoPP::AES::Encryption aes_enc_;
    
public:
    // AES-NI hardware acceleration
    bool aes_encrypt_hardware(const uint8_t* plaintext, uint8_t* ciphertext);
    
    // Intel IPP optimized hashing
    void sha256_ipp_optimized(const uint8_t* data, uint8_t* hash);
    
    // Quantum-resistant crypto
    bool kyber_key_exchange(uint8_t* public_key, uint8_t* shared_secret);
};

} // namespace datacenter_security