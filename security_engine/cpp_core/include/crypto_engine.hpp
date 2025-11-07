#pragma once

#include "common.hpp"
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/gcm.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#ifdef HAVE_IPP
#include <ipp.h>
#include <ippcp.h>
#endif

namespace infinite_security {

class CryptoEngine {
public:
    CryptoEngine();
    ~CryptoEngine();

    // Hardware-accelerated AES operations
    bool encrypt_aes_256_gcm(
        const u8* plaintext, size_t plaintext_len,
        const u8* key, const u8* iv,
        u8* ciphertext, u8* tag
    );
    
    bool decrypt_aes_256_gcm(
        const u8* ciphertext, size_t ciphertext_len,
        const u8* key, const u8* iv, const u8* tag,
        u8* plaintext
    );
    
    // Batch encryption for high throughput
    void encrypt_batch_aes_256_gcm(
        std::span<const std::span<const u8>> plaintexts,
        std::span<const std::array<u8, 32>> keys,
        std::span<const std::array<u8, 12>> ivs,
        std::span<std::span<u8>> ciphertexts,
        std::span<std::array<u8, 16>> tags
    );
    
    // High-performance hashing
    void sha256_hash(const u8* data, size_t length, u8* hash);
    void sha256_hash_batch(
        std::span<const std::span<const u8>> data_blocks,
        std::span<std::array<u8, 32>> hashes
    );
    
    // SIMD-optimized SHA-256 (if available)
    void sha256_hash_avx2(const u8* data, size_t length, u8* hash);
    
    // HMAC operations
    bool hmac_sha256(
        const u8* key, size_t key_len,
        const u8* data, size_t data_len,
        u8* hmac
    );
    
    // Key derivation
    bool derive_key_pbkdf2(
        const u8* password, size_t password_len,
        const u8* salt, size_t salt_len,
        u32 iterations,
        u8* derived_key, size_t key_len
    );
    
    // Secure random generation
    bool generate_random_bytes(u8* buffer, size_t length);
    u64 generate_random_u64();
    
    // Digital signatures (Ed25519)
    bool generate_keypair_ed25519(u8* public_key, u8* private_key);
    bool sign_ed25519(
        const u8* message, size_t message_len,
        const u8* private_key,
        u8* signature
    );
    bool verify_ed25519(
        const u8* message, size_t message_len,
        const u8* signature,
        const u8* public_key
    );
    
    // Performance monitoring
    u64 get_crypto_operations_count() const { return crypto_operations_.load(); }
    f64 get_throughput_mbps() const;
    
private:
    // OpenSSL contexts
    EVP_CIPHER_CTX* aes_encrypt_ctx_;
    EVP_CIPHER_CTX* aes_decrypt_ctx_;
    EVP_MD_CTX* hash_ctx_;
    
    // Performance counters
    std::atomic<u64> crypto_operations_{0};
    std::atomic<u64> bytes_processed_{0};
    TimePoint start_time_;
    
    // Hardware acceleration detection
    bool has_aes_ni_;
    bool has_avx2_;
    bool has_sha_extensions_;
    
#ifdef HAVE_IPP
    // Intel IPP contexts for hardware acceleration
    IppsAESSpec* ipp_aes_spec_;
    IppsSHA256State* ipp_sha256_state_;
#endif
    
    // Private methods
    void initialize_hardware_acceleration();
    void cleanup_contexts();
    
    // Hardware-specific implementations
    bool encrypt_aes_ni(
        const u8* plaintext, size_t len,
        const u8* key, const u8* iv,
        u8* ciphertext, u8* tag
    );
    
    void sha256_with_extensions(const u8* data, size_t length, u8* hash);
    
    // Batch processing helpers
    void process_crypto_batch_parallel(
        std::function<void(size_t)> crypto_operation,
        size_t batch_size
    );
};

// High-performance secure memory management
class SecureMemoryManager {
public:
    SecureMemoryManager();
    ~SecureMemoryManager();
    
    // Secure memory allocation
    void* secure_alloc(size_t size);
    void secure_free(void* ptr, size_t size);
    
    // Memory protection
    bool protect_memory(void* ptr, size_t size, bool read_only = true);
    bool unprotect_memory(void* ptr, size_t size);
    
    // Secure memory operations
    void secure_zero(void* ptr, size_t size);
    bool secure_compare(const void* a, const void* b, size_t size);
    
    // Memory pool for frequent allocations
    void* pool_alloc(size_t size);
    void pool_free(void* ptr);
    
private:
    // Memory pools for different sizes
    std::array<boost::lockfree::stack<void*>, 16> memory_pools_;
    std::mutex pool_mutex_;
    
    // Secure memory tracking
    std::unordered_map<void*, size_t> secure_allocations_;
    std::mutex allocations_mutex_;
    
    // Platform-specific secure allocation
    void* platform_secure_alloc(size_t size);
    void platform_secure_free(void* ptr, size_t size);
};

// Cryptographic random number generator
class SecureRNG {
public:
    SecureRNG();
    ~SecureRNG();
    
    // High-quality random generation
    bool generate_bytes(u8* buffer, size_t length);
    u32 generate_u32();
    u64 generate_u64();
    f64 generate_uniform_f64(); // [0.0, 1.0)
    
    // Cryptographically secure random for specific use cases
    std::string generate_session_id(size_t length = 32);
    std::array<u8, 32> generate_encryption_key();
    std::array<u8, 12> generate_iv();
    
    // Entropy management
    void add_entropy(const u8* data, size_t length);
    u32 get_entropy_estimate() const;
    
private:
    // Multiple entropy sources
    std::random_device hardware_rng_;
    
    // Entropy pool
    std::array<u8, 4096> entropy_pool_;
    size_t entropy_index_;
    std::mutex entropy_mutex_;
    
    // CSPRNG state
    std::array<u8, 32> rng_state_;
    u64 counter_;
    
    // Private methods
    void reseed_if_needed();
    void mix_entropy();
    void chacha20_generate(u8* output, size_t length);
};

// Hardware security module interface
class HSMInterface {
public:
    HSMInterface();
    ~HSMInterface();
    
    // HSM operations
    bool is_available() const { return hsm_available_; }
    bool initialize_hsm();
    
    // Key management
    bool generate_key_in_hsm(const std::string& key_id);
    bool encrypt_with_hsm_key(
        const std::string& key_id,
        const u8* plaintext, size_t plaintext_len,
        u8* ciphertext, size_t* ciphertext_len
    );
    
    bool decrypt_with_hsm_key(
        const std::string& key_id,
        const u8* ciphertext, size_t ciphertext_len,
        u8* plaintext, size_t* plaintext_len
    );
    
    // Digital signatures with HSM
    bool sign_with_hsm_key(
        const std::string& key_id,
        const u8* data, size_t data_len,
        u8* signature, size_t* signature_len
    );
    
private:
    bool hsm_available_;
    void* hsm_handle_;
    
    // HSM-specific implementation
    bool detect_hsm();
    void cleanup_hsm();
};

// Quantum-resistant cryptography (experimental)
class PostQuantumCrypto {
public:
    PostQuantumCrypto();
    ~PostQuantumCrypto();
    
    // CRYSTALS-Kyber key encapsulation
    bool kyber_generate_keypair(u8* public_key, u8* private_key);
    bool kyber_encapsulate(const u8* public_key, u8* ciphertext, u8* shared_secret);
    bool kyber_decapsulate(const u8* private_key, const u8* ciphertext, u8* shared_secret);
    
    // CRYSTALS-Dilithium signatures
    bool dilithium_generate_keypair(u8* public_key, u8* private_key);
    bool dilithium_sign(
        const u8* private_key,
        const u8* message, size_t message_len,
        u8* signature, size_t* signature_len
    );
    bool dilithium_verify(
        const u8* public_key,
        const u8* message, size_t message_len,
        const u8* signature, size_t signature_len
    );
    
private:
    bool pqc_available_;
    
    void initialize_pqc_library();
    void cleanup_pqc_library();
};

} // namespace infinite_security