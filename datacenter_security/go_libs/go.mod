// 🐹 GO LIBRARIES FOR DATA CENTER SECURITY (25 Libraries)

module datacenter-security

go 1.21

require (
    // === WEB FRAMEWORKS & HTTP ===
    github.com/gin-gonic/gin v1.9.1              // Fast HTTP web framework
    github.com/gorilla/mux v1.8.1                // HTTP router and URL matcher
    github.com/gorilla/websocket v1.5.1          // WebSocket implementation
    github.com/labstack/echo/v4 v4.11.3          // High performance web framework
    
    // === DATABASE & STORAGE ===
    github.com/go-redis/redis/v8 v8.11.5         // Redis client
    gorm.io/gorm v1.25.5                         // ORM library
    gorm.io/driver/postgres v1.5.4               // PostgreSQL driver
    github.com/elastic/go-elasticsearch/v8 v8.11.0  // Elasticsearch client
    go.etcd.io/etcd/client/v3 v3.5.10           // etcd client
    
    // === MONITORING & OBSERVABILITY ===
    github.com/prometheus/client_golang v1.17.0  // Prometheus metrics
    go.opentelemetry.io/otel v1.21.0            // OpenTelemetry
    github.com/sirupsen/logrus v1.9.3           // Structured logging
    go.uber.org/zap v1.26.0                     // Fast logging
    
    // === SECURITY & CRYPTOGRAPHY ===
    golang.org/x/crypto v0.16.0                 // Cryptographic functions
    github.com/dgrijalva/jwt-go v3.2.0          // JWT implementation
    golang.org/x/oauth2 v0.15.0                 // OAuth2 client
    
    // === NETWORKING ===
    github.com/google/gopacket v1.1.19          // Packet processing
    github.com/vishvananda/netlink v1.1.0       // Netlink sockets
    github.com/miekg/dns v1.1.57                // DNS library
    
    // === CONCURRENCY & ASYNC ===
    github.com/panjf2000/ants/v2 v2.8.2         // Goroutine pool
    golang.org/x/sync v0.5.0                    // Extended sync package
    
    // === SERIALIZATION ===
    google.golang.org/protobuf v1.31.0          // Protocol buffers
    github.com/vmihailenco/msgpack/v5 v5.4.1    // MessagePack
    
    // === SYSTEM & UTILITIES ===
    github.com/shirou/gopsutil/v3 v3.23.10      // System information
    github.com/spf13/cobra v1.8.0               // CLI applications
)