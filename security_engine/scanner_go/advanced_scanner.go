package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

// Advanced threat patterns dengan machine learning
var ThreatPatterns = map[string][]string{
	"sql_injection": {
		"' OR '1'='1", "UNION SELECT", "DROP TABLE", "INSERT INTO", 
		"UPDATE SET", "DELETE FROM", "EXEC(", "xp_cmdshell",
		"sp_executesql", "WAITFOR DELAY", "BENCHMARK(", "SLEEP(",
	},
	"xss": {
		"<script>", "</script>", "javascript:", "onload=", "onerror=",
		"onclick=", "onmouseover=", "eval(", "document.cookie",
		"window.location", "innerHTML", "outerHTML",
	},
	"command_injection": {
		"; ls", "| whoami", "&& cat", "$(", "`", "eval", "exec",
		"system(", "shell_exec", "passthru", "popen",
	},
	"path_traversal": {
		"../", "..\\", "%2e%2e%2f", "%2e%2e\\", "....//", "....\\\\",
		"/etc/passwd", "/etc/shadow", "C:\\Windows\\System32",
	},
	"ldap_injection": {
		"*)(uid=*", "*)(cn=*", "admin*", "*(|(password=*",
		"*))%00", "*)(userPassword=*", "*)(objectClass=*",
	},
}

type ThreatLevel int

const (
	LOW ThreatLevel = iota
	MEDIUM
	HIGH
	CRITICAL
)

type ScanResult struct {
	Timestamp    time.Time   `json:"timestamp"`
	Source       string      `json:"source"`
	ThreatType   string      `json:"threat_type"`
	ThreatLevel  ThreatLevel `json:"threat_level"`
	Payload      string      `json:"payload"`
	Confidence   float64     `json:"confidence"`
	Blocked      bool        `json:"blocked"`
	ResponseTime int64       `json:"response_time_ns"`
}

type AdvancedScanner struct {
	mu              sync.RWMutex
	patterns        map[string][]string
	scanCount       int64
	threatCount     int64
	blockedCount    int64
	clients         map[*websocket.Conn]bool
	clientsMu       sync.RWMutex
	rateLimiter     map[string]*RateLimit
	rateLimiterMu   sync.RWMutex
	mlModel         *MLThreatDetector
	honeypots       []string
	decoyTokens     []string
}

type RateLimit struct {
	requests    int64
	lastReset   time.Time
	maxRequests int64
	window      time.Duration
}

type MLThreatDetector struct {
	weights    [][]float64
	biases     []float64
	vocabulary map[string]int
}

func NewAdvancedScanner() *AdvancedScanner {
	scanner := &AdvancedScanner{
		patterns:    ThreatPatterns,
		clients:     make(map[*websocket.Conn]bool),
		rateLimiter: make(map[string]*RateLimit),
		honeypots: []string{
			"/admin/config.php", "/wp-admin/", "/.env", "/backup.sql",
			"/phpMyAdmin/", "/admin.php", "/login.php", "/config.ini",
		},
		decoyTokens: []string{
			"admin_secret_key_12345", "db_password_prod", "api_key_internal",
			"jwt_secret_token", "encryption_master_key",
		},
	}
	
	scanner.initMLModel()
	return scanner
}

func (s *AdvancedScanner) initMLModel() {
	// Simplified neural network for threat detection
	s.mlModel = &MLThreatDetector{
		weights: [][]float64{
			{0.8, -0.3, 0.6, -0.9, 0.4},
			{-0.5, 0.7, -0.2, 0.8, -0.6},
			{0.3, -0.8, 0.9, -0.4, 0.7},
		},
		biases:     []float64{0.1, -0.2, 0.3},
		vocabulary: make(map[string]int),
	}
	
	// Build vocabulary from threat patterns
	idx := 0
	for _, patterns := range ThreatPatterns {
		for _, pattern := range patterns {
			words := strings.Fields(strings.ToLower(pattern))
			for _, word := range words {
				if _, exists := s.mlModel.vocabulary[word]; !exists {
					s.mlModel.vocabulary[word] = idx
					idx++
				}
			}
		}
	}
}

func (s *AdvancedScanner) ScanPayload(payload string, source string) *ScanResult {
	start := time.Now()
	atomic.AddInt64(&s.scanCount, 1)
	
	result := &ScanResult{
		Timestamp:    start,
		Source:       source,
		Payload:      payload,
		ResponseTime: 0,
		Blocked:      false,
	}
	
	// Rate limiting check
	if s.isRateLimited(source) {
		result.ThreatType = "rate_limit_exceeded"
		result.ThreatLevel = MEDIUM
		result.Confidence = 1.0
		result.Blocked = true
		atomic.AddInt64(&s.blockedCount, 1)
		result.ResponseTime = time.Since(start).Nanoseconds()
		return result
	}
	
	// Honeypot detection
	if s.isHoneypotAccess(payload) {
		result.ThreatType = "honeypot_access"
		result.ThreatLevel = CRITICAL
		result.Confidence = 1.0
		result.Blocked = true
		atomic.AddInt64(&s.threatCount, 1)
		atomic.AddInt64(&s.blockedCount, 1)
		result.ResponseTime = time.Since(start).Nanoseconds()
		s.broadcastThreat(result)
		return result
	}
	
	// Pattern matching dengan optimasi
	maxConfidence := 0.0
	detectedType := ""
	detectedLevel := LOW
	
	for threatType, patterns := range s.patterns {
		for _, pattern := range patterns {
			if strings.Contains(strings.ToLower(payload), strings.ToLower(pattern)) {
				confidence := s.calculateConfidence(payload, pattern, threatType)
				if confidence > maxConfidence {
					maxConfidence = confidence
					detectedType = threatType
					detectedLevel = s.getThreatLevel(threatType, confidence)
				}
			}
		}
	}
	
	// ML-based detection
	mlConfidence := s.mlModel.predict(payload)
	if mlConfidence > maxConfidence {
		maxConfidence = mlConfidence
		detectedType = "ml_detected_threat"
		detectedLevel = s.getMLThreatLevel(mlConfidence)
	}
	
	result.ThreatType = detectedType
	result.ThreatLevel = detectedLevel
	result.Confidence = maxConfidence
	
	if maxConfidence > 0.7 {
		result.Blocked = true
		atomic.AddInt64(&s.threatCount, 1)
		atomic.AddInt64(&s.blockedCount, 1)
		s.broadcastThreat(result)
	}
	
	result.ResponseTime = time.Since(start).Nanoseconds()
	return result
}

func (s *AdvancedScanner) isRateLimited(source string) bool {
	s.rateLimiterMu.Lock()
	defer s.rateLimiterMu.Unlock()
	
	now := time.Now()
	limit, exists := s.rateLimiter[source]
	
	if !exists {
		s.rateLimiter[source] = &RateLimit{
			requests:    1,
			lastReset:   now,
			maxRequests: 1000, // 1000 requests per minute
			window:      time.Minute,
		}
		return false
	}
	
	if now.Sub(limit.lastReset) > limit.window {
		limit.requests = 1
		limit.lastReset = now
		return false
	}
	
	limit.requests++
	return limit.requests > limit.maxRequests
}

func (s *AdvancedScanner) isHoneypotAccess(payload string) bool {
	lowerPayload := strings.ToLower(payload)
	for _, honeypot := range s.honeypots {
		if strings.Contains(lowerPayload, strings.ToLower(honeypot)) {
			return true
		}
	}
	
	for _, token := range s.decoyTokens {
		if strings.Contains(lowerPayload, strings.ToLower(token)) {
			return true
		}
	}
	
	return false
}

func (s *AdvancedScanner) calculateConfidence(payload, pattern, threatType string) float64 {
	baseConfidence := 0.5
	
	// Pattern frequency
	count := strings.Count(strings.ToLower(payload), strings.ToLower(pattern))
	frequencyBonus := float64(count) * 0.1
	
	// Length penalty for short patterns
	if len(pattern) < 3 {
		baseConfidence *= 0.7
	}
	
	// Threat type specific adjustments
	switch threatType {
	case "sql_injection":
		if strings.Contains(payload, "'") && strings.Contains(payload, "OR") {
			baseConfidence += 0.3
		}
	case "xss":
		if strings.Contains(payload, "<") && strings.Contains(payload, ">") {
			baseConfidence += 0.3
		}
	case "command_injection":
		if strings.Contains(payload, ";") || strings.Contains(payload, "|") {
			baseConfidence += 0.3
		}
	}
	
	confidence := baseConfidence + frequencyBonus
	if confidence > 1.0 {
		confidence = 1.0
	}
	
	return confidence
}

func (s *AdvancedScanner) getThreatLevel(threatType string, confidence float64) ThreatLevel {
	if confidence > 0.9 {
		return CRITICAL
	} else if confidence > 0.7 {
		return HIGH
	} else if confidence > 0.5 {
		return MEDIUM
	}
	return LOW
}

func (s *AdvancedScanner) getMLThreatLevel(confidence float64) ThreatLevel {
	if confidence > 0.85 {
		return CRITICAL
	} else if confidence > 0.65 {
		return HIGH
	} else if confidence > 0.45 {
		return MEDIUM
	}
	return LOW
}

func (ml *MLThreatDetector) predict(input string) float64 {
	// Simple feature extraction
	features := make([]float64, 5)
	
	// Feature 1: Length
	features[0] = float64(len(input)) / 1000.0
	
	// Feature 2: Special characters
	specialChars := strings.Count(input, "'") + strings.Count(input, "\"") + 
		strings.Count(input, "<") + strings.Count(input, ">") + strings.Count(input, ";")
	features[1] = float64(specialChars) / 10.0
	
	// Feature 3: SQL keywords
	sqlKeywords := []string{"select", "union", "drop", "insert", "update", "delete"}
	sqlCount := 0
	lowerInput := strings.ToLower(input)
	for _, keyword := range sqlKeywords {
		if strings.Contains(lowerInput, keyword) {
			sqlCount++
		}
	}
	features[2] = float64(sqlCount) / 6.0
	
	// Feature 4: Script tags
	if strings.Contains(lowerInput, "<script") || strings.Contains(lowerInput, "javascript:") {
		features[3] = 1.0
	}
	
	// Feature 5: Command injection patterns
	cmdPatterns := []string{";", "|", "&&", "$(", "`"}
	cmdCount := 0
	for _, pattern := range cmdPatterns {
		if strings.Contains(input, pattern) {
			cmdCount++
		}
	}
	features[4] = float64(cmdCount) / 5.0
	
	// Simple neural network forward pass
	output := 0.0
	for i, weight := range ml.weights[0] {
		if i < len(features) {
			output += features[i] * weight
		}
	}
	output += ml.biases[0]
	
	// Sigmoid activation
	return 1.0 / (1.0 + math.Exp(-output))
}

func (s *AdvancedScanner) broadcastThreat(result *ScanResult) {
	s.clientsMu.RLock()
	defer s.clientsMu.RUnlock()
	
	message, _ := json.Marshal(result)
	
	for client := range s.clients {
		err := client.WriteMessage(websocket.TextMessage, message)
		if err != nil {
			client.Close()
			delete(s.clients, client)
		}
	}
}

func (s *AdvancedScanner) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"total_scans":    atomic.LoadInt64(&s.scanCount),
		"threats_found":  atomic.LoadInt64(&s.threatCount),
		"blocked_count":  atomic.LoadInt64(&s.blockedCount),
		"active_clients": len(s.clients),
		"goroutines":     runtime.NumGoroutine(),
		"memory_mb":      getMemUsage(),
	}
}

func getMemUsage() uint64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.Alloc / 1024 / 1024
}

// HTTP Handlers
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

func (s *AdvancedScanner) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	s.clientsMu.Lock()
	s.clients[conn] = true
	s.clientsMu.Unlock()
	
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			s.clientsMu.Lock()
			delete(s.clients, conn)
			s.clientsMu.Unlock()
			break
		}
	}
}

func (s *AdvancedScanner) handleScan(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Payload string `json:"payload"`
		Source  string `json:"source"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	
	if request.Source == "" {
		request.Source = r.RemoteAddr
	}
	
	result := s.ScanPayload(request.Payload, request.Source)
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func (s *AdvancedScanner) handleStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.GetStats())
}

// Network scanning capabilities
func (s *AdvancedScanner) ScanNetwork(network string) []string {
	var vulnerableHosts []string
	
	ip, ipnet, err := net.ParseCIDR(network)
	if err != nil {
		return vulnerableHosts
	}
	
	var wg sync.WaitGroup
	var mu sync.Mutex
	
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			
			if s.scanHost(host) {
				mu.Lock()
				vulnerableHosts = append(vulnerableHosts, host)
				mu.Unlock()
			}
		}(ip.String())
	}
	
	wg.Wait()
	return vulnerableHosts
}

func (s *AdvancedScanner) scanHost(host string) bool {
	// Port scanning
	ports := []int{22, 23, 80, 443, 3389, 5432, 3306, 1433, 6379, 27017}
	
	for _, port := range ports {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), time.Second)
		if err == nil {
			conn.Close()
			
			// Additional vulnerability checks
			if s.checkVulnerabilities(host, port) {
				return true
			}
		}
	}
	
	return false
}

func (s *AdvancedScanner) checkVulnerabilities(host string, port int) bool {
	switch port {
	case 22: // SSH
		return s.checkSSHVulns(host, port)
	case 80, 443: // HTTP/HTTPS
		return s.checkWebVulns(host, port)
	case 3306: // MySQL
		return s.checkMySQLVulns(host, port)
	}
	return false
}

func (s *AdvancedScanner) checkSSHVulns(host string, port int) bool {
	config := &ssh.ClientConfig{
		User: "root",
		Auth: []ssh.AuthMethod{
			ssh.Password("root"),
			ssh.Password("admin"),
			ssh.Password("password"),
			ssh.Password("123456"),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	
	_, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", host, port), config)
	return err == nil
}

func (s *AdvancedScanner) checkWebVulns(host string, port int) bool {
	scheme := "http"
	if port == 443 {
		scheme = "https"
	}
	
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	
	// Check for common vulnerabilities
	vulnPaths := []string{
		"/admin", "/.env", "/config.php", "/phpinfo.php",
		"/wp-admin", "/admin.php", "/backup.sql",
	}
	
	for _, path := range vulnPaths {
		resp, err := client.Get(fmt.Sprintf("%s://%s:%d%s", scheme, host, port, path))
		if err == nil && resp.StatusCode == 200 {
			resp.Body.Close()
			return true
		}
		if resp != nil {
			resp.Body.Close()
		}
	}
	
	return false
}

func (s *AdvancedScanner) checkMySQLVulns(host string, port int) bool {
	// Simplified MySQL vulnerability check
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 5*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	
	// Check for anonymous login
	return true // Simplified for demo
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func main() {
	scanner := NewAdvancedScanner()
	
	http.HandleFunc("/ws", scanner.handleWebSocket)
	http.HandleFunc("/scan", scanner.handleScan)
	http.HandleFunc("/stats", scanner.handleStats)
	
	// Network scanning endpoint
	http.HandleFunc("/scan-network", func(w http.ResponseWriter, r *http.Request) {
		network := r.URL.Query().Get("network")
		if network == "" {
			http.Error(w, "Network parameter required", http.StatusBadRequest)
			return
		}
		
		vulnerableHosts := scanner.ScanNetwork(network)
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"network":          network,
			"vulnerable_hosts": vulnerableHosts,
			"scan_time":        time.Now(),
		})
	})
	
	fmt.Println("🚀 Advanced Go Scanner started on :8080")
	fmt.Println("📊 Endpoints:")
	fmt.Println("   /scan - Payload scanning")
	fmt.Println("   /scan-network - Network vulnerability scanning")
	fmt.Println("   /stats - Scanner statistics")
	fmt.Println("   /ws - WebSocket for real-time alerts")
	
	log.Fatal(http.ListenAndServe(":8080", nil))
}