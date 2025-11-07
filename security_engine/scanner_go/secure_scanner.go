package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

type ThreatEvent struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Severity    string    `json:"severity"`
	Source      string    `json:"source"`
	SourceHash  string    `json:"source_hash"`
	Timestamp   time.Time `json:"timestamp"`
	Details     string    `json:"details"`
	Confidence  float64   `json:"confidence"`
	Blocked     bool      `json:"blocked"`
}

type SecurityScanner struct {
	threats     chan ThreatEvent
	clients     map[*websocket.Conn]bool
	clientsMux  sync.RWMutex
	patterns    map[string]*regexp.Regexp
	blockedIPs  map[string]time.Time
	ipMux       sync.RWMutex
	stats       ScannerStats
	statsMux    sync.RWMutex
}

type ScannerStats struct {
	TotalScans     int64 `json:"total_scans"`
	ThreatsBlocked int64 `json:"threats_blocked"`
	ActiveClients  int   `json:"active_clients"`
	Uptime         int64 `json:"uptime_seconds"`
}

type ScanRequest struct {
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
	Method  string            `json:"method"`
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		return origin == "http://localhost:5173" || origin == "http://127.0.0.1:5173"
	},
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

func NewSecurityScanner() *SecurityScanner {
	scanner := &SecurityScanner{
		threats:    make(chan ThreatEvent, 1000),
		clients:    make(map[*websocket.Conn]bool),
		blockedIPs: make(map[string]time.Time),
		patterns:   make(map[string]*regexp.Regexp),
		stats: ScannerStats{
			Uptime: time.Now().Unix(),
		},
	}
	
	// Initialize threat detection patterns
	scanner.initializePatterns()
	
	return scanner
}

func (s *SecurityScanner) initializePatterns() {
	patterns := map[string]string{
		"sql_injection": `(?i)(union|select|insert|update|delete|drop|create|alter|exec|execute|script|javascript|vbscript|onload|onerror|alert|prompt|confirm|eval|expression|import|meta|link|object|embed|applet|form|iframe|frame|frameset|input|textarea|button|img|svg|audio|video|source|track|canvas|map|area)`,
		"xss_attack":    `(?i)(<script|javascript:|vbscript:|onload=|onerror=|onclick=|onmouseover=|onfocus=|onblur=|onchange=|onsubmit=|<iframe|<object|<embed|<applet|<form|<img[^>]*src[^>]*javascript|<svg[^>]*onload)`,
		"path_traversal": `(?i)(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e%5c|%252e%252e%252f|%252e%252e%255c|\.\.%2f|\.\.%5c)`,
		"command_injection": `(?i)(;|\||&|`+"`"+`|\$\(|\${|nc |netcat |wget |curl |ping |nslookup |dig |whoami |id |ps |ls |cat |tail |head |grep |awk |sed |sort |uniq |wc |find |locate |which |whereis |uname |hostname |uptime |w |who |last |history |env |set |export |alias |unalias |jobs |bg |fg |nohup |screen |tmux |su |sudo |chmod |chown |chgrp |mount |umount |df |du |free |top |htop |iotop |iftop |netstat |ss |lsof |strace |ltrace |gdb |objdump |strings |hexdump |od |xxd |base64 |openssl |gpg |ssh |scp |rsync |tar |gzip |gunzip |zip |unzip |7z |rar |unrar)`,
		"ldap_injection": `(?i)(\*|\(|\)|&|\||!|=|<|>|~|%2a|%28|%29|%26|%7c|%21|%3d|%3c|%3e|%7e)`,
		"nosql_injection": `(?i)(\$where|\$ne|\$in|\$nin|\$gt|\$gte|\$lt|\$lte|\$exists|\$regex|\$options|\$elemMatch|\$size|\$all|\$mod|\$type|\$text|\$search|\$language|\$caseSensitive|\$diacriticSensitive)`,
	}
	
	for name, pattern := range patterns {
		if compiled, err := regexp.Compile(pattern); err == nil {
			s.patterns[name] = compiled
		} else {
			log.Printf("Failed to compile pattern %s: %v", name, err)
		}
	}
}

func (s *SecurityScanner) scanForThreats(req ScanRequest, clientIP string) []ThreatEvent {
	var threats []ThreatEvent
	
	// Increment scan counter
	s.statsMux.Lock()
	s.stats.TotalScans++
	s.statsMux.Unlock()
	
	// Check if IP is blocked
	s.ipMux.RLock()
	if blockedTime, exists := s.blockedIPs[clientIP]; exists {
		if time.Since(blockedTime) < 10*time.Minute {
			s.ipMux.RUnlock()
			return []ThreatEvent{{
				ID:         generateThreatID(),
				Type:       "Blocked IP",
				Severity:   "HIGH",
				Source:     clientIP,
				SourceHash: hashIP(clientIP),
				Timestamp:  time.Now(),
				Details:    "Request from blocked IP address",
				Confidence: 1.0,
				Blocked:    true,
			}}
		}
	}
	s.ipMux.RUnlock()
	
	// Scan URL, headers, and body
	allContent := fmt.Sprintf("%s %s %s", req.URL, req.Body, strings.Join(getHeaderValues(req.Headers), " "))
	
	for patternName, pattern := range s.patterns {
		if pattern.MatchString(allContent) {
			threat := ThreatEvent{
				ID:         generateThreatID(),
				Type:       strings.Title(strings.Replace(patternName, "_", " ", -1)),
				Severity:   s.calculateSeverity(patternName),
				Source:     clientIP,
				SourceHash: hashIP(clientIP),
				Timestamp:  time.Now(),
				Details:    fmt.Sprintf("Detected %s pattern in request", patternName),
				Confidence: s.calculateConfidence(patternName, allContent),
				Blocked:    false,
			}
			threats = append(threats, threat)
		}
	}
	
	// Block IP if high-severity threats detected
	if len(threats) > 0 {
		for _, threat := range threats {
			if threat.Severity == "CRITICAL" || threat.Severity == "HIGH" {
				s.blockIP(clientIP)
				break
			}
		}
	}
	
	return threats
}

func (s *SecurityScanner) calculateSeverity(patternName string) string {
	switch patternName {
	case "sql_injection", "command_injection":
		return "CRITICAL"
	case "xss_attack", "path_traversal":
		return "HIGH"
	case "ldap_injection", "nosql_injection":
		return "MEDIUM"
	default:
		return "LOW"
	}
}

func (s *SecurityScanner) calculateConfidence(patternName, content string) float64 {
	matches := s.patterns[patternName].FindAllString(content, -1)
	confidence := float64(len(matches)) * 0.2
	if confidence > 1.0 {
		confidence = 1.0
	}
	return confidence
}

func (s *SecurityScanner) blockIP(ip string) {
	s.ipMux.Lock()
	s.blockedIPs[ip] = time.Now()
	s.ipMux.Unlock()
	
	s.statsMux.Lock()
	s.stats.ThreatsBlocked++
	s.statsMux.Unlock()
	
	log.Printf("🚫 Blocked IP: %s", hashIP(ip))
}

func (s *SecurityScanner) broadcastThreat(threat ThreatEvent) {
	data, err := json.Marshal(threat)
	if err != nil {
		log.Printf("Error marshaling threat: %v", err)
		return
	}
	
	s.clientsMux.RLock()
	defer s.clientsMux.RUnlock()
	
	for client := range s.clients {
		if err := client.WriteMessage(websocket.TextMessage, data); err != nil {
			log.Printf("WebSocket write error: %v", err)
			client.Close()
			delete(s.clients, client)
		}
	}
}

func (s *SecurityScanner) wsHandler(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade error: %v", err)
		return
	}
	defer conn.Close()
	
	s.clientsMux.Lock()
	s.clients[conn] = true
	s.stats.ActiveClients = len(s.clients)
	s.clientsMux.Unlock()
	
	log.Printf("🔌 WebSocket client connected from %s", r.RemoteAddr)
	
	// Keep connection alive
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
		}
	}
	
	s.clientsMux.Lock()
	delete(s.clients, conn)
	s.stats.ActiveClients = len(s.clients)
	s.clientsMux.Unlock()
	
	log.Printf("🔌 WebSocket client disconnected")
}

func (s *SecurityScanner) scanHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	var scanReq ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&scanReq); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	
	clientIP := getClientIP(r)
	threats := s.scanForThreats(scanReq, clientIP)
	
	// Broadcast threats to WebSocket clients
	for _, threat := range threats {
		s.broadcastThreat(threat)
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":        "success",
		"threats_found": len(threats),
		"threats":       threats,
	})
}

func (s *SecurityScanner) statsHandler(w http.ResponseWriter, r *http.Request) {
	s.statsMux.RLock()
	stats := s.stats
	stats.Uptime = time.Now().Unix() - stats.Uptime
	s.statsMux.RUnlock()
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (s *SecurityScanner) healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "healthy",
		"service": "Go Security Scanner",
		"version": "2.0.0",
	})
}

// Utility functions
func generateThreatID() string {
	return fmt.Sprintf("THR-%d-%d", time.Now().Unix(), time.Now().Nanosecond()%1000000)
}

func hashIP(ip string) string {
	hash := sha256.Sum256([]byte(ip))
	return fmt.Sprintf("%x", hash)[:16]
}

func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}
	
	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	
	// Fall back to RemoteAddr
	ip := r.RemoteAddr
	if colon := strings.LastIndex(ip, ":"); colon != -1 {
		ip = ip[:colon]
	}
	return ip
}

func getHeaderValues(headers map[string]string) []string {
	var values []string
	for _, value := range headers {
		values = append(values, value)
	}
	return values
}

func main() {
	scanner := NewSecurityScanner()
	
	// Start threat processing goroutine
	go func() {
		for threat := range scanner.threats {
			log.Printf("🚨 Threat detected: %s - %s from %s", 
				threat.Type, threat.Severity, threat.SourceHash)
			scanner.broadcastThreat(threat)
		}
	}()
	
	// Setup routes with security middleware
	r := mux.NewRouter()
	r.HandleFunc("/ws", scanner.wsHandler)
	r.HandleFunc("/api/scan", scanner.scanHandler)
	r.HandleFunc("/api/stats", scanner.statsHandler)
	r.HandleFunc("/health", scanner.healthHandler)
	
	// Add security headers middleware
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("X-XSS-Protection", "1; mode=block")
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			next.ServeHTTP(w, r)
		})
	})
	
	server := &http.Server{
		Addr:         ":8080",
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	
	log.Println("🔍 Go Security Scanner starting on :8080")
	log.Println("📊 Health check: http://localhost:8080/health")
	log.Println("📈 Stats: http://localhost:8080/api/stats")
	log.Println("🔌 WebSocket: ws://localhost:8080/ws")
	
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server failed to start: %v", err)
	}
}