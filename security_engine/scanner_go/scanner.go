// Use the secure scanner implementation
// This file is replaced by secure_scanner.go

type ThreatEvent struct {
    ID        string    `json:"id"`
    Type      string    `json:"type"`
    Severity  string    `json:"severity"`
    Source    string    `json:"source"`
    Timestamp time.Time `json:"timestamp"`
    Details   string    `json:"details"`
}

type Scanner struct {
    threats chan ThreatEvent
    clients map[*websocket.Conn]bool
}

var upgrader = websocket.Upgrader{
    CheckOrigin: func(r *http.Request) bool { return true },
}

func NewScanner() *Scanner {
    return &Scanner{
        threats: make(chan ThreatEvent, 100),
        clients: make(map[*websocket.Conn]bool),
    }
}

func (s *Scanner) detectThreats() {
    // Simulasi deteksi ancaman real-time
    threats := []string{"SQL Injection", "XSS Attack", "DDoS", "Brute Force"}
    
    for {
        threat := ThreatEvent{
            ID:        fmt.Sprintf("THR-%d", time.Now().Unix()),
            Type:      threats[time.Now().Second()%len(threats)],
            Severity:  "HIGH",
            Source:    "192.168.1.100",
            Timestamp: time.Now(),
            Details:   "Suspicious activity detected",
        }
        
        s.threats <- threat
        time.Sleep(2 * time.Second)
    }
}

func (s *Scanner) broadcastThreat(threat ThreatEvent) {
    data, _ := json.Marshal(threat)
    
    for client := range s.clients {
        err := client.WriteMessage(websocket.TextMessage, data)
        if err != nil {
            client.Close()
            delete(s.clients, client)
        }
    }
}

func (s *Scanner) wsHandler(w http.ResponseWriter, r *http.Request) {
    conn, err := upgrader.Upgrade(w, r, nil)
    if err != nil {
        log.Println("WebSocket upgrade error:", err)
        return
    }
    
    s.clients[conn] = true
    log.Println("Client connected")
}

func (s *Scanner) threatHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    
    threat := ThreatEvent{
        ID:        "MANUAL-001",
        Type:      "Manual Scan",
        Severity:  "INFO",
        Source:    r.RemoteAddr,
        Timestamp: time.Now(),
        Details:   "Manual threat scan initiated",
    }
    
    json.NewEncoder(w).Encode(threat)
}

func main() {
    scanner := NewScanner()
    
    // Start threat detection
    go scanner.detectThreats()
    
    // Process threats
    go func() {
        for threat := range scanner.threats {
            log.Printf("Threat detected: %s - %s", threat.Type, threat.Severity)
            scanner.broadcastThreat(threat)
        }
    }()
    
    // Setup routes
    r := mux.NewRouter()
    r.HandleFunc("/ws", scanner.wsHandler)
    r.HandleFunc("/api/threats", scanner.threatHandler)
    r.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
        w.Write([]byte("Scanner OK"))
    })
    
    log.Println("Security Scanner running on :8080")
    log.Fatal(http.ListenAndServe(":8080", r))
}