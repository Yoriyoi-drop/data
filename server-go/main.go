package main

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

type ThreatEvent struct {
	ID         string    `json:"id"`
	SourceIP   string    `json:"source_ip"`
	AttackType string    `json:"attack_type"`
	Severity   string    `json:"severity"`
	Timestamp  time.Time `json:"timestamp"`
	Blocked    bool      `json:"blocked"`
}

type SecurityServer struct {
	clients    map[*websocket.Conn]bool
	broadcast  chan ThreatEvent
	register   chan *websocket.Conn
	unregister chan *websocket.Conn
	mutex      sync.RWMutex
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins in development
	},
}

func NewSecurityServer() *SecurityServer {
	return &SecurityServer{
		clients:    make(map[*websocket.Conn]bool),
		broadcast:  make(chan ThreatEvent),
		register:   make(chan *websocket.Conn),
		unregister: make(chan *websocket.Conn),
	}
}

func (s *SecurityServer) handleConnections() {
	for {
		select {
		case client := <-s.register:
			s.mutex.Lock()
			s.clients[client] = true
			s.mutex.Unlock()
			log.Printf("Client connected. Total: %d", len(s.clients))

		case client := <-s.unregister:
			s.mutex.Lock()
			if _, ok := s.clients[client]; ok {
				delete(s.clients, client)
				client.Close()
			}
			s.mutex.Unlock()
			log.Printf("Client disconnected. Total: %d", len(s.clients))

		case event := <-s.broadcast:
			s.mutex.RLock()
			for client := range s.clients {
				err := client.WriteJSON(event)
				if err != nil {
					log.Printf("WebSocket error: %v", err)
					client.Close()
					delete(s.clients, client)
				}
			}
			s.mutex.RUnlock()
		}
	}
}

func (s *SecurityServer) wsHandler(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade error: %v", err)
		return
	}

	s.register <- conn

	defer func() {
		s.unregister <- conn
		conn.Close()
	}()

	for {
		var event ThreatEvent
		err := conn.ReadJSON(&event)
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("WebSocket error: %v", err)
			}
			break
		}
		s.broadcast <- event
	}
}

func (s *SecurityServer) threatHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var event ThreatEvent
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	event.Timestamp = time.Now()
	s.broadcast <- event

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "received"})
}

func (s *SecurityServer) metricsHandler(w http.ResponseWriter, r *http.Request) {
	s.mutex.RLock()
	clientCount := len(s.clients)
	s.mutex.RUnlock()

	metrics := map[string]interface{}{
		"active_connections": clientCount,
		"uptime_seconds":     time.Since(startTime).Seconds(),
		"threats_processed":  threatsProcessed,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metrics)
}

var (
	startTime        = time.Now()
	threatsProcessed = 0
)

func main() {
	server := NewSecurityServer()
	go server.handleConnections()

	http.HandleFunc("/ws", server.wsHandler)
	http.HandleFunc("/api/threat", server.threatHandler)
	http.HandleFunc("/api/metrics", server.metricsHandler)

	// Serve static files
	http.Handle("/", http.FileServer(http.Dir("./static/")))

	log.Println("Infinite AI Security Server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}