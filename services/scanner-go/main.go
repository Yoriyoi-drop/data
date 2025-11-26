package main

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type ScanResult struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

var scanCounter = prometheus.NewCounter(prometheus.CounterOpts{
	Name: "scanner_scan_total",
	Help: "Total number of scan requests",
})

func init() {
	prometheus.MustRegister(scanCounter)
}

func scanHandler(w http.ResponseWriter, r *http.Request) {
	scanCounter.Inc()
	result := ScanResult{Status: "ok", Message: "Scan completed"}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func main() {
	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/scan", scanHandler)
	log.Println("Scanner service listening on :8002")
	if err := http.ListenAndServe(":8002", nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
