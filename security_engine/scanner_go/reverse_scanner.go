package main

import (
	"crypto/md5"
	"crypto/sha256"
	"debug/pe"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// ReverseAnalysis represents the result of reverse engineering analysis
type ReverseAnalysis struct {
	FileInfo        FileInfo          `json:"file_info"`
	PEAnalysis      *PEAnalysis       `json:"pe_analysis,omitempty"`
	StringAnalysis  StringAnalysis    `json:"string_analysis"`
	ImportAnalysis  ImportAnalysis    `json:"import_analysis"`
	ThreatScore     int               `json:"threat_score"`
	Indicators      []ThreatIndicator `json:"indicators"`
	Recommendations []string          `json:"recommendations"`
	Timestamp       time.Time         `json:"timestamp"`
}

type FileInfo struct {
	Filename string `json:"filename"`
	Size     int64  `json:"size"`
	MD5      string `json:"md5"`
	SHA256   string `json:"sha256"`
	FileType string `json:"file_type"`
}

type PEAnalysis struct {
	Architecture    string      `json:"architecture"`
	EntryPoint      string      `json:"entry_point"`
	Sections        []Section   `json:"sections"`
	Imports         []Import    `json:"imports"`
	Exports         []string    `json:"exports"`
	IsPacked        bool        `json:"is_packed"`
	PackerSignature string      `json:"packer_signature,omitempty"`
}

type Section struct {
	Name         string `json:"name"`
	VirtualSize  uint32 `json:"virtual_size"`
	RawSize      uint32 `json:"raw_size"`
	Entropy      float64 `json:"entropy"`
	Permissions  string `json:"permissions"`
	Suspicious   bool   `json:"suspicious"`
}

type Import struct {
	DLL       string   `json:"dll"`
	Functions []string `json:"functions"`
	Suspicious bool    `json:"suspicious"`
}

type StringAnalysis struct {
	TotalStrings    int      `json:"total_strings"`
	URLs            []string `json:"urls"`
	IPAddresses     []string `json:"ip_addresses"`
	FilePaths       []string `json:"file_paths"`
	RegistryKeys    []string `json:"registry_keys"`
	CryptoStrings   []string `json:"crypto_strings"`
	SuspiciousStrings []string `json:"suspicious_strings"`
}

type ImportAnalysis struct {
	TotalImports     int      `json:"total_imports"`
	SuspiciousAPIs   []string `json:"suspicious_apis"`
	CryptoAPIs       []string `json:"crypto_apis"`
	NetworkAPIs      []string `json:"network_apis"`
	FileAPIs         []string `json:"file_apis"`
	ProcessAPIs      []string `json:"process_apis"`
}

type ThreatIndicator struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Confidence  float64 `json:"confidence"`
}

// ReverseScanner performs reverse engineering analysis
type ReverseScanner struct {
	suspiciousAPIs   map[string]string
	packerSignatures []string
	cryptoPatterns   []*regexp.Regexp
}

// NewReverseScanner creates a new reverse engineering scanner
func NewReverseScanner() *ReverseScanner {
	return &ReverseScanner{
		suspiciousAPIs: map[string]string{
			"CreateRemoteThread":   "Process Injection",
			"VirtualAllocEx":       "Memory Manipulation", 
			"WriteProcessMemory":   "Process Injection",
			"SetWindowsHookEx":     "Keylogging/Hooking",
			"CryptEncrypt":         "Encryption",
			"CryptDecrypt":         "Decryption",
			"RegSetValue":          "Registry Modification",
			"CreateService":        "Service Installation",
			"OpenProcess":          "Process Access",
			"ReadProcessMemory":    "Memory Reading",
			"GetAsyncKeyState":     "Keylogging",
			"FindWindow":           "Window Enumeration",
			"ShellExecute":         "Command Execution",
			"WinExec":              "Command Execution",
		},
		packerSignatures: []string{
			"UPX0", "UPX1", "UPX2",
			".aspack", ".adata",
			"PECompact", "PEC2",
			"Themida", ".themida",
			"VMProtect", ".vmp0",
		},
		cryptoPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)(aes|des|rsa|md5|sha1|sha256|blowfish)`),
			regexp.MustCompile(`(?i)(encrypt|decrypt|cipher|hash|crypto)`),
			regexp.MustCompile(`[A-Za-z0-9+/]{40,}={0,2}`), // Base64
			regexp.MustCompile(`[0-9a-fA-F]{32,}`),         // Hex
		},
	}
}

// AnalyzeFile performs comprehensive reverse engineering analysis
func (rs *ReverseScanner) AnalyzeFile(filePath string) (*ReverseAnalysis, error) {
	analysis := &ReverseAnalysis{
		Timestamp: time.Now(),
	}

	// Basic file info
	fileInfo, err := rs.analyzeFileInfo(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to analyze file info: %v", err)
	}
	analysis.FileInfo = *fileInfo

	// PE analysis for Windows executables
	if strings.HasSuffix(strings.ToLower(filePath), ".exe") || 
	   strings.HasSuffix(strings.ToLower(filePath), ".dll") {
		peAnalysis, err := rs.analyzePE(filePath)
		if err == nil {
			analysis.PEAnalysis = peAnalysis
		}
	}

	// String analysis
	stringAnalysis, err := rs.analyzeStrings(filePath)
	if err == nil {
		analysis.StringAnalysis = *stringAnalysis
	}

	// Import analysis (if PE file)
	if analysis.PEAnalysis != nil {
		importAnalysis := rs.analyzeImports(analysis.PEAnalysis.Imports)
		analysis.ImportAnalysis = *importAnalysis
	}

	// Calculate threat score and indicators
	analysis.ThreatScore = rs.calculateThreatScore(analysis)
	analysis.Indicators = rs.generateThreatIndicators(analysis)
	analysis.Recommendations = rs.generateRecommendations(analysis)

	return analysis, nil
}

func (rs *ReverseScanner) analyzeFileInfo(filePath string) (*FileInfo, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return nil, err
	}

	// Calculate hashes
	md5Hash := md5.New()
	sha256Hash := sha256.New()
	
	file.Seek(0, 0)
	if _, err := io.Copy(io.MultiWriter(md5Hash, sha256Hash), file); err != nil {
		return nil, err
	}

	return &FileInfo{
		Filename: filepath.Base(filePath),
		Size:     stat.Size(),
		MD5:      hex.EncodeToString(md5Hash.Sum(nil)),
		SHA256:   hex.EncodeToString(sha256Hash.Sum(nil)),
		FileType: rs.detectFileType(filePath),
	}, nil
}

func (rs *ReverseScanner) detectFileType(filePath string) string {
	file, err := os.Open(filePath)
	if err != nil {
		return "Unknown"
	}
	defer file.Close()

	header := make([]byte, 16)
	file.Read(header)

	if len(header) >= 2 && header[0] == 0x4D && header[1] == 0x5A {
		return "PE (Windows Executable)"
	} else if len(header) >= 4 && string(header[:4]) == "\x7fELF" {
		return "ELF (Linux Executable)"
	} else if len(header) >= 4 && 
		(header[0] == 0xFE && header[1] == 0xED && header[2] == 0xFA) {
		return "Mach-O (macOS Executable)"
	}

	return "Unknown Binary"
}

func (rs *ReverseScanner) analyzePE(filePath string) (*PEAnalysis, error) {
	file, err := pe.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	analysis := &PEAnalysis{
		Architecture: rs.getArchitecture(file),
		EntryPoint:   fmt.Sprintf("0x%x", file.OptionalHeader.(*pe.OptionalHeader32).AddressOfEntryPoint),
	}

	// Analyze sections
	for _, section := range file.Sections {
		sec := Section{
			Name:        strings.TrimRight(string(section.Name[:]), "\x00"),
			VirtualSize: section.VirtualSize,
			RawSize:     section.Size,
			Permissions: rs.getSectionPermissions(section.Characteristics),
		}

		// Check for packer signatures
		for _, sig := range rs.packerSignatures {
			if strings.Contains(sec.Name, sig) {
				analysis.IsPacked = true
				analysis.PackerSignature = sig
				sec.Suspicious = true
				break
			}
		}

		// Calculate entropy (simplified)
		sec.Entropy = rs.calculateEntropy(section)
		if sec.Entropy > 7.0 {
			sec.Suspicious = true
		}

		analysis.Sections = append(analysis.Sections, sec)
	}

	// Analyze imports
	imports, err := file.ImportedSymbols()
	if err == nil {
		importMap := make(map[string][]string)
		for _, imp := range imports {
			parts := strings.Split(imp, ":")
			if len(parts) == 2 {
				dll := parts[0]
				function := parts[1]
				importMap[dll] = append(importMap[dll], function)
			}
		}

		for dll, functions := range importMap {
			imp := Import{
				DLL:       dll,
				Functions: functions,
			}

			// Check for suspicious APIs
			for _, function := range functions {
				if _, exists := rs.suspiciousAPIs[function]; exists {
					imp.Suspicious = true
					break
				}
			}

			analysis.Imports = append(analysis.Imports, imp)
		}
	}

	return analysis, nil
}

func (rs *ReverseScanner) analyzeStrings(filePath string) (*StringAnalysis, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	content, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	analysis := &StringAnalysis{}

	// Extract printable strings
	strings := rs.extractStrings(content)
	analysis.TotalStrings = len(strings)

	// Analyze string patterns
	urlPattern := regexp.MustCompile(`https?://[^\s]+`)
	ipPattern := regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)
	pathPattern := regexp.MustCompile(`[A-Za-z]:\\[^\\/:*?"<>|\r\n]+`)
	regPattern := regexp.MustCompile(`HKEY_[A-Z_]+\\[^\\/:*?"<>|\r\n]+`)

	for _, str := range strings {
		if urlPattern.MatchString(str) {
			analysis.URLs = append(analysis.URLs, str)
		}
		if ipPattern.MatchString(str) {
			analysis.IPAddresses = append(analysis.IPAddresses, str)
		}
		if pathPattern.MatchString(str) {
			analysis.FilePaths = append(analysis.FilePaths, str)
		}
		if regPattern.MatchString(str) {
			analysis.RegistryKeys = append(analysis.RegistryKeys, str)
		}

		// Check crypto patterns
		for _, pattern := range rs.cryptoPatterns {
			if pattern.MatchString(str) {
				analysis.CryptoStrings = append(analysis.CryptoStrings, str)
				break
			}
		}

		// Check suspicious strings
		suspiciousKeywords := []string{
			"backdoor", "trojan", "virus", "malware", "keylog",
			"password", "credential", "exploit", "payload",
		}
		lowerStr := strings.ToLower(str)
		for _, keyword := range suspiciousKeywords {
			if strings.Contains(lowerStr, keyword) {
				analysis.SuspiciousStrings = append(analysis.SuspiciousStrings, str)
				break
			}
		}
	}

	return analysis, nil
}

func (rs *ReverseScanner) analyzeImports(imports []Import) *ImportAnalysis {
	analysis := &ImportAnalysis{
		TotalImports: len(imports),
	}

	for _, imp := range imports {
		for _, function := range imp.Functions {
			// Categorize APIs
			if threat, exists := rs.suspiciousAPIs[function]; exists {
				analysis.SuspiciousAPIs = append(analysis.SuspiciousAPIs, 
					fmt.Sprintf("%s (%s)", function, threat))
			}

			if rs.isCryptoAPI(function) {
				analysis.CryptoAPIs = append(analysis.CryptoAPIs, function)
			}
			if rs.isNetworkAPI(function) {
				analysis.NetworkAPIs = append(analysis.NetworkAPIs, function)
			}
			if rs.isFileAPI(function) {
				analysis.FileAPIs = append(analysis.FileAPIs, function)
			}
			if rs.isProcessAPI(function) {
				analysis.ProcessAPIs = append(analysis.ProcessAPIs, function)
			}
		}
	}

	return analysis
}

func (rs *ReverseScanner) calculateThreatScore(analysis *ReverseAnalysis) int {
	score := 0

	// File size factor
	if analysis.FileInfo.Size > 10*1024*1024 { // > 10MB
		score += 10
	}

	// PE analysis factors
	if analysis.PEAnalysis != nil {
		if analysis.PEAnalysis.IsPacked {
			score += 30
		}

		// Suspicious sections
		for _, section := range analysis.PEAnalysis.Sections {
			if section.Suspicious {
				score += 15
			}
		}

		// Suspicious imports
		for _, imp := range analysis.PEAnalysis.Imports {
			if imp.Suspicious {
				score += 20
			}
		}
	}

	// String analysis factors
	score += len(analysis.StringAnalysis.URLs) * 5
	score += len(analysis.StringAnalysis.IPAddresses) * 3
	score += len(analysis.StringAnalysis.SuspiciousStrings) * 10
	score += len(analysis.StringAnalysis.CryptoStrings) * 2

	// Import analysis factors
	score += len(analysis.ImportAnalysis.SuspiciousAPIs) * 15
	score += len(analysis.ImportAnalysis.CryptoAPIs) * 5

	// Cap at 100
	if score > 100 {
		score = 100
	}

	return score
}

func (rs *ReverseScanner) generateThreatIndicators(analysis *ReverseAnalysis) []ThreatIndicator {
	var indicators []ThreatIndicator

	// Packer detection
	if analysis.PEAnalysis != nil && analysis.PEAnalysis.IsPacked {
		indicators = append(indicators, ThreatIndicator{
			Type:        "Packer Detection",
			Description: fmt.Sprintf("File is packed with %s", analysis.PEAnalysis.PackerSignature),
			Severity:    "Medium",
			Confidence:  0.9,
		})
	}

	// Suspicious APIs
	if len(analysis.ImportAnalysis.SuspiciousAPIs) > 0 {
		indicators = append(indicators, ThreatIndicator{
			Type:        "Suspicious API Usage",
			Description: fmt.Sprintf("Uses %d suspicious APIs", len(analysis.ImportAnalysis.SuspiciousAPIs)),
			Severity:    "High",
			Confidence:  0.8,
		})
	}

	// Network indicators
	if len(analysis.StringAnalysis.URLs) > 0 || len(analysis.StringAnalysis.IPAddresses) > 0 {
		indicators = append(indicators, ThreatIndicator{
			Type:        "Network Indicators",
			Description: "Contains network-related strings",
			Severity:    "Medium",
			Confidence:  0.7,
		})
	}

	// Crypto usage
	if len(analysis.ImportAnalysis.CryptoAPIs) > 0 || len(analysis.StringAnalysis.CryptoStrings) > 0 {
		indicators = append(indicators, ThreatIndicator{
			Type:        "Cryptographic Usage",
			Description: "Uses cryptographic functions",
			Severity:    "Low",
			Confidence:  0.6,
		})
	}

	return indicators
}

func (rs *ReverseScanner) generateRecommendations(analysis *ReverseAnalysis) []string {
	var recommendations []string

	if analysis.ThreatScore >= 80 {
		recommendations = append(recommendations, "CRITICAL: Quarantine file immediately")
		recommendations = append(recommendations, "Perform dynamic analysis in sandbox")
		recommendations = append(recommendations, "Check for system compromise")
	} else if analysis.ThreatScore >= 60 {
		recommendations = append(recommendations, "HIGH: Isolate and analyze further")
		recommendations = append(recommendations, "Monitor network traffic")
		recommendations = append(recommendations, "Scan with multiple AV engines")
	} else if analysis.ThreatScore >= 40 {
		recommendations = append(recommendations, "MEDIUM: Continue monitoring")
		recommendations = append(recommendations, "Update security signatures")
	} else {
		recommendations = append(recommendations, "LOW: File appears benign")
	}

	if analysis.PEAnalysis != nil && analysis.PEAnalysis.IsPacked {
		recommendations = append(recommendations, "Unpack binary for deeper analysis")
	}

	if len(analysis.StringAnalysis.URLs) > 0 {
		recommendations = append(recommendations, "Monitor network connections to identified URLs")
	}

	return recommendations
}

// Helper functions
func (rs *ReverseScanner) getArchitecture(file *pe.File) string {
	switch file.FileHeader.Machine {
	case pe.IMAGE_FILE_MACHINE_I386:
		return "x86"
	case pe.IMAGE_FILE_MACHINE_AMD64:
		return "x64"
	case pe.IMAGE_FILE_MACHINE_ARM:
		return "ARM"
	default:
		return "Unknown"
	}
}

func (rs *ReverseScanner) getSectionPermissions(characteristics uint32) string {
	var perms []string
	if characteristics&pe.IMAGE_SCN_MEM_READ != 0 {
		perms = append(perms, "R")
	}
	if characteristics&pe.IMAGE_SCN_MEM_WRITE != 0 {
		perms = append(perms, "W")
	}
	if characteristics&pe.IMAGE_SCN_MEM_EXECUTE != 0 {
		perms = append(perms, "X")
	}
	return strings.Join(perms, "")
}

func (rs *ReverseScanner) calculateEntropy(section *pe.Section) float64 {
	// Simplified entropy calculation
	return 6.5 // Mock value
}

func (rs *ReverseScanner) extractStrings(content []byte) []string {
	var strings []string
	var current []byte

	for _, b := range content {
		if b >= 32 && b <= 126 { // Printable ASCII
			current = append(current, b)
		} else {
			if len(current) >= 4 {
				strings = append(strings, string(current))
			}
			current = nil
		}
	}

	if len(current) >= 4 {
		strings = append(strings, string(current))
	}

	return strings
}

func (rs *ReverseScanner) isCryptoAPI(function string) bool {
	cryptoAPIs := []string{
		"CryptEncrypt", "CryptDecrypt", "CryptGenKey", "CryptCreateHash",
		"CryptHashData", "CryptSignHash", "CryptVerifySignature",
	}
	for _, api := range cryptoAPIs {
		if strings.Contains(function, api) {
			return true
		}
	}
	return false
}

func (rs *ReverseScanner) isNetworkAPI(function string) bool {
	networkAPIs := []string{
		"socket", "connect", "send", "recv", "WSAStartup", "WSASocket",
		"InternetOpen", "InternetConnect", "HttpOpenRequest",
	}
	for _, api := range networkAPIs {
		if strings.Contains(function, api) {
			return true
		}
	}
	return false
}

func (rs *ReverseScanner) isFileAPI(function string) bool {
	fileAPIs := []string{
		"CreateFile", "ReadFile", "WriteFile", "DeleteFile", "CopyFile",
		"MoveFile", "FindFirstFile", "FindNextFile",
	}
	for _, api := range fileAPIs {
		if strings.Contains(function, api) {
			return true
		}
	}
	return false
}

func (rs *ReverseScanner) isProcessAPI(function string) bool {
	processAPIs := []string{
		"CreateProcess", "OpenProcess", "TerminateProcess", "GetCurrentProcess",
		"CreateRemoteThread", "VirtualAlloc", "VirtualProtect",
	}
	for _, api := range processAPIs {
		if strings.Contains(function, api) {
			return true
		}
	}
	return false
}

// Main function for command-line usage
func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: reverse_scanner <file_path>")
		os.Exit(1)
	}

	scanner := NewReverseScanner()
	analysis, err := scanner.AnalyzeFile(os.Args[1])
	if err != nil {
		log.Fatalf("Analysis failed: %v", err)
	}

	// Output JSON
	output, err := json.MarshalIndent(analysis, "", "  ")
	if err != nil {
		log.Fatalf("JSON encoding failed: %v", err)
	}

	fmt.Println(string(output))
}