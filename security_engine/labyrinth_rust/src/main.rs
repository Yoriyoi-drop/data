use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::thread;
use std::net::{TcpListener, TcpStream};
use std::io::{Read, Write};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use rand::Rng;
use sha2::{Sha256, Digest};
use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, NewAead}};
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use ring::rand::SystemRandom;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntel {
    pub id: String,
    pub timestamp: u64,
    pub source_ip: String,
    pub threat_type: ThreatType,
    pub severity: Severity,
    pub payload: String,
    pub confidence: f64,
    pub geolocation: Option<GeoLocation>,
    pub attack_vector: AttackVector,
    pub mitigation_applied: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatType {
    SQLInjection,
    XSS,
    CommandInjection,
    PathTraversal,
    BufferOverflow,
    DDoS,
    BruteForce,
    Malware,
    Phishing,
    APT,
    ZeroDay,
    Ransomware,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
    Catastrophic,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AttackVector {
    Network,
    Web,
    Email,
    USB,
    Wireless,
    Social,
    Physical,
    Supply Chain,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoLocation {
    pub country: String,
    pub city: String,
    pub latitude: f64,
    pub longitude: f64,
    pub isp: String,
}

#[derive(Debug, Clone)]
pub struct DecoySystem {
    pub honeypots: Vec<Honeypot>,
    pub canary_tokens: Vec<CanaryToken>,
    pub fake_services: Vec<FakeService>,
    pub trap_networks: Vec<TrapNetwork>,
}

#[derive(Debug, Clone)]
pub struct Honeypot {
    pub id: String,
    pub service_type: String,
    pub port: u16,
    pub interactions: u64,
    pub last_access: Option<Instant>,
    pub captured_payloads: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct CanaryToken {
    pub token: String,
    pub token_type: String,
    pub created_at: Instant,
    pub accessed: bool,
    pub access_count: u64,
}

#[derive(Debug, Clone)]
pub struct FakeService {
    pub name: String,
    pub version: String,
    pub vulnerabilities: Vec<String>,
    pub response_templates: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct TrapNetwork {
    pub network_range: String,
    pub trap_hosts: Vec<String>,
    pub monitoring_active: bool,
}

pub struct InfiniteLabyrinth {
    threat_db: Arc<RwLock<HashMap<String, ThreatIntel>>>,
    decoy_system: Arc<Mutex<DecoySystem>>,
    active_connections: Arc<Mutex<HashMap<String, ConnectionInfo>>>,
    ml_engine: Arc<Mutex<MLThreatEngine>>,
    quantum_crypto: Arc<Mutex<QuantumCrypto>>,
    blockchain_ledger: Arc<Mutex<BlockchainLedger>>,
    threat_broadcaster: broadcast::Sender<ThreatIntel>,
    performance_metrics: Arc<Mutex<PerformanceMetrics>>,
    adaptive_defense: Arc<Mutex<AdaptiveDefense>>,
}

#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    pub ip: String,
    pub first_seen: Instant,
    pub last_activity: Instant,
    pub request_count: u64,
    pub threat_score: f64,
    pub blocked: bool,
    pub country: Option<String>,
}

pub struct MLThreatEngine {
    pub neural_network: NeuralNetwork,
    pub feature_extractors: Vec<FeatureExtractor>,
    pub threat_patterns: HashMap<String, Vec<String>>,
    pub anomaly_detector: AnomalyDetector,
    pub behavioral_analyzer: BehavioralAnalyzer,
}

pub struct NeuralNetwork {
    pub layers: Vec<Layer>,
    pub weights: Vec<Vec<Vec<f64>>>,
    pub biases: Vec<Vec<f64>>,
    pub learning_rate: f64,
}

pub struct Layer {
    pub neurons: usize,
    pub activation: ActivationFunction,
}

#[derive(Debug, Clone)]
pub enum ActivationFunction {
    ReLU,
    Sigmoid,
    Tanh,
    Softmax,
}

pub struct FeatureExtractor {
    pub name: String,
    pub extractor_fn: fn(&str) -> Vec<f64>,
}

pub struct AnomalyDetector {
    pub baseline_metrics: HashMap<String, f64>,
    pub threshold_multiplier: f64,
    pub detection_window: Duration,
}

pub struct BehavioralAnalyzer {
    pub user_profiles: HashMap<String, UserProfile>,
    pub session_patterns: HashMap<String, SessionPattern>,
}

#[derive(Debug, Clone)]
pub struct UserProfile {
    pub user_id: String,
    pub typical_hours: Vec<u8>,
    pub common_ips: HashSet<String>,
    pub usual_user_agents: HashSet<String>,
    pub average_session_duration: Duration,
    pub risk_score: f64,
}

#[derive(Debug, Clone)]
pub struct SessionPattern {
    pub session_id: String,
    pub start_time: Instant,
    pub actions: Vec<UserAction>,
    pub anomaly_score: f64,
}

#[derive(Debug, Clone)]
pub struct UserAction {
    pub timestamp: Instant,
    pub action_type: String,
    pub resource: String,
    pub success: bool,
}

pub struct QuantumCrypto {
    pub quantum_keys: HashMap<String, Vec<u8>>,
    pub entangled_pairs: Vec<(String, String)>,
    pub quantum_random: SystemRandom,
}

pub struct BlockchainLedger {
    pub blocks: Vec<Block>,
    pub pending_transactions: Vec<Transaction>,
    pub difficulty: u32,
    pub mining_reward: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub index: u64,
    pub timestamp: u64,
    pub transactions: Vec<Transaction>,
    pub previous_hash: String,
    pub hash: String,
    pub nonce: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub id: String,
    pub threat_data: ThreatIntel,
    pub validator: String,
    pub signature: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone)]
pub struct PerformanceMetrics {
    pub requests_per_second: f64,
    pub average_response_time: Duration,
    pub memory_usage: u64,
    pub cpu_usage: f64,
    pub threat_detection_rate: f64,
    pub false_positive_rate: f64,
    pub uptime: Duration,
    pub start_time: Instant,
}

pub struct AdaptiveDefense {
    pub defense_strategies: HashMap<String, DefenseStrategy>,
    pub active_countermeasures: Vec<Countermeasure>,
    pub threat_intelligence_feeds: Vec<ThreatFeed>,
    pub auto_response_rules: Vec<ResponseRule>,
}

#[derive(Debug, Clone)]
pub struct DefenseStrategy {
    pub name: String,
    pub effectiveness: f64,
    pub resource_cost: u32,
    pub activation_threshold: f64,
    pub cooldown: Duration,
    pub last_used: Option<Instant>,
}

#[derive(Debug, Clone)]
pub struct Countermeasure {
    pub id: String,
    pub measure_type: CountermeasureType,
    pub target: String,
    pub duration: Duration,
    pub effectiveness: f64,
    pub activated_at: Instant,
}

#[derive(Debug, Clone)]
pub enum CountermeasureType {
    IPBlock,
    RateLimit,
    TrafficRedirect,
    DecoyDeployment,
    NetworkSegmentation,
    ServiceDisable,
    AlertEscalation,
}

#[derive(Debug, Clone)]
pub struct ThreatFeed {
    pub source: String,
    pub url: String,
    pub last_updated: Instant,
    pub indicators: Vec<ThreatIndicator>,
    pub reliability_score: f64,
}

#[derive(Debug, Clone)]
pub struct ThreatIndicator {
    pub indicator_type: String,
    pub value: String,
    pub confidence: f64,
    pub first_seen: Instant,
    pub last_seen: Instant,
}

#[derive(Debug, Clone)]
pub struct ResponseRule {
    pub id: String,
    pub condition: String,
    pub action: String,
    pub priority: u8,
    pub enabled: bool,
    pub execution_count: u64,
}

impl InfiniteLabyrinth {
    pub fn new() -> Self {
        let (tx, _rx) = broadcast::channel(1000);
        
        let mut labyrinth = InfiniteLabyrinth {
            threat_db: Arc::new(RwLock::new(HashMap::new())),
            decoy_system: Arc::new(Mutex::new(DecoySystem::new())),
            active_connections: Arc::new(Mutex::new(HashMap::new())),
            ml_engine: Arc::new(Mutex::new(MLThreatEngine::new())),
            quantum_crypto: Arc::new(Mutex::new(QuantumCrypto::new())),
            blockchain_ledger: Arc::new(Mutex::new(BlockchainLedger::new())),
            threat_broadcaster: tx,
            performance_metrics: Arc::new(Mutex::new(PerformanceMetrics::new())),
            adaptive_defense: Arc::new(Mutex::new(AdaptiveDefense::new())),
        };
        
        labyrinth.initialize_systems();
        labyrinth
    }
    
    fn initialize_systems(&mut self) {
        // Initialize honeypots
        self.deploy_honeypots();
        
        // Initialize ML models
        self.train_ml_models();
        
        // Initialize quantum crypto
        self.setup_quantum_crypto();
        
        // Initialize blockchain
        self.initialize_blockchain();
        
        // Start background tasks
        self.start_background_tasks();
    }
    
    fn deploy_honeypots(&self) {
        let mut decoy_system = self.decoy_system.lock().unwrap();
        
        // Deploy various honeypots
        let honeypots = vec![
            Honeypot {
                id: "ssh-honeypot-1".to_string(),
                service_type: "SSH".to_string(),
                port: 22,
                interactions: 0,
                last_access: None,
                captured_payloads: Vec::new(),
            },
            Honeypot {
                id: "web-honeypot-1".to_string(),
                service_type: "HTTP".to_string(),
                port: 80,
                interactions: 0,
                last_access: None,
                captured_payloads: Vec::new(),
            },
            Honeypot {
                id: "ftp-honeypot-1".to_string(),
                service_type: "FTP".to_string(),
                port: 21,
                interactions: 0,
                last_access: None,
                captured_payloads: Vec::new(),
            },
        ];
        
        decoy_system.honeypots = honeypots;
        
        // Deploy canary tokens
        let canary_tokens = vec![
            CanaryToken {
                token: "admin_secret_key_12345".to_string(),
                token_type: "API Key".to_string(),
                created_at: Instant::now(),
                accessed: false,
                access_count: 0,
            },
            CanaryToken {
                token: "db_password_prod_2024".to_string(),
                token_type: "Database Password".to_string(),
                created_at: Instant::now(),
                accessed: false,
                access_count: 0,
            },
        ];
        
        decoy_system.canary_tokens = canary_tokens;
    }
    
    fn train_ml_models(&self) {
        let mut ml_engine = self.ml_engine.lock().unwrap();
        
        // Initialize neural network
        ml_engine.neural_network = NeuralNetwork {
            layers: vec![
                Layer { neurons: 100, activation: ActivationFunction::ReLU },
                Layer { neurons: 50, activation: ActivationFunction::ReLU },
                Layer { neurons: 25, activation: ActivationFunction::ReLU },
                Layer { neurons: 10, activation: ActivationFunction::Softmax },
            ],
            weights: Vec::new(),
            biases: Vec::new(),
            learning_rate: 0.001,
        };
        
        // Initialize feature extractors
        ml_engine.feature_extractors = vec![
            FeatureExtractor {
                name: "payload_length".to_string(),
                extractor_fn: |payload| vec![payload.len() as f64 / 1000.0],
            },
            FeatureExtractor {
                name: "special_chars".to_string(),
                extractor_fn: |payload| {
                    let special_count = payload.chars()
                        .filter(|c| "'\";|&<>(){}[]".contains(*c))
                        .count();
                    vec![special_count as f64 / payload.len() as f64]
                },
            },
        ];
        
        // Initialize threat patterns
        let mut patterns = HashMap::new();
        patterns.insert("sql_injection".to_string(), vec![
            "' OR '1'='1".to_string(),
            "UNION SELECT".to_string(),
            "DROP TABLE".to_string(),
            "INSERT INTO".to_string(),
        ]);
        patterns.insert("xss".to_string(), vec![
            "<script>".to_string(),
            "javascript:".to_string(),
            "onload=".to_string(),
            "eval(".to_string(),
        ]);
        
        ml_engine.threat_patterns = patterns;
    }
    
    fn setup_quantum_crypto(&self) {
        let mut quantum_crypto = self.quantum_crypto.lock().unwrap();
        
        // Generate quantum keys
        let mut quantum_keys = HashMap::new();
        let rng = SystemRandom::new();
        
        for i in 0..10 {
            let mut key = vec![0u8; 32];
            ring::rand::SecureRandom::fill(&rng, &mut key).unwrap();
            quantum_keys.insert(format!("quantum_key_{}", i), key);
        }
        
        quantum_crypto.quantum_keys = quantum_keys;
        quantum_crypto.quantum_random = rng;
    }
    
    fn initialize_blockchain(&self) {
        let mut blockchain = self.blockchain_ledger.lock().unwrap();
        
        // Create genesis block
        let genesis_block = Block {
            index: 0,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            transactions: Vec::new(),
            previous_hash: "0".to_string(),
            hash: "genesis_hash".to_string(),
            nonce: 0,
        };
        
        blockchain.blocks.push(genesis_block);
        blockchain.difficulty = 4;
        blockchain.mining_reward = 100;
    }
    
    fn start_background_tasks(&self) {
        // Start threat intelligence updates
        let threat_db = Arc::clone(&self.threat_db);
        thread::spawn(move || {
            loop {
                // Update threat intelligence
                thread::sleep(Duration::from_secs(300)); // Every 5 minutes
                // Implementation for threat intel updates
            }
        });
        
        // Start performance monitoring
        let metrics = Arc::clone(&self.performance_metrics);
        thread::spawn(move || {
            loop {
                thread::sleep(Duration::from_secs(60)); // Every minute
                let mut perf = metrics.lock().unwrap();
                perf.uptime = perf.start_time.elapsed();
                // Update other metrics
            }
        });
        
        // Start adaptive defense
        let adaptive_defense = Arc::clone(&self.adaptive_defense);
        thread::spawn(move || {
            loop {
                thread::sleep(Duration::from_secs(30)); // Every 30 seconds
                // Evaluate and adapt defense strategies
            }
        });
    }
    
    pub async fn analyze_threat(&self, payload: &str, source_ip: &str) -> ThreatIntel {
        let start_time = Instant::now();
        
        // Extract features using ML engine
        let ml_engine = self.ml_engine.lock().unwrap();
        let mut features = Vec::new();
        
        for extractor in &ml_engine.feature_extractors {
            let extracted = (extractor.extractor_fn)(payload);
            features.extend(extracted);
        }
        
        // Pattern matching
        let mut threat_type = ThreatType::SQLInjection;
        let mut confidence = 0.0;
        
        for (pattern_type, patterns) in &ml_engine.threat_patterns {
            for pattern in patterns {
                if payload.to_lowercase().contains(&pattern.to_lowercase()) {
                    confidence = 0.8;
                    threat_type = match pattern_type.as_str() {
                        "sql_injection" => ThreatType::SQLInjection,
                        "xss" => ThreatType::XSS,
                        _ => ThreatType::SQLInjection,
                    };
                    break;
                }
            }
        }
        
        // Neural network prediction
        let nn_confidence = self.neural_network_predict(&features);
        if nn_confidence > confidence {
            confidence = nn_confidence;
        }
        
        // Behavioral analysis
        let behavioral_score = self.analyze_behavior(source_ip, payload).await;
        confidence = (confidence + behavioral_score) / 2.0;
        
        // Determine severity
        let severity = match confidence {
            c if c > 0.9 => Severity::Catastrophic,
            c if c > 0.8 => Severity::Critical,
            c if c > 0.6 => Severity::High,
            c if c > 0.4 => Severity::Medium,
            _ => Severity::Low,
        };
        
        let threat_intel = ThreatIntel {
            id: format!("threat_{}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()),
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            source_ip: source_ip.to_string(),
            threat_type,
            severity,
            payload: payload.to_string(),
            confidence,
            geolocation: self.get_geolocation(source_ip).await,
            attack_vector: AttackVector::Web,
            mitigation_applied: false,
        };
        
        // Store in threat database
        {
            let mut db = self.threat_db.write().unwrap();
            db.insert(threat_intel.id.clone(), threat_intel.clone());
        }
        
        // Broadcast threat
        let _ = self.threat_broadcaster.send(threat_intel.clone());
        
        // Apply countermeasures if needed
        if confidence > 0.7 {
            self.apply_countermeasures(&threat_intel).await;
        }
        
        // Update performance metrics
        {
            let mut metrics = self.performance_metrics.lock().unwrap();
            metrics.average_response_time = start_time.elapsed();
            metrics.threat_detection_rate += 1.0;
        }
        
        threat_intel
    }
    
    fn neural_network_predict(&self, features: &[f64]) -> f64 {
        // Simplified neural network prediction
        let mut output = 0.0;
        for (i, &feature) in features.iter().enumerate() {
            output += feature * (0.5 + (i as f64 * 0.1));
        }
        
        // Sigmoid activation
        1.0 / (1.0 + (-output).exp())
    }
    
    async fn analyze_behavior(&self, source_ip: &str, payload: &str) -> f64 {
        let mut connections = self.active_connections.lock().unwrap();
        
        let now = Instant::now();
        let connection = connections.entry(source_ip.to_string()).or_insert(ConnectionInfo {
            ip: source_ip.to_string(),
            first_seen: now,
            last_activity: now,
            request_count: 0,
            threat_score: 0.0,
            blocked: false,
            country: None,
        });
        
        connection.last_activity = now;
        connection.request_count += 1;
        
        // Calculate behavioral score
        let mut score = 0.0;
        
        // Frequency analysis
        if connection.request_count > 100 {
            score += 0.3;
        }
        
        // Time-based analysis
        let session_duration = now.duration_since(connection.first_seen);
        if session_duration < Duration::from_secs(60) && connection.request_count > 50 {
            score += 0.4; // Rapid requests
        }
        
        // Payload analysis
        if payload.len() > 1000 {
            score += 0.2;
        }
        
        connection.threat_score = score;
        score
    }
    
    async fn get_geolocation(&self, _ip: &str) -> Option<GeoLocation> {
        // Simplified geolocation
        Some(GeoLocation {
            country: "Unknown".to_string(),
            city: "Unknown".to_string(),
            latitude: 0.0,
            longitude: 0.0,
            isp: "Unknown".to_string(),
        })
    }
    
    async fn apply_countermeasures(&self, threat: &ThreatIntel) {
        let mut adaptive_defense = self.adaptive_defense.lock().unwrap();
        
        let countermeasure = Countermeasure {
            id: format!("counter_{}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()),
            measure_type: match threat.severity {
                Severity::Critical | Severity::Catastrophic => CountermeasureType::IPBlock,
                Severity::High => CountermeasureType::RateLimit,
                _ => CountermeasureType::AlertEscalation,
            },
            target: threat.source_ip.clone(),
            duration: Duration::from_secs(3600), // 1 hour
            effectiveness: threat.confidence,
            activated_at: Instant::now(),
        };
        
        adaptive_defense.active_countermeasures.push(countermeasure);
    }
    
    pub fn get_performance_metrics(&self) -> PerformanceMetrics {
        self.performance_metrics.lock().unwrap().clone()
    }
    
    pub fn get_threat_statistics(&self) -> HashMap<String, u64> {
        let db = self.threat_db.read().unwrap();
        let mut stats = HashMap::new();
        
        for threat in db.values() {
            let threat_type = format!("{:?}", threat.threat_type);
            *stats.entry(threat_type).or_insert(0) += 1;
        }
        
        stats
    }
}

// Implementation for supporting structures
impl DecoySystem {
    fn new() -> Self {
        DecoySystem {
            honeypots: Vec::new(),
            canary_tokens: Vec::new(),
            fake_services: Vec::new(),
            trap_networks: Vec::new(),
        }
    }
}

impl MLThreatEngine {
    fn new() -> Self {
        MLThreatEngine {
            neural_network: NeuralNetwork {
                layers: Vec::new(),
                weights: Vec::new(),
                biases: Vec::new(),
                learning_rate: 0.001,
            },
            feature_extractors: Vec::new(),
            threat_patterns: HashMap::new(),
            anomaly_detector: AnomalyDetector {
                baseline_metrics: HashMap::new(),
                threshold_multiplier: 2.0,
                detection_window: Duration::from_secs(300),
            },
            behavioral_analyzer: BehavioralAnalyzer {
                user_profiles: HashMap::new(),
                session_patterns: HashMap::new(),
            },
        }
    }
}

impl QuantumCrypto {
    fn new() -> Self {
        QuantumCrypto {
            quantum_keys: HashMap::new(),
            entangled_pairs: Vec::new(),
            quantum_random: SystemRandom::new(),
        }
    }
}

impl BlockchainLedger {
    fn new() -> Self {
        BlockchainLedger {
            blocks: Vec::new(),
            pending_transactions: Vec::new(),
            difficulty: 4,
            mining_reward: 100,
        }
    }
}

impl PerformanceMetrics {
    fn new() -> Self {
        PerformanceMetrics {
            requests_per_second: 0.0,
            average_response_time: Duration::from_millis(0),
            memory_usage: 0,
            cpu_usage: 0.0,
            threat_detection_rate: 0.0,
            false_positive_rate: 0.0,
            uptime: Duration::from_secs(0),
            start_time: Instant::now(),
        }
    }
}

impl AdaptiveDefense {
    fn new() -> Self {
        let mut defense_strategies = HashMap::new();
        
        defense_strategies.insert("ip_blocking".to_string(), DefenseStrategy {
            name: "IP Blocking".to_string(),
            effectiveness: 0.9,
            resource_cost: 1,
            activation_threshold: 0.8,
            cooldown: Duration::from_secs(300),
            last_used: None,
        });
        
        defense_strategies.insert("rate_limiting".to_string(), DefenseStrategy {
            name: "Rate Limiting".to_string(),
            effectiveness: 0.7,
            resource_cost: 2,
            activation_threshold: 0.6,
            cooldown: Duration::from_secs(60),
            last_used: None,
        });
        
        AdaptiveDefense {
            defense_strategies,
            active_countermeasures: Vec::new(),
            threat_intelligence_feeds: Vec::new(),
            auto_response_rules: Vec::new(),
        }
    }
}

#[tokio::main]
async fn main() {
    println!("🦀 Infinite Labyrinth Rust Defense System Starting...");
    
    let labyrinth = InfiniteLabyrinth::new();
    
    // Start HTTP server
    let listener = TcpListener::bind("127.0.0.1:8081").unwrap();
    println!("🚀 Rust Labyrinth Defense listening on 127.0.0.1:8081");
    
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let labyrinth_clone = Arc::new(labyrinth);
                tokio::spawn(async move {
                    handle_connection(stream, labyrinth_clone).await;
                });
            }
            Err(e) => {
                eprintln!("Connection failed: {}", e);
            }
        }
    }
}

async fn handle_connection(mut stream: TcpStream, labyrinth: Arc<InfiniteLabyrinth>) {
    let mut buffer = [0; 1024];
    
    match stream.read(&mut buffer) {
        Ok(size) => {
            let request = String::from_utf8_lossy(&buffer[..size]);
            
            if request.contains("GET /analyze") {
                let payload = extract_payload(&request);
                let source_ip = stream.peer_addr().unwrap().ip().to_string();
                
                let threat_intel = labyrinth.analyze_threat(&payload, &source_ip).await;
                
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}",
                    serde_json::to_string(&threat_intel).unwrap()
                );
                
                let _ = stream.write(response.as_bytes());
            } else if request.contains("GET /stats") {
                let stats = labyrinth.get_threat_statistics();
                let metrics = labyrinth.get_performance_metrics();
                
                let response_data = serde_json::json!({
                    "threat_statistics": stats,
                    "performance_metrics": {
                        "uptime_seconds": metrics.uptime.as_secs(),
                        "requests_per_second": metrics.requests_per_second,
                        "average_response_time_ms": metrics.average_response_time.as_millis(),
                        "threat_detection_rate": metrics.threat_detection_rate,
                    }
                });
                
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}",
                    response_data
                );
                
                let _ = stream.write(response.as_bytes());
            }
        }
        Err(e) => {
            eprintln!("Failed to read from connection: {}", e);
        }
    }
}

fn extract_payload(request: &str) -> String {
    // Simple payload extraction from query parameters
    if let Some(start) = request.find("payload=") {
        let start = start + 8;
        if let Some(end) = request[start..].find(' ') {
            return request[start..start + end].to_string();
        }
    }
    "test_payload".to_string()
}