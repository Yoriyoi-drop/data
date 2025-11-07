use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::time::sleep;
use rand::{Rng, thread_rng};
use uuid::Uuid;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureLabyrinthNode {
    pub id: String,
    pub node_type: NodeType,
    pub connections: Vec<String>,
    pub trap_level: u8,
    pub security_hash: String,
    pub created_at: u64,
    pub access_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NodeType {
    Entry,
    DecoyDatabase,
    HoneyTrap,
    InfiniteLoop,
    FakeData,
    SecurityBarrier,
    Exit,
}

#[derive(Debug, Clone)]
pub struct IntruderSession {
    pub id: String,
    pub ip_hash: String,
    pub current_node: String,
    pub path_history: Vec<String>,
    pub trap_count: u32,
    pub data_fed: u32,
    pub start_time: Instant,
    pub threat_level: u8,
}

pub struct InfiniteSecureLabyrinth {
    nodes: Arc<Mutex<HashMap<String, SecureLabyrinthNode>>>,
    active_intruders: Arc<Mutex<HashMap<String, IntruderSession>>>,
    fake_data_pool: Arc<Mutex<Vec<String>>>,
    generation_rate: Duration,
    max_nodes: usize,
    security_key: String,
}

impl InfiniteSecureLabyrinth {
    pub fn new(max_nodes: usize) -> Self {
        let security_key = format!("{:x}", Sha256::digest(b"infinite_security_2024"));
        
        let mut labyrinth = Self {
            nodes: Arc::new(Mutex::new(HashMap::new())),
            active_intruders: Arc::new(Mutex::new(HashMap::new())),
            fake_data_pool: Arc::new(Mutex::new(Vec::new())),
            generation_rate: Duration::from_millis(100),
            max_nodes,
            security_key,
        };
        
        labyrinth.generate_initial_structure();
        labyrinth.populate_fake_data();
        labyrinth
    }
    
    fn generate_initial_structure(&mut self) {
        let mut nodes = self.nodes.lock().unwrap();
        
        // Create secure entry node
        let entry_id = self.generate_secure_id();
        let entry_node = SecureLabyrinthNode {
            id: entry_id.clone(),
            node_type: NodeType::Entry,
            connections: vec![],
            trap_level: 0,
            security_hash: self.generate_security_hash(&entry_id),
            created_at: self.current_timestamp(),
            access_count: 0,
        };
        nodes.insert(entry_id.clone(), entry_node);
        
        // Generate initial maze structure
        for _ in 0..50 {
            self.generate_connected_node_internal(&entry_id, &mut nodes);
        }
    }
    
    fn populate_fake_data(&self) {
        let mut fake_data = self.fake_data_pool.lock().unwrap();
        
        // Generate realistic fake database responses
        let fake_responses = vec![
            r#"{"users": [{"id": 1, "name": "admin", "role": "user"}]}"#,
            r#"{"error": "Access denied", "code": 403}"#,
            r#"{"data": "Loading...", "status": "processing"}"#,
            r#"{"result": [], "count": 0, "message": "No data found"}"#,
            r#"{"session": "expired", "redirect": "/login"}"#,
        ];
        
        for response in fake_responses {
            fake_data.push(response.to_string());
        }
    }
    
    fn generate_connected_node_internal(
        &self, 
        parent_id: &str, 
        nodes: &mut HashMap<String, SecureLabyrinthNode>
    ) -> String {
        let node_id = self.generate_secure_id();
        let mut rng = thread_rng();
        
        let node_type = match rng.gen_range(0..6) {
            0 => NodeType::DecoyDatabase,
            1 => NodeType::HoneyTrap,
            2 => NodeType::InfiniteLoop,
            3 => NodeType::FakeData,
            4 => NodeType::SecurityBarrier,
            _ => NodeType::Exit,
        };
        
        let node = SecureLabyrinthNode {
            id: node_id.clone(),
            node_type,
            connections: vec![],
            trap_level: rng.gen_range(1..=10),
            security_hash: self.generate_security_hash(&node_id),
            created_at: self.current_timestamp(),
            access_count: 0,
        };
        
        nodes.insert(node_id.clone(), node);
        
        // Connect to parent
        if let Some(parent) = nodes.get_mut(parent_id) {
            parent.connections.push(node_id.clone());
        }
        
        node_id
    }
    
    pub async fn start_infinite_generation(&self) {
        println!("🌀 Infinite Secure Labyrinth Defense ACTIVATED");
        
        loop {
            {
                let mut nodes = self.nodes.lock().unwrap();
                
                // Generate new nodes if under limit
                if nodes.len() < self.max_nodes {
                    let node_ids: Vec<String> = nodes.keys().cloned().collect();
                    
                    for node_id in node_ids.iter().take(5) {
                        if thread_rng().gen_bool(0.3) {
                            self.generate_connected_node_internal(node_id, &mut nodes);
                        }
                    }
                }
                
                // Clean old unused nodes
                self.cleanup_old_nodes(&mut nodes);
            }
            
            // Process active intruders
            self.process_intruders().await;
            
            // Security stats
            let (node_count, intruder_count) = {
                let nodes = self.nodes.lock().unwrap();
                let intruders = self.active_intruders.lock().unwrap();
                (nodes.len(), intruders.len())
            };
            
            println!("🛡️  Labyrinth Stats: {} nodes, {} trapped intruders", 
                    node_count, intruder_count);
            
            sleep(self.generation_rate).await;
        }
    }
    
    fn cleanup_old_nodes(&self, nodes: &mut HashMap<String, SecureLabyrinthNode>) {
        let cutoff_time = self.current_timestamp() - 600; // 10 minutes
        
        nodes.retain(|_, node| {
            matches!(node.node_type, NodeType::Entry) || 
            node.created_at > cutoff_time ||
            node.access_count > 0
        });
    }
    
    async fn process_intruders(&self) {
        let mut intruders = self.active_intruders.lock().unwrap();
        let nodes = self.nodes.lock().unwrap();
        let fake_data = self.fake_data_pool.lock().unwrap();
        
        for (intruder_id, session) in intruders.iter_mut() {
            if let Some(current_node) = nodes.get(&session.current_node) {
                // Move intruder deeper into labyrinth
                if !current_node.connections.is_empty() {
                    let next_idx = thread_rng().gen_range(0..current_node.connections.len());
                    let next_node = current_node.connections[next_idx].clone();
                    
                    session.path_history.push(session.current_node.clone());
                    session.current_node = next_node;
                    session.trap_count += 1;
                    
                    // Feed fake data based on node type
                    match current_node.node_type {
                        NodeType::FakeData | NodeType::DecoyDatabase => {
                            if !fake_data.is_empty() {
                                let data_idx = thread_rng().gen_range(0..fake_data.len());
                                session.data_fed += 1;
                                println!("🎭 Fed fake data to intruder {}: {}", 
                                        intruder_id, &fake_data[data_idx][..50]);
                            }
                        },
                        NodeType::InfiniteLoop => {
                            println!("🌀 Intruder {} caught in infinite loop", intruder_id);
                        },
                        _ => {}
                    }
                    
                    println!("🕷️  Intruder {} moved to trap level {} (fed {} fake responses)", 
                            intruder_id, session.trap_count, session.data_fed);
                }
            }
        }
    }
    
    pub fn add_intruder(&self, source_ip: String, threat_level: u8) -> String {
        let intruder_id = self.generate_secure_id();
        let ip_hash = format!("{:x}", Sha256::digest(source_ip.as_bytes()));
        
        // Find entry node
        let nodes = self.nodes.lock().unwrap();
        let entry_node = nodes.values()
            .find(|n| matches!(n.node_type, NodeType::Entry))
            .map(|n| n.id.clone())
            .unwrap_or_else(|| "default_entry".to_string());
        
        let session = IntruderSession {
            id: intruder_id.clone(),
            ip_hash: ip_hash[..16].to_string(),
            current_node: entry_node,
            path_history: vec![],
            trap_count: 0,
            data_fed: 0,
            start_time: Instant::now(),
            threat_level,
        };
        
        {
            let mut intruders = self.active_intruders.lock().unwrap();
            intruders.insert(intruder_id.clone(), session);
        }
        
        println!("🎯 New intruder {} (threat level {}) entered labyrinth", 
                intruder_id, threat_level);
        
        intruder_id
    }
    
    pub fn get_stats(&self) -> HashMap<String, u32> {
        let nodes = self.nodes.lock().unwrap();
        let intruders = self.active_intruders.lock().unwrap();
        
        let mut stats = HashMap::new();
        stats.insert("total_nodes".to_string(), nodes.len() as u32);
        stats.insert("active_intruders".to_string(), intruders.len() as u32);
        stats.insert("total_traps".to_string(), 
                    intruders.values().map(|i| i.trap_count).sum());
        stats.insert("fake_data_served".to_string(), 
                    intruders.values().map(|i| i.data_fed).sum());
        
        stats
    }
    
    fn generate_secure_id(&self) -> String {
        format!("{}-{}", 
                Uuid::new_v4().to_string()[..8].to_uppercase(),
                thread_rng().gen::<u32>())
    }
    
    fn generate_security_hash(&self, id: &str) -> String {
        let input = format!("{}{}{}", id, self.security_key, self.current_timestamp());
        format!("{:x}", Sha256::digest(input.as_bytes()))[..16].to_string()
    }
    
    fn current_timestamp(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}