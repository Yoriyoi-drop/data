use std::collections::HashMap;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct ThreatDetectionResult {
    pub threat_type: String,
    pub severity: u8,
    pub confidence: f64,
    pub blocked: bool,
    pub details: HashMap<String, String>,
}

pub struct SQLInjectionDetector {
    patterns: Vec<Regex>,
}

impl SQLInjectionDetector {
    pub fn new() -> Self {
        let patterns = vec![
            Regex::new(r"(?i)(union\s+select)").unwrap(),
            Regex::new(r"(?i)(or\s+1\s*=\s*1)").unwrap(),
            Regex::new(r"(?i)(drop\s+table)").unwrap(),
            Regex::new(r"(?i)(insert\s+into)").unwrap(),
            Regex::new(r"(?i)(delete\s+from)").unwrap(),
        ];
        
        Self { patterns }
    }
    
    pub fn detect(&self, input: &str) -> ThreatDetectionResult {
        let mut details = HashMap::new();
        let mut max_severity = 0u8;
        let mut total_matches = 0;
        
        for (i, pattern) in self.patterns.iter().enumerate() {
            if pattern.is_match(input) {
                total_matches += 1;
                let severity = match i {
                    0 | 2 | 4 => 9, // UNION, DROP, DELETE - critical
                    1 => 8,         // OR 1=1 - high
                    3 => 7,         // INSERT - medium-high
                    _ => 5,         // default
                };
                
                if severity > max_severity {
                    max_severity = severity;
                }
                
                details.insert(
                    format!("pattern_{}", i),
                    format!("SQL injection pattern detected: {}", pattern.as_str())
                );
            }
        }
        
        let confidence = if total_matches > 0 {
            (total_matches as f64 * 0.3 + max_severity as f64 * 0.1).min(1.0)
        } else {
            0.0
        };
        
        ThreatDetectionResult {
            threat_type: "sql_injection".to_string(),
            severity: max_severity,
            confidence,
            blocked: max_severity >= 7,
            details,
        }
    }
}

pub struct LabyrinthEngine {
    trap_count: u32,
    active_sessions: HashMap<String, u32>,
}

impl LabyrinthEngine {
    pub fn new() -> Self {
        Self {
            trap_count: 0,
            active_sessions: HashMap::new(),
        }
    }
    
    pub fn create_trap(&mut self, session_id: String) -> u32 {
        self.trap_count += 1;
        self.active_sessions.insert(session_id, self.trap_count);
        self.trap_count
    }
    
    pub fn is_trapped(&self, session_id: &str) -> bool {
        self.active_sessions.contains_key(session_id)
    }
}

#[no_mangle]
pub extern "C" fn detect_sql_injection(input: *const std::os::raw::c_char) -> *mut std::os::raw::c_char {
    use std::ffi::{CStr, CString};
    
    let c_str = unsafe { CStr::from_ptr(input) };
    let input_str = c_str.to_str().unwrap_or("");
    
    let detector = SQLInjectionDetector::new();
    let result = detector.detect(input_str);
    
    let json_result = serde_json::to_string(&result).unwrap_or_default();
    CString::new(json_result).unwrap().into_raw()
}