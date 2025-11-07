"""
Live Demo System for Infinite AI Security
Real-time attack simulation and defense demonstration
"""
import asyncio
import json
import time
import random
from datetime import datetime
from typing import Dict, List, Any
import websockets
import requests
from colorama import init, Fore, Style
import threading
import queue
import matplotlib.pyplot as plt
import matplotlib.animation as animation
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import tkinter as tk
from tkinter import ttk

init(autoreset=True)

class AttackSimulator:
    """Simulates various cyber attacks for demo purposes"""
    
    def __init__(self):
        self.attack_patterns = {
            "sql_injection": [
                "' OR 1=1 --",
                "'; DROP TABLE users; --",
                "' UNION SELECT password FROM users --",
                "admin'/**/OR/**/1=1#"
            ],
            "xss": [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "javascript:alert('XSS')",
                "<svg onload=alert('XSS')>"
            ],
            "ddos": [
                {"type": "volumetric", "pps": 50000},
                {"type": "protocol", "pps": 25000},
                {"type": "application", "pps": 10000}
            ],
            "brute_force": [
                {"username": "admin", "password": "password"},
                {"username": "root", "password": "123456"},
                {"username": "user", "password": "qwerty"}
            ]
        }
    
    def generate_attack(self, attack_type: str) -> Dict[str, Any]:
        """Generate realistic attack data"""
        base_attack = {
            "id": f"attack_{int(time.time())}_{random.randint(1000, 9999)}",
            "timestamp": datetime.utcnow().isoformat(),
            "source_ip": f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}",
            "attack_type": attack_type,
            "severity": random.choice(["medium", "high", "critical"]),
            "blocked": False,
            "confidence": 0.0
        }
        
        if attack_type == "sql_injection":
            payload = random.choice(self.attack_patterns["sql_injection"])
            base_attack.update({
                "payload": payload,
                "target_url": "/login.php",
                "method": "POST",
                "user_agent": "Mozilla/5.0 (Hacker Tools)"
            })
        
        elif attack_type == "xss":
            payload = random.choice(self.attack_patterns["xss"])
            base_attack.update({
                "payload": payload,
                "target_url": "/search.php",
                "method": "GET",
                "parameter": "q"
            })
        
        elif attack_type == "ddos":
            pattern = random.choice(self.attack_patterns["ddos"])
            base_attack.update({
                "ddos_type": pattern["type"],
                "packets_per_second": pattern["pps"],
                "target_port": random.choice([80, 443, 22, 25])
            })
        
        elif attack_type == "brute_force":
            creds = random.choice(self.attack_patterns["brute_force"])
            base_attack.update({
                "username": creds["username"],
                "password": creds["password"],
                "target_service": "SSH",
                "attempts": random.randint(100, 1000)
            })
        
        return base_attack

class AIDefenseSimulator:
    """Simulates AI defense responses"""
    
    def __init__(self):
        self.agents = {
            "gpt4_security": {"specialty": "threat_analysis", "response_time": 150},
            "claude_analyst": {"specialty": "vulnerability_assessment", "response_time": 120},
            "grok_scanner": {"specialty": "pattern_recognition", "response_time": 80},
            "mistral_coordinator": {"specialty": "response_coordination", "response_time": 100}
        }
    
    async def analyze_attack(self, attack: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate AI analysis of attack"""
        # Simulate processing time
        await asyncio.sleep(random.uniform(0.1, 0.3))
        
        # Determine confidence based on attack type
        confidence_map = {
            "sql_injection": random.uniform(0.85, 0.98),
            "xss": random.uniform(0.75, 0.92),
            "ddos": random.uniform(0.90, 0.99),
            "brute_force": random.uniform(0.80, 0.95)
        }
        
        confidence = confidence_map.get(attack["attack_type"], 0.5)
        
        # Multi-agent voting
        agent_votes = {}
        for agent_id, agent_info in self.agents.items():
            vote_confidence = confidence + random.uniform(-0.1, 0.1)
            agent_votes[agent_id] = {
                "confidence": max(0.0, min(1.0, vote_confidence)),
                "recommendation": "block" if vote_confidence > 0.7 else "monitor",
                "response_time_ms": agent_info["response_time"] + random.randint(-20, 20)
            }
        
        # Consensus decision
        avg_confidence = sum(v["confidence"] for v in agent_votes.values()) / len(agent_votes)
        consensus = "block" if avg_confidence > 0.7 else "monitor"
        
        return {
            "attack_id": attack["id"],
            "analysis_result": {
                "confidence": avg_confidence,
                "consensus": consensus,
                "agent_votes": agent_votes,
                "blocked": consensus == "block",
                "analysis_time_ms": max(v["response_time_ms"] for v in agent_votes.values())
            }
        }

class LiveDashboard:
    """Real-time dashboard for demo visualization"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Infinite AI Security - Live Demo Dashboard")
        self.root.geometry("1200x800")
        
        # Data storage
        self.attack_data = []
        self.defense_data = []
        self.metrics = {
            "total_attacks": 0,
            "blocked_attacks": 0,
            "avg_response_time": 0,
            "threat_level": "LOW"
        }
        
        self.setup_ui()
        
    def setup_ui(self):
        """Setup dashboard UI"""
        # Main frame
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Metrics frame
        metrics_frame = ttk.LabelFrame(main_frame, text="Real-Time Metrics")
        metrics_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.metrics_labels = {}
        for i, (key, value) in enumerate(self.metrics.items()):
            label = ttk.Label(metrics_frame, text=f"{key.replace('_', ' ').title()}: {value}")
            label.grid(row=0, column=i, padx=20, pady=10)
            self.metrics_labels[key] = label
        
        # Attack log frame
        log_frame = ttk.LabelFrame(main_frame, text="Attack Log")
        log_frame.pack(fill=tk.BOTH, expand=True)
        
        # Treeview for attack log
        columns = ("Time", "Type", "Source IP", "Severity", "Status", "Confidence")
        self.attack_tree = ttk.Treeview(log_frame, columns=columns, show="headings")
        
        for col in columns:
            self.attack_tree.heading(col, text=col)
            self.attack_tree.column(col, width=120)
        
        scrollbar = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.attack_tree.yview)
        self.attack_tree.configure(yscrollcommand=scrollbar.set)
        
        self.attack_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def update_metrics(self, attack_result: Dict[str, Any]):
        """Update dashboard metrics"""
        self.metrics["total_attacks"] += 1
        
        if attack_result["analysis_result"]["blocked"]:
            self.metrics["blocked_attacks"] += 1
        
        # Update average response time
        response_time = attack_result["analysis_result"]["analysis_time_ms"]
        current_avg = self.metrics["avg_response_time"]
        total = self.metrics["total_attacks"]
        self.metrics["avg_response_time"] = ((current_avg * (total - 1)) + response_time) / total
        
        # Update threat level
        block_rate = self.metrics["blocked_attacks"] / self.metrics["total_attacks"]
        if block_rate > 0.8:
            self.metrics["threat_level"] = "HIGH"
        elif block_rate > 0.5:
            self.metrics["threat_level"] = "MEDIUM"
        else:
            self.metrics["threat_level"] = "LOW"
        
        # Update UI
        for key, value in self.metrics.items():
            if key == "avg_response_time":
                display_value = f"{value:.1f}ms"
            elif key in ["total_attacks", "blocked_attacks"]:
                display_value = str(int(value))
            else:
                display_value = str(value)
            
            self.metrics_labels[key].config(text=f"{key.replace('_', ' ').title()}: {display_value}")
    
    def add_attack_log(self, attack: Dict[str, Any], result: Dict[str, Any]):
        """Add attack to log display"""
        timestamp = datetime.fromisoformat(attack["timestamp"]).strftime("%H:%M:%S")
        status = "BLOCKED" if result["analysis_result"]["blocked"] else "MONITORED"
        confidence = f"{result['analysis_result']['confidence']:.2%}"
        
        # Color coding
        if result["analysis_result"]["blocked"]:
            tags = ("blocked",)
        else:
            tags = ("monitored",)
        
        self.attack_tree.insert("", 0, values=(
            timestamp,
            attack["attack_type"].upper(),
            attack["source_ip"],
            attack["severity"].upper(),
            status,
            confidence
        ), tags=tags)
        
        # Configure tags
        self.attack_tree.tag_configure("blocked", background="#ffcccc")
        self.attack_tree.tag_configure("monitored", background="#ffffcc")
        
        # Keep only last 50 entries
        children = self.attack_tree.get_children()
        if len(children) > 50:
            self.attack_tree.delete(children[-1])

class LiveDemoSystem:
    """Main demo system orchestrator"""
    
    def __init__(self):
        self.attack_simulator = AttackSimulator()
        self.defense_simulator = AIDefenseSimulator()
        self.dashboard = LiveDashboard()
        self.running = False
        self.demo_queue = queue.Queue()
    
    def print_banner(self):
        """Print demo banner"""
        banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║                 🚀 INFINITE AI SECURITY                      ║
║                  Live Demo System v2.0                       ║
║                                                              ║
║  🤖 Multi-Agent AI Defense    🛡️  Real-Time Protection      ║
║  ⚡ <30ms Response Time       📊 Live Threat Analytics      ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
        """
        print(banner)
    
    async def simulate_attack_wave(self):
        """Simulate continuous attack waves"""
        attack_types = ["sql_injection", "xss", "ddos", "brute_force"]
        
        while self.running:
            # Generate random attack
            attack_type = random.choice(attack_types)
            attack = self.attack_simulator.generate_attack(attack_type)
            
            print(f"{Fore.RED}🔥 ATTACK DETECTED: {attack_type.upper()}{Style.RESET_ALL}")
            print(f"   Source: {attack['source_ip']}")
            print(f"   Severity: {attack['severity'].upper()}")
            
            # AI Defense Analysis
            print(f"{Fore.YELLOW}🤖 AI AGENTS ANALYZING...{Style.RESET_ALL}")
            result = await self.defense_simulator.analyze_attack(attack)
            
            # Display result
            analysis = result["analysis_result"]
            if analysis["blocked"]:
                print(f"{Fore.GREEN}✅ ATTACK BLOCKED{Style.RESET_ALL}")
                print(f"   Confidence: {analysis['confidence']:.2%}")
                print(f"   Response Time: {analysis['analysis_time_ms']}ms")
            else:
                print(f"{Fore.BLUE}👁️  ATTACK MONITORED{Style.RESET_ALL}")
                print(f"   Confidence: {analysis['confidence']:.2%}")
            
            # Update dashboard
            self.demo_queue.put(("attack", attack, result))
            
            # Wait before next attack
            await asyncio.sleep(random.uniform(2, 5))
    
    def update_dashboard_worker(self):
        """Worker thread to update dashboard"""
        while self.running:
            try:
                item = self.demo_queue.get(timeout=1)
                if item[0] == "attack":
                    _, attack, result = item
                    self.dashboard.update_metrics(result)
                    self.dashboard.add_attack_log(attack, result)
                    self.dashboard.root.update()
            except queue.Empty:
                continue
            except Exception as e:
                print(f"Dashboard update error: {e}")
    
    async def run_demo(self, duration_minutes: int = 5):
        """Run complete demo"""
        self.print_banner()
        print(f"{Fore.CYAN}🎬 Starting {duration_minutes}-minute live demo...{Style.RESET_ALL}")
        
        self.running = True
        
        # Start dashboard update worker
        dashboard_thread = threading.Thread(target=self.update_dashboard_worker)
        dashboard_thread.daemon = True
        dashboard_thread.start()
        
        # Start attack simulation
        attack_task = asyncio.create_task(self.simulate_attack_wave())
        
        # Show dashboard
        def run_dashboard():
            self.dashboard.root.mainloop()
        
        dashboard_thread = threading.Thread(target=run_dashboard)
        dashboard_thread.daemon = True
        dashboard_thread.start()
        
        # Run for specified duration
        await asyncio.sleep(duration_minutes * 60)
        
        self.running = False
        attack_task.cancel()
        
        print(f"\n{Fore.GREEN}✅ DEMO COMPLETED{Style.RESET_ALL}")
        print(f"{Fore.CYAN}📊 Final Statistics:{Style.RESET_ALL}")
        print(f"   Total Attacks: {self.dashboard.metrics['total_attacks']}")
        print(f"   Blocked: {self.dashboard.metrics['blocked_attacks']}")
        print(f"   Success Rate: {(self.dashboard.metrics['blocked_attacks']/max(1, self.dashboard.metrics['total_attacks']))*100:.1f}%")
        print(f"   Avg Response: {self.dashboard.metrics['avg_response_time']:.1f}ms")

# Demo execution
async def main():
    demo = LiveDemoSystem()
    await demo.run_demo(duration_minutes=10)  # 10-minute demo

if __name__ == "__main__":
    asyncio.run(main())