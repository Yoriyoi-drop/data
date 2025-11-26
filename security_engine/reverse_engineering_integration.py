"""
Reverse Engineering Integration for Multi-Language Security Engine
"""
import os
import subprocess
import json
from typing import Dict, List, Any, Optional
from pathlib import Path

class MultiLanguageReverseEngine:
    def __init__(self):
        self.go_scanner_path = Path(__file__).parent / "scanner_go"
        self.rust_labyrinth_path = Path(__file__).parent / "labyrinth_rust"
        self.cpp_detector_path = Path(__file__).parent / "detector_cpp"
        self.asm_core_path = Path(__file__).parent / "asm_core"
    
    async def analyze_with_go_scanner(self, file_path: str) -> Dict[str, Any]:
        """Use Go scanner for high-performance binary analysis"""
        try:
            # Build Go scanner if needed
            go_binary = self.go_scanner_path / "scanner"
            if not go_binary.exists():
                await self._build_go_scanner()
            
            # Run Go scanner
            result = subprocess.run([
                str(go_binary), 
                "--analyze", file_path,
                "--output", "json"
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                return json.loads(result.stdout)
            else:
                return {"error": result.stderr, "status": "go_scanner_failed"}
        
        except Exception as e:
            return {"error": str(e), "status": "go_scanner_error"}
    
    async def analyze_with_rust_labyrinth(self, file_path: str) -> Dict[str, Any]:
        """Use Rust labyrinth for deep binary analysis"""
        try:
            # Build Rust labyrinth if needed
            rust_binary = self.rust_labyrinth_path / "target" / "release" / "labyrinth_analyzer"
            if not rust_binary.exists():
                await self._build_rust_labyrinth()
            
            # Run Rust analyzer
            result = subprocess.run([
                str(rust_binary),
                "--file", file_path,
                "--mode", "reverse-engineering"
            ], capture_output=True, text=True, timeout=45)
            
            if result.returncode == 0:
                return json.loads(result.stdout)
            else:
                return {"error": result.stderr, "status": "rust_analyzer_failed"}
        
        except Exception as e:
            return {"error": str(e), "status": "rust_analyzer_error"}
    
    async def analyze_with_cpp_detector(self, file_path: str) -> Dict[str, Any]:
        """Use C++ detector for advanced pattern detection"""
        try:
            # Build C++ detector if needed
            cpp_binary = self.cpp_detector_path / "build" / "advanced_detector"
            if not cpp_binary.exists():
                await self._build_cpp_detector()
            
            # Run C++ detector
            result = subprocess.run([
                str(cpp_binary),
                file_path,
                "--reverse-engineering",
                "--json-output"
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                return json.loads(result.stdout)
            else:
                return {"error": result.stderr, "status": "cpp_detector_failed"}
        
        except Exception as e:
            return {"error": str(e), "status": "cpp_detector_error"}
    
    async def analyze_with_asm_core(self, file_path: str) -> Dict[str, Any]:
        """Use Assembly core for low-level analysis"""
        try:
            # Use Python interface to ASM core
            asm_interface = self.asm_core_path / "asm_interface.py"
            
            result = subprocess.run([
                "python", str(asm_interface),
                "--analyze", file_path,
                "--mode", "reverse-engineering"
            ], capture_output=True, text=True, timeout=20)
            
            if result.returncode == 0:
                return json.loads(result.stdout)
            else:
                return {"error": result.stderr, "status": "asm_core_failed"}
        
        except Exception as e:
            return {"error": str(e), "status": "asm_core_error"}
    
    async def comprehensive_analysis(self, file_path: str) -> Dict[str, Any]:
        """Run comprehensive analysis using all engines"""
        results = {
            "file_path": file_path,
            "analysis_timestamp": "2024-01-01T00:00:00Z",
            "engines": {}
        }
        
        # Run all engines in parallel
        import asyncio
        
        tasks = [
            ("go_scanner", self.analyze_with_go_scanner(file_path)),
            ("rust_labyrinth", self.analyze_with_rust_labyrinth(file_path)),
            ("cpp_detector", self.analyze_with_cpp_detector(file_path)),
            ("asm_core", self.analyze_with_asm_core(file_path))
        ]
        
        for engine_name, task in tasks:
            try:
                result = await task
                results["engines"][engine_name] = result
            except Exception as e:
                results["engines"][engine_name] = {"error": str(e), "status": "failed"}
        
        # Aggregate results
        results["aggregated"] = self._aggregate_results(results["engines"])
        
        return results
    
    def _aggregate_results(self, engine_results: Dict[str, Any]) -> Dict[str, Any]:
        """Aggregate results from all engines"""
        aggregated = {
            "threat_score": 0,
            "confidence": 0.0,
            "malware_indicators": [],
            "vulnerabilities": [],
            "recommendations": []
        }
        
        successful_engines = 0
        total_threat_score = 0
        
        for engine, result in engine_results.items():
            if result.get("status") != "failed" and "error" not in result:
                successful_engines += 1
                
                # Aggregate threat scores
                if "threat_score" in result:
                    total_threat_score += result["threat_score"]
                
                # Collect malware indicators
                if "malware_indicators" in result:
                    aggregated["malware_indicators"].extend(result["malware_indicators"])
                
                # Collect vulnerabilities
                if "vulnerabilities" in result:
                    aggregated["vulnerabilities"].extend(result["vulnerabilities"])
        
        # Calculate final scores
        if successful_engines > 0:
            aggregated["threat_score"] = total_threat_score // successful_engines
            aggregated["confidence"] = successful_engines / len(engine_results)
        
        # Generate recommendations
        aggregated["recommendations"] = self._generate_recommendations(aggregated)
        
        return aggregated
    
    def _generate_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        threat_score = analysis.get("threat_score", 0)
        
        if threat_score >= 80:
            recommendations.append("CRITICAL: Quarantine file immediately")
            recommendations.append("Perform full system scan")
            recommendations.append("Check for lateral movement")
        elif threat_score >= 60:
            recommendations.append("HIGH: Isolate and analyze further")
            recommendations.append("Monitor network traffic")
        elif threat_score >= 40:
            recommendations.append("MEDIUM: Continue monitoring")
            recommendations.append("Update security signatures")
        else:
            recommendations.append("LOW: File appears benign")
        
        if analysis.get("malware_indicators"):
            recommendations.append("Update antivirus definitions")
        
        if analysis.get("vulnerabilities"):
            recommendations.append("Patch identified vulnerabilities")
        
        return recommendations
    
    async def _build_go_scanner(self):
        """Build Go scanner binary"""
        try:
            os.chdir(self.go_scanner_path)
            subprocess.run(["go", "build", "-o", "scanner", "scanner.go"], check=True)
        except Exception as e:
            print(f"Failed to build Go scanner: {e}")
    
    async def _build_rust_labyrinth(self):
        """Build Rust labyrinth binary"""
        try:
            os.chdir(self.rust_labyrinth_path)
            subprocess.run(["cargo", "build", "--release"], check=True)
        except Exception as e:
            print(f"Failed to build Rust labyrinth: {e}")
    
    async def _build_cpp_detector(self):
        """Build C++ detector binary"""
        try:
            build_dir = self.cpp_detector_path / "build"
            build_dir.mkdir(exist_ok=True)
            os.chdir(build_dir)
            subprocess.run(["cmake", ".."], check=True)
            subprocess.run(["make"], check=True)
        except Exception as e:
            print(f"Failed to build C++ detector: {e}")

# Global instance
multi_engine = MultiLanguageReverseEngine()