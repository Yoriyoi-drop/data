#!/usr/bin/env python3
"""
Runner untuk menjalankan arsitektur LangGraph multi-tier dengan 200 node dalam 50 level
Versi kompatibel Python 3.14
"""

import asyncio
import time
from typing import Dict, Any, List
from langgraph_components import AgentFactory, LANGGRAPH_TOOLS
from python314_compatible import Python314CompatibleMultiTierGraph as MultiTierLangGraph, State
from datetime import datetime
import json
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class MultiTierRunner:
    """Runner untuk menjalankan keseluruhan arsitektur multi-tier"""
    
    def __init__(self, config_path: str = "langgraph_config.yaml"):
        self.config_path = config_path
        self.agent_factory = AgentFactory(config_path)
        self.graph_app = None
        
    def build_graph(self):
        """Build graph dari konfigurasi"""
        logger.info("Membangun graph multi-tier...")
        start_time = time.time()
        
        # Gunakan config_path jika file konfigurasi ada, jika tidak gunakan default
        import os
        if os.path.exists(self.config_path):
            self.graph_app = MultiTierLangGraph(self.config_path)
        else:
            self.graph_app = MultiTierLangGraph()  # Gunakan default
        
        logger.info(f"Graph berhasil dibangun dalam {time.time() - start_time:.2f} detik")
        
    async def run_single_tier(self, tier_level: int, input_data: Any) -> Dict[str, Any]:
        """Menjalankan satu tier saja untuk testing (versi disederhanakan)"""
        logger.info(f"Menjalankan tier {tier_level} - versi kompatibel")
        
        # Dalam implementasi kompatibel, kita akan membuat simulasi tier
        start_time = time.time()
        results = {}
        
        # Simulasikan 4 node per tier
        node_types = ["ai_core", "data", "compute", "decision"]  # Sesuaikan dengan posisi
        for pos, node_type in enumerate(node_types):
            node_id = f"node_{tier_level}_{pos}"
            
            agent = self.agent_factory.create_agent(
                node_id,
                tier_level,
                pos,
                node_type
            )
            
            result = await agent.execute(input_data)
            results[node_id] = result
        
        execution_time = time.time() - start_time
        logger.info(f"Selesai menjalankan tier {tier_level} dalam {execution_time:.2f} detik")
        
        return {
            "tier_level": tier_level,
            "results": results,
            "execution_time": execution_time,
            "timestamp": datetime.now().isoformat()
        }
    
    async def run_multi_tier_simulation(self, input_data: Any = None) -> Dict[str, Any]:
        """Menjalankan simulasi multi-tier lengkap"""
        if input_data is None:
            input_data = {
                "message": "Input simulasi untuk arsitektur multi-tier",
                "timestamp": datetime.now().isoformat(),
                "source": "multi_tier_runner"
            }
        
        logger.info("Memulai simulasi multi-tier kompatibel...")
        start_time = time.time()
        
        # Eksekusi tier per tier (hanya 5 tier untuk simulasi cepat)
        all_results = {}
        
        for tier_level in range(1, 6):  # Hanya 5 tier pertama untuk simulasi cepat
            tier_result = await self.run_single_tier(tier_level, input_data)
            all_results[f"tier_{tier_level}"] = tier_result
            
            # Simulasi delay antar tier untuk keperluan demonstrasi
            await asyncio.sleep(0.1)
        
        total_execution_time = time.time() - start_time
        
        summary = {
            "total_tiers_executed": len(all_results),
            "total_execution_time": total_execution_time,
            "average_time_per_tier": total_execution_time / len(all_results),
            "input_data": input_data,
            "results": all_results,
            "timestamp": datetime.now().isoformat()
        }
        
        logger.info(f"Simulasi selesai dalam {total_execution_time:.2f} detik")
        return summary
    
    async def run_full_graph_execution(self):
        """Menjalankan eksekusi graph penuh (menggunakan implementasi kompatibel)"""
        if not self.graph_app:
            self.build_graph()
        
        logger.info("Menjalankan eksekusi graph penuh kompatibel...")
        
        # Siapkan state awal
        initial_state = State(
            input_data={
                "message": "Input awal untuk graph penuh kompatibel",
                "timestamp": datetime.now().isoformat(),
                "request_id": "full_graph_execution"
            }
        )
        
        start_time = time.time()
        
        try:
            # Eksekusi graf secara langsung
            result = await self.graph_app.execute_all_tiers(initial_state)
            
            execution_time = time.time() - start_time
            logger.info(f"Eksekusi graph selesai dalam {execution_time:.2f} detik")
            
            return result
        except Exception as e:
            logger.error(f"Error dalam eksekusi graph: {e}")
            raise
    
    def generate_execution_report(self, results: Dict[str, Any]) -> str:
        """Menghasilkan laporan eksekusi"""
        report = {
            "execution_summary": {
                "total_tiers": results.get("total_tiers_executed", len(results.get("results", {}))),
                "total_execution_time": results.get("total_execution_time", 0),
                "average_time_per_tier": results.get("average_time_per_tier", 0),
                "timestamp": datetime.now().isoformat()
            },
            "performance_metrics": {
                "nodes_per_second": 20 / results.get("total_execution_time", 1) if results.get("total_execution_time", 1) > 0 else 0,
                "efficiency_rating": "high" if results.get("average_time_per_tier", float('inf')) < 1.0 else "medium"
            },
            "node_type_distribution": {
                "ai_core": 5,
                "data": 5,
                "compute": 5,
                "decision": 5
            }
        }
        
        return json.dumps(report, indent=2, default=str)

async def main():
    """Fungsi utama untuk menjalankan runner"""
    logger.info("Memulai Multi-Tier LangGraph Runner (Kompatibel Python 3.14)")
    
    runner = MultiTierRunner()
    
    # Build graph
    runner.build_graph()
    
    # Jalankan simulasi
    logger.info("Menjalankan simulasi multi-tier kompatibel...")
    results = await runner.run_multi_tier_simulation()
    
    # Generate dan tampilkan laporan
    report = runner.generate_execution_report(results)
    print("\n=== Laporan Eksekusi ===")
    print(report)
    
    # Simpan laporan ke file
    with open("multi_tier_execution_report.json", "w", encoding="utf-8") as f:
        f.write(report)
    
    logger.info("Laporan eksekusi disimpan ke multi_tier_execution_report.json")
    
    # Demonstrasi tools
    print("\n=== Demonstrasi Tools ===")
    for tool in LANGGRAPH_TOOLS[:3]:  # Hanya 3 tools pertama
        print(f"Nama tool: {tool.name}")
        print(f"Deskripsi: {tool.description}")
        print(f"Contoh eksekusi: {tool.run('Contoh input untuk tool')}")
        print()

if __name__ == "__main__":
    asyncio.run(main())