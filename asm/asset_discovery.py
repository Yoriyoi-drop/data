"""
Attack Surface Management - Asset Discovery Engine
Automated reconnaissance and asset enumeration
"""
import asyncio
import subprocess
import json
import ipaddress
from typing import List, Dict, Set, Optional
import asyncpg
import aiohttp
import dns.resolver
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)

@dataclass
class Asset:
    type: str  # 'ip', 'domain', 'subdomain', 'port', 'service'
    value: str
    metadata: Dict
    risk_score: int = 0
    discovered_by: str = ""

class AssetDiscovery:
    def __init__(self, db_pool: asyncpg.Pool):
        self.db_pool = db_pool
        self.discovered_assets: Set[str] = set()
    
    async def discover_subdomains(self, domain: str) -> List[Asset]:
        """Discover subdomains using multiple techniques"""
        assets = []
        
        # DNS enumeration
        subdomains = await self._dns_enumeration(domain)
        for subdomain in subdomains:
            if subdomain not in self.discovered_assets:
                asset = Asset(
                    type="subdomain",
                    value=subdomain,
                    metadata={"parent_domain": domain, "method": "dns"},
                    discovered_by="dns_enum"
                )
                assets.append(asset)
                self.discovered_assets.add(subdomain)
        
        # Certificate transparency
        ct_subdomains = await self._certificate_transparency(domain)
        for subdomain in ct_subdomains:
            if subdomain not in self.discovered_assets:
                asset = Asset(
                    type="subdomain",
                    value=subdomain,
                    metadata={"parent_domain": domain, "method": "ct_logs"},
                    discovered_by="cert_transparency"
                )
                assets.append(asset)
                self.discovered_assets.add(subdomain)
        
        return assets
    
    async def _dns_enumeration(self, domain: str) -> List[str]:
        """DNS-based subdomain enumeration"""
        subdomains = []
        common_subdomains = [
            "www", "mail", "ftp", "admin", "api", "dev", "test", "staging",
            "prod", "app", "web", "secure", "portal", "dashboard", "cdn"
        ]
        
        for sub in common_subdomains:
            try:
                full_domain = f"{sub}.{domain}"
                dns.resolver.resolve(full_domain, 'A')
                subdomains.append(full_domain)
            except:
                continue
        
        return subdomains
    
    async def _certificate_transparency(self, domain: str) -> List[str]:
        """Query certificate transparency logs"""
        subdomains = []
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://crt.sh/?q=%.{domain}&output=json"
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        for cert in data:
                            name = cert.get('name_value', '')
                            if name and name.endswith(domain):
                                subdomains.append(name)
        except Exception as e:
            logger.error(f"CT logs query failed: {e}")
        
        return list(set(subdomains))
    
    async def port_scan(self, target: str) -> List[Asset]:
        """Fast port scanning"""
        assets = []
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 8080, 8443]
        
        for port in common_ports:
            if await self._check_port(target, port):
                asset = Asset(
                    type="port",
                    value=f"{target}:{port}",
                    metadata={"host": target, "port": port, "state": "open"},
                    risk_score=self._calculate_port_risk(port),
                    discovered_by="port_scan"
                )
                assets.append(asset)
        
        return assets
    
    async def _check_port(self, host: str, port: int, timeout: int = 3) -> bool:
        """Check if port is open"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
            writer.close()
            await writer.wait_closed()
            return True
        except:
            return False
    
    def _calculate_port_risk(self, port: int) -> int:
        """Calculate risk score for open port"""
        high_risk_ports = {21: 8, 23: 9, 135: 7, 445: 8, 1433: 7, 3389: 6}
        medium_risk_ports = {22: 4, 25: 3, 53: 2, 110: 3, 143: 3}
        return high_risk_ports.get(port, medium_risk_ports.get(port, 1))
    
    async def service_detection(self, host: str, port: int) -> Optional[Asset]:
        """Detect service running on port"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=5
            )
            
            # Send HTTP request for web services
            if port in [80, 443, 8080, 8443]:
                writer.write(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
                await writer.drain()
                data = await asyncio.wait_for(reader.read(1024), timeout=3)
                
                service_info = self._parse_http_response(data.decode('utf-8', errors='ignore'))
                writer.close()
                await writer.wait_closed()
                
                return Asset(
                    type="service",
                    value=f"{host}:{port}",
                    metadata={
                        "service_type": "http",
                        "server": service_info.get("server", "unknown"),
                        "version": service_info.get("version", "unknown")
                    },
                    risk_score=3,
                    discovered_by="service_detection"
                )
            
            writer.close()
            await writer.wait_closed()
            
        except Exception as e:
            logger.debug(f"Service detection failed for {host}:{port}: {e}")
        
        return None
    
    def _parse_http_response(self, response: str) -> Dict[str, str]:
        """Parse HTTP response headers"""
        info = {}
        lines = response.split('\n')
        for line in lines:
            if line.lower().startswith('server:'):
                info['server'] = line.split(':', 1)[1].strip()
            elif line.lower().startswith('x-powered-by:'):
                info['version'] = line.split(':', 1)[1].strip()
        return info
    
    async def store_assets(self, assets: List[Asset]) -> bool:
        """Store discovered assets in database"""
        try:
            async with self.db_pool.acquire() as conn:
                for asset in assets:
                    await conn.execute("""
                        INSERT INTO asm.assets (type, value, metadata, risk_score, discovered_by)
                        VALUES ($1, $2, $3, $4, $5)
                        ON CONFLICT (type, value) DO UPDATE SET
                        metadata = $3, risk_score = $4, last_scanned = NOW()
                    """, asset.type, asset.value, json.dumps(asset.metadata), 
                    asset.risk_score, asset.discovered_by)
            
            logger.info(f"Stored {len(assets)} assets")
            return True
        except Exception as e:
            logger.error(f"Failed to store assets: {e}")
            return False
    
    async def full_discovery(self, target: str) -> Dict[str, List[Asset]]:
        """Complete asset discovery for target"""
        results = {
            "subdomains": [],
            "ports": [],
            "services": []
        }
        
        # Determine if target is domain or IP
        try:
            ipaddress.ip_address(target)
            is_ip = True
        except:
            is_ip = False
        
        if not is_ip:
            # Domain-based discovery
            results["subdomains"] = await self.discover_subdomains(target)
            
            # Scan main domain
            results["ports"] = await self.port_scan(target)
            
            # Scan discovered subdomains
            for subdomain_asset in results["subdomains"][:5]:  # Limit to first 5
                subdomain_ports = await self.port_scan(subdomain_asset.value)
                results["ports"].extend(subdomain_ports)
        else:
            # IP-based discovery
            results["ports"] = await self.port_scan(target)
        
        # Service detection on open ports
        for port_asset in results["ports"]:
            host, port = port_asset.value.split(':')
            service = await self.service_detection(host, int(port))
            if service:
                results["services"].append(service)
        
        # Store all discovered assets
        all_assets = results["subdomains"] + results["ports"] + results["services"]
        await self.store_assets(all_assets)
        
        return results

# Usage example
async def run_discovery():
    db_pool = await asyncpg.create_pool("postgresql://user:pass@localhost/infinite_labyrinth")
    discovery = AssetDiscovery(db_pool)
    
    # Discover assets for target
    results = await discovery.full_discovery("example.com")
    
    print(f"Discovered {len(results['subdomains'])} subdomains")
    print(f"Found {len(results['ports'])} open ports")
    print(f"Identified {len(results['services'])} services")
    
    return results