"""
SIEM/SOAR Integration Module
Connects with enterprise security platforms for unified threat management
"""
import asyncio
import json
import time
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
import aiohttp
import logging

logger = logging.getLogger(__name__)

@dataclass
class SecurityEvent:
    event_id: str
    timestamp: datetime
    source: str
    event_type: str
    severity: str
    description: str
    raw_data: Dict[str, Any]
    indicators: List[str]
    remediation: Optional[str] = None

class SIEMConnector:
    """Base class for SIEM integrations"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.session = None
    
    async def initialize(self) -> bool:
        """Initialize SIEM connection"""
        raise NotImplementedError
    
    async def send_event(self, event: SecurityEvent) -> bool:
        """Send security event to SIEM"""
        raise NotImplementedError
    
    async def query_events(self, query: str, time_range: str = "1h") -> List[Dict[str, Any]]:
        """Query events from SIEM"""
        raise NotImplementedError

class SplunkConnector(SIEMConnector):
    """Splunk Enterprise Security integration"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.base_url = config.get("base_url")
        self.username = config.get("username")
        self.password = config.get("password")
        self.session_key = None
    
    async def initialize(self) -> bool:
        """Initialize Splunk connection"""
        try:
            self.session = aiohttp.ClientSession()
            
            # Authenticate and get session key
            auth_url = f"{self.base_url}/services/auth/login"
            auth_data = {
                "username": self.username,
                "password": self.password
            }
            
            async with self.session.post(auth_url, data=auth_data) as response:
                if response.status == 200:
                    response_text = await response.text()
                    # Extract session key from XML response
                    import xml.etree.ElementTree as ET
                    root = ET.fromstring(response_text)
                    self.session_key = root.find(".//sessionKey").text
                    
                    logger.info("Splunk connection initialized")
                    return True
                else:
                    logger.error(f"Splunk authentication failed: {response.status}")
                    return False
        
        except Exception as e:
            logger.error(f"Failed to initialize Splunk connection: {e}")
            return False
    
    async def send_event(self, event: SecurityEvent) -> bool:
        """Send event to Splunk via HTTP Event Collector"""
        try:
            # Format event for Splunk
            splunk_event = {
                "time": event.timestamp.timestamp(),
                "source": "infinite_ai_security",
                "sourcetype": "security_event",
                "index": "security",
                "event": {
                    "event_id": event.event_id,
                    "event_type": event.event_type,
                    "severity": event.severity,
                    "description": event.description,
                    "source_system": event.source,
                    "indicators": event.indicators,
                    "raw_data": event.raw_data,
                    "remediation": event.remediation
                }
            }
            
            # Send to HEC endpoint
            hec_url = f"{self.base_url}/services/collector/event"
            headers = {
                "Authorization": f"Splunk {self.config.get('hec_token')}",
                "Content-Type": "application/json"
            }
            
            async with self.session.post(hec_url, json=splunk_event, headers=headers) as response:
                if response.status == 200:
                    logger.debug(f"Event {event.event_id} sent to Splunk")
                    return True
                else:
                    logger.error(f"Failed to send event to Splunk: {response.status}")
                    return False
        
        except Exception as e:
            logger.error(f"Error sending event to Splunk: {e}")
            return False
    
    async def query_events(self, query: str, time_range: str = "1h") -> List[Dict[str, Any]]:
        """Query events from Splunk"""
        try:
            search_url = f"{self.base_url}/services/search/jobs"
            
            # Create search job
            search_data = {
                "search": f"search {query} earliest=-{time_range}",
                "output_mode": "json"
            }
            
            headers = {"Authorization": f"Splunk {self.session_key}"}
            
            async with self.session.post(search_url, data=search_data, headers=headers) as response:
                if response.status == 201:
                    job_data = await response.json()
                    job_id = job_data["sid"]
                    
                    # Wait for job completion and get results
                    results_url = f"{self.base_url}/services/search/jobs/{job_id}/results"
                    
                    # Poll for completion
                    for _ in range(30):  # 30 second timeout
                        await asyncio.sleep(1)
                        async with self.session.get(f"{search_url}/{job_id}", headers=headers) as status_response:
                            status_data = await status_response.json()
                            if status_data["entry"][0]["content"]["isDone"]:
                                break
                    
                    # Get results
                    async with self.session.get(results_url, headers=headers) as results_response:
                        if results_response.status == 200:
                            results_data = await results_response.json()
                            return results_data.get("results", [])
            
            return []
        
        except Exception as e:
            logger.error(f"Error querying Splunk: {e}")
            return []

class QRadarConnector(SIEMConnector):
    """IBM QRadar integration"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.base_url = config.get("base_url")
        self.api_token = config.get("api_token")
    
    async def initialize(self) -> bool:
        """Initialize QRadar connection"""
        try:
            self.session = aiohttp.ClientSession()
            
            # Test connection
            test_url = f"{self.base_url}/api/system/about"
            headers = {"SEC": self.api_token}
            
            async with self.session.get(test_url, headers=headers) as response:
                if response.status == 200:
                    logger.info("QRadar connection initialized")
                    return True
                else:
                    logger.error(f"QRadar connection test failed: {response.status}")
                    return False
        
        except Exception as e:
            logger.error(f"Failed to initialize QRadar connection: {e}")
            return False
    
    async def send_event(self, event: SecurityEvent) -> bool:
        """Send event to QRadar via REST API"""
        try:
            # Format event for QRadar
            qradar_event = {
                "events": [{
                    "qid": 28250001,  # Custom event QID
                    "message": f"Infinite AI Security: {event.description}",
                    "properties": {
                        "EventID": event.event_id,
                        "EventType": event.event_type,
                        "Severity": event.severity,
                        "SourceSystem": event.source,
                        "Indicators": ",".join(event.indicators),
                        "RawData": json.dumps(event.raw_data)
                    }
                }]
            }
            
            events_url = f"{self.base_url}/api/siem/events"
            headers = {
                "SEC": self.api_token,
                "Content-Type": "application/json"
            }
            
            async with self.session.post(events_url, json=qradar_event, headers=headers) as response:
                if response.status == 200:
                    logger.debug(f"Event {event.event_id} sent to QRadar")
                    return True
                else:
                    logger.error(f"Failed to send event to QRadar: {response.status}")
                    return False
        
        except Exception as e:
            logger.error(f"Error sending event to QRadar: {e}")
            return False
    
    async def query_events(self, query: str, time_range: str = "1h") -> List[Dict[str, Any]]:
        """Query events from QRadar"""
        try:
            # Convert time range to milliseconds
            time_ms = int(time.time() * 1000) - (3600000 if time_range == "1h" else 86400000)
            
            search_url = f"{self.base_url}/api/ariel/searches"
            aql_query = f"SELECT * FROM events WHERE {query} AND starttime > {time_ms}"
            
            headers = {
                "SEC": self.api_token,
                "Content-Type": "application/json"
            }
            
            # Start search
            search_data = {"query_expression": aql_query}
            
            async with self.session.post(search_url, json=search_data, headers=headers) as response:
                if response.status == 201:
                    search_data = await response.json()
                    search_id = search_data["search_id"]
                    
                    # Wait for completion
                    for _ in range(30):
                        await asyncio.sleep(1)
                        status_url = f"{search_url}/{search_id}"
                        async with self.session.get(status_url, headers=headers) as status_response:
                            status_data = await status_response.json()
                            if status_data["status"] == "COMPLETED":
                                break
                    
                    # Get results
                    results_url = f"{search_url}/{search_id}/results"
                    async with self.session.get(results_url, headers=headers) as results_response:
                        if results_response.status == 200:
                            results_data = await results_response.json()
                            return results_data.get("events", [])
            
            return []
        
        except Exception as e:
            logger.error(f"Error querying QRadar: {e}")
            return []

class SentinelConnector(SIEMConnector):
    """Microsoft Sentinel integration"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.workspace_id = config.get("workspace_id")
        self.shared_key = config.get("shared_key")
        self.log_type = "InfiniteAISecurity"
    
    async def initialize(self) -> bool:
        """Initialize Sentinel connection"""
        try:
            self.session = aiohttp.ClientSession()
            logger.info("Sentinel connection initialized")
            return True
        
        except Exception as e:
            logger.error(f"Failed to initialize Sentinel connection: {e}")
            return False
    
    async def send_event(self, event: SecurityEvent) -> bool:
        """Send event to Sentinel via Data Collector API"""
        try:
            import base64
            import hmac
            import hashlib
            
            # Format event for Sentinel
            sentinel_event = {
                "EventID": event.event_id,
                "TimeGenerated": event.timestamp.isoformat(),
                "Source": event.source,
                "EventType": event.event_type,
                "Severity": event.severity,
                "Description": event.description,
                "Indicators": event.indicators,
                "RawData": json.dumps(event.raw_data),
                "Remediation": event.remediation
            }
            
            # Prepare request
            body = json.dumps([sentinel_event])
            method = "POST"
            content_type = "application/json"
            resource = "/api/logs"
            rfc1123date = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
            content_length = len(body)
            
            # Build signature
            string_to_hash = f"{method}\n{content_length}\n{content_type}\nx-ms-date:{rfc1123date}\n{resource}"
            bytes_to_hash = bytes(string_to_hash, 'UTF-8')
            decoded_key = base64.b64decode(self.shared_key)
            encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
            authorization = f"SharedKey {self.workspace_id}:{encoded_hash}"
            
            # Send to Sentinel
            url = f"https://{self.workspace_id}.ods.opinsights.azure.com{resource}?api-version=2016-04-01"
            headers = {
                "Authorization": authorization,
                "Log-Type": self.log_type,
                "x-ms-date": rfc1123date,
                "time-generated-field": "TimeGenerated",
                "Content-Type": content_type
            }
            
            async with self.session.post(url, data=body, headers=headers) as response:
                if response.status == 200:
                    logger.debug(f"Event {event.event_id} sent to Sentinel")
                    return True
                else:
                    logger.error(f"Failed to send event to Sentinel: {response.status}")
                    return False
        
        except Exception as e:
            logger.error(f"Error sending event to Sentinel: {e}")
            return False

class SIEMIntegrationManager:
    """Manages multiple SIEM integrations"""
    
    def __init__(self, config: Dict[str, Any]):
        self.connectors = {}
        self.config = config
        
        # Initialize configured connectors
        if "splunk" in config:
            self.connectors["splunk"] = SplunkConnector(config["splunk"])
        
        if "qradar" in config:
            self.connectors["qradar"] = QRadarConnector(config["qradar"])
        
        if "sentinel" in config:
            self.connectors["sentinel"] = SentinelConnector(config["sentinel"])
    
    async def initialize_all(self) -> Dict[str, bool]:
        """Initialize all configured SIEM connectors"""
        results = {}
        
        for name, connector in self.connectors.items():
            try:
                results[name] = await connector.initialize()
                logger.info(f"SIEM connector {name}: {'✅' if results[name] else '❌'}")
            except Exception as e:
                logger.error(f"Failed to initialize {name}: {e}")
                results[name] = False
        
        return results
    
    async def broadcast_event(self, event: SecurityEvent) -> Dict[str, bool]:
        """Send event to all configured SIEMs"""
        results = {}
        
        for name, connector in self.connectors.items():
            try:
                results[name] = await connector.send_event(event)
            except Exception as e:
                logger.error(f"Failed to send event to {name}: {e}")
                results[name] = False
        
        return results
    
    async def correlate_events(self, indicators: List[str], time_range: str = "1h") -> Dict[str, List[Dict[str, Any]]]:
        """Query all SIEMs for correlated events"""
        results = {}
        
        # Build query based on indicators
        query_parts = []
        for indicator in indicators:
            if "." in indicator:  # IP address
                query_parts.append(f"src_ip={indicator} OR dest_ip={indicator}")
            elif "@" in indicator:  # Email
                query_parts.append(f"email={indicator}")
            else:  # Generic indicator
                query_parts.append(f"*{indicator}*")
        
        query = " OR ".join(query_parts)
        
        for name, connector in self.connectors.items():
            try:
                results[name] = await connector.query_events(query, time_range)
            except Exception as e:
                logger.error(f"Failed to query {name}: {e}")
                results[name] = []
        
        return results

# Usage example
async def setup_siem_integrations():
    """Setup SIEM integrations for Infinite Security"""
    
    config = {
        "splunk": {
            "base_url": "https://splunk.company.com:8089",
            "username": "infinite_security",
            "password": "secure_password",
            "hec_token": "your-hec-token"
        },
        "qradar": {
            "base_url": "https://qradar.company.com",
            "api_token": "your-api-token"
        },
        "sentinel": {
            "workspace_id": "your-workspace-id",
            "shared_key": "your-shared-key"
        }
    }
    
    siem_manager = SIEMIntegrationManager(config)
    
    # Initialize all connectors
    init_results = await siem_manager.initialize_all()
    logger.info(f"SIEM initialization results: {init_results}")
    
    # Test event broadcast
    test_event = SecurityEvent(
        event_id="test_001",
        timestamp=datetime.utcnow(),
        source="infinite_ai_security",
        event_type="sql_injection",
        severity="high",
        description="SQL injection attempt detected and blocked",
        raw_data={"payload": "' OR 1=1 --", "source_ip": "192.168.1.100"},
        indicators=["192.168.1.100", "sql_injection"],
        remediation="IP blocked for 1 hour"
    )
    
    broadcast_results = await siem_manager.broadcast_event(test_event)
    logger.info(f"Event broadcast results: {broadcast_results}")
    
    return siem_manager

if __name__ == "__main__":
    asyncio.run(setup_siem_integrations())