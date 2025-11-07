"""
Automated Penetration Testing Suite
Security validation and vulnerability assessment
"""
import asyncio
import aiohttp
import json
import time
from typing import List, Dict, Any
import logging

logger = logging.getLogger(__name__)

class PenetrationTester:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.vulnerabilities = []
        self.test_results = {}
    
    async def test_sql_injection(self) -> Dict[str, Any]:
        """Test for SQL injection vulnerabilities"""
        payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT NULL, NULL, NULL --",
            "admin'/**/OR/**/1=1#"
        ]
        
        vulnerabilities = []
        
        async with aiohttp.ClientSession() as session:
            for payload in payloads:
                try:
                    test_url = f"{self.target_url}/api/login"
                    data = {"username": payload, "password": "test"}
                    
                    async with session.post(test_url, json=data) as response:
                        response_text = await response.text()
                        
                        # Check for SQL error indicators
                        sql_errors = [
                            "mysql_fetch_array",
                            "ORA-01756",
                            "Microsoft OLE DB Provider",
                            "PostgreSQL query failed",
                            "SQLite/JDBCDriver"
                        ]
                        
                        if any(error in response_text for error in sql_errors):
                            vulnerabilities.append({
                                "type": "sql_injection",
                                "payload": payload,
                                "severity": "high",
                                "evidence": response_text[:200]
                            })
                        
                        # Check for successful bypass
                        if response.status == 200 and "token" in response_text:
                            vulnerabilities.append({
                                "type": "authentication_bypass",
                                "payload": payload,
                                "severity": "critical",
                                "evidence": "Authentication bypassed"
                            })
                
                except Exception as e:
                    logger.debug(f"SQL injection test failed: {e}")
        
        return {
            "test": "sql_injection",
            "vulnerabilities_found": len(vulnerabilities),
            "details": vulnerabilities
        }
    
    async def test_xss(self) -> Dict[str, Any]:
        """Test for Cross-Site Scripting vulnerabilities"""
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>"
        ]
        
        vulnerabilities = []
        
        async with aiohttp.ClientSession() as session:
            for payload in payloads:
                try:
                    test_url = f"{self.target_url}/api/search"
                    params = {"q": payload}
                    
                    async with session.get(test_url, params=params) as response:
                        response_text = await response.text()
                        
                        # Check if payload is reflected without encoding
                        if payload in response_text and "<script>" in payload:
                            vulnerabilities.append({
                                "type": "reflected_xss",
                                "payload": payload,
                                "severity": "medium",
                                "evidence": "Payload reflected without encoding"
                            })
                
                except Exception as e:
                    logger.debug(f"XSS test failed: {e}")
        
        return {
            "test": "xss",
            "vulnerabilities_found": len(vulnerabilities),
            "details": vulnerabilities
        }
    
    async def test_authentication(self) -> Dict[str, Any]:
        """Test authentication mechanisms"""
        vulnerabilities = []
        
        async with aiohttp.ClientSession() as session:
            # Test weak passwords
            weak_passwords = ["password", "123456", "admin", "qwerty"]
            
            for password in weak_passwords:
                try:
                    data = {"username": "admin", "password": password}
                    async with session.post(f"{self.target_url}/api/login", json=data) as response:
                        if response.status == 200:
                            vulnerabilities.append({
                                "type": "weak_credentials",
                                "payload": f"admin:{password}",
                                "severity": "high",
                                "evidence": "Weak credentials accepted"
                            })
                except:
                    pass
            
            # Test for missing authentication
            protected_endpoints = ["/api/admin", "/api/users", "/api/config"]
            
            for endpoint in protected_endpoints:
                try:
                    async with session.get(f"{self.target_url}{endpoint}") as response:
                        if response.status == 200:
                            vulnerabilities.append({
                                "type": "missing_authentication",
                                "payload": endpoint,
                                "severity": "critical",
                                "evidence": "Protected endpoint accessible without auth"
                            })
                except:
                    pass
        
        return {
            "test": "authentication",
            "vulnerabilities_found": len(vulnerabilities),
            "details": vulnerabilities
        }
    
    async def test_authorization(self) -> Dict[str, Any]:
        """Test authorization controls"""
        vulnerabilities = []
        
        # Test for privilege escalation
        # This would require valid user tokens in a real test
        
        return {
            "test": "authorization",
            "vulnerabilities_found": len(vulnerabilities),
            "details": vulnerabilities
        }
    
    async def test_information_disclosure(self) -> Dict[str, Any]:
        """Test for information disclosure"""
        vulnerabilities = []
        
        async with aiohttp.ClientSession() as session:
            # Test for exposed files
            exposed_files = [
                "/.env",
                "/config.json",
                "/backup.sql",
                "/.git/config",
                "/admin.php",
                "/phpinfo.php"
            ]
            
            for file_path in exposed_files:
                try:
                    async with session.get(f"{self.target_url}{file_path}") as response:
                        if response.status == 200:
                            content = await response.text()
                            if len(content) > 100:  # Likely contains sensitive data
                                vulnerabilities.append({
                                    "type": "information_disclosure",
                                    "payload": file_path,
                                    "severity": "medium",
                                    "evidence": f"Exposed file: {file_path}"
                                })
                except:
                    pass
        
        return {
            "test": "information_disclosure",
            "vulnerabilities_found": len(vulnerabilities),
            "details": vulnerabilities
        }
    
    async def run_full_pentest(self) -> Dict[str, Any]:
        """Run complete penetration test suite"""
        start_time = time.time()
        
        print("🔍 Starting penetration test...")
        
        # Run all tests
        tests = [
            self.test_sql_injection(),
            self.test_xss(),
            self.test_authentication(),
            self.test_authorization(),
            self.test_information_disclosure()
        ]
        
        results = await asyncio.gather(*tests)
        
        # Compile results
        total_vulnerabilities = sum(r["vulnerabilities_found"] for r in results)
        
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        all_vulnerabilities = []
        
        for result in results:
            for vuln in result["details"]:
                severity_counts[vuln["severity"]] += 1
                all_vulnerabilities.append(vuln)
        
        end_time = time.time()
        
        report = {
            "test_duration_seconds": round(end_time - start_time, 2),
            "target_url": self.target_url,
            "total_vulnerabilities": total_vulnerabilities,
            "severity_breakdown": severity_counts,
            "test_results": results,
            "all_vulnerabilities": all_vulnerabilities,
            "risk_score": self._calculate_risk_score(severity_counts),
            "recommendations": self._generate_recommendations(all_vulnerabilities)
        }
        
        return report
    
    def _calculate_risk_score(self, severity_counts: Dict[str, int]) -> int:
        """Calculate overall risk score (0-100)"""
        weights = {"critical": 25, "high": 15, "medium": 8, "low": 3}
        score = sum(severity_counts[sev] * weight for sev, weight in weights.items())
        return min(score, 100)
    
    def _generate_recommendations(self, vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        vuln_types = set(v["type"] for v in vulnerabilities)
        
        if "sql_injection" in vuln_types:
            recommendations.append("Implement parameterized queries and input validation")
        
        if "reflected_xss" in vuln_types:
            recommendations.append("Implement output encoding and Content Security Policy")
        
        if "weak_credentials" in vuln_types:
            recommendations.append("Enforce strong password policies and MFA")
        
        if "missing_authentication" in vuln_types:
            recommendations.append("Implement authentication for all protected endpoints")
        
        if "information_disclosure" in vuln_types:
            recommendations.append("Remove or secure exposed files and directories")
        
        return recommendations
    
    def generate_report(self, results: Dict[str, Any]) -> str:
        """Generate human-readable penetration test report"""
        report = f"""
# Penetration Test Report

## Executive Summary
- **Target**: {results['target_url']}
- **Test Duration**: {results['test_duration_seconds']} seconds
- **Total Vulnerabilities**: {results['total_vulnerabilities']}
- **Risk Score**: {results['risk_score']}/100

## Vulnerability Breakdown
- **Critical**: {results['severity_breakdown']['critical']}
- **High**: {results['severity_breakdown']['high']}
- **Medium**: {results['severity_breakdown']['medium']}
- **Low**: {results['severity_breakdown']['low']}

## Key Findings
"""
        
        for vuln in results['all_vulnerabilities'][:5]:  # Top 5 vulnerabilities
            report += f"""
### {vuln['type'].replace('_', ' ').title()}
- **Severity**: {vuln['severity'].upper()}
- **Payload**: `{vuln['payload']}`
- **Evidence**: {vuln['evidence']}
"""
        
        report += "\n## Recommendations\n"
        for i, rec in enumerate(results['recommendations'], 1):
            report += f"{i}. {rec}\n"
        
        return report

# Usage example
async def run_pentest():
    """Run penetration test against Infinite AI Security"""
    tester = PenetrationTester("http://localhost:8000")
    
    results = await tester.run_full_pentest()
    
    print("🔍 Penetration Test Results:")
    print(f"   Total Vulnerabilities: {results['total_vulnerabilities']}")
    print(f"   Risk Score: {results['risk_score']}/100")
    print(f"   Critical: {results['severity_breakdown']['critical']}")
    print(f"   High: {results['severity_breakdown']['high']}")
    
    # Generate detailed report
    report = tester.generate_report(results)
    
    # Save report
    with open("pentest_report.md", "w") as f:
        f.write(report)
    
    print("📄 Detailed report saved to: pentest_report.md")
    
    return results

if __name__ == "__main__":
    asyncio.run(run_pentest())