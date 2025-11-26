"""
Reverse Engineering API Routes
"""
from fastapi import APIRouter, HTTPException, UploadFile, File, Form
from typing import Dict, Any, Optional
import os
import tempfile
import shutil
from ..reverse_engineering.core_engine import reverse_engine
from ..reverse_engineering.malware_analyzer import malware_analyzer
from ..reverse_engineering.code_analyzer import code_analyzer
from ..ai_agents.claude_agent import ClaudeAgent
from ..ai_agents.grok_agent import GrokAgent

router = APIRouter(prefix="/api/reverse-engineering", tags=["reverse-engineering"])

@router.post("/analyze-binary")
async def analyze_binary_file(
    file: UploadFile = File(...),
    analysis_type: str = Form("comprehensive")
):
    """Analyze uploaded binary file"""
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")
    
    # Save uploaded file temporarily
    with tempfile.NamedTemporaryFile(delete=False, suffix=f"_{file.filename}") as tmp_file:
        shutil.copyfileobj(file.file, tmp_file)
        tmp_path = tmp_file.name
    
    try:
        if analysis_type == "comprehensive":
            # Full analysis with all engines
            binary_analysis = reverse_engine.analyze_binary(tmp_path)
            malware_analysis = malware_analyzer.analyze_malware(tmp_path)
            
            # AI agent analysis
            claude_agent = ClaudeAgent()
            grok_agent = GrokAgent()
            
            claude_result = await claude_agent.run_task({
                "type": "reverse_engineering",
                "data": {"file_path": tmp_path}
            })
            
            grok_result = await grok_agent.run_task({
                "type": "binary_pattern_analysis", 
                "data": {"file_path": tmp_path}
            })
            
            return {
                "filename": file.filename,
                "analysis_type": analysis_type,
                "binary_analysis": {
                    "file_type": binary_analysis.file_type,
                    "architecture": binary_analysis.architecture,
                    "entry_point": binary_analysis.entry_point,
                    "sections": binary_analysis.sections,
                    "imports": binary_analysis.imports[:20],  # Limit for response size
                    "exports": binary_analysis.exports,
                    "strings": binary_analysis.strings[:50],
                    "functions": binary_analysis.functions,
                    "vulnerabilities": binary_analysis.vulnerabilities
                },
                "malware_analysis": malware_analysis,
                "ai_analysis": {
                    "claude": claude_result,
                    "grok": grok_result
                },
                "status": "success"
            }
        
        elif analysis_type == "quick":
            # Quick analysis
            binary_analysis = reverse_engine.analyze_binary(tmp_path)
            
            return {
                "filename": file.filename,
                "analysis_type": analysis_type,
                "file_type": binary_analysis.file_type,
                "architecture": binary_analysis.architecture,
                "threat_score": len(binary_analysis.vulnerabilities) * 20,
                "status": "success"
            }
        
        else:
            raise HTTPException(status_code=400, detail="Invalid analysis type")
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")
    
    finally:
        # Cleanup temporary file
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)

@router.post("/analyze-source-code")
async def analyze_source_code(
    file: UploadFile = File(...),
    language: Optional[str] = Form(None)
):
    """Analyze uploaded source code file"""
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")
    
    # Save uploaded file temporarily
    with tempfile.NamedTemporaryFile(delete=False, suffix=f"_{file.filename}") as tmp_file:
        content = await file.read()
        tmp_file.write(content)
        tmp_path = tmp_file.name
    
    try:
        # Source code analysis
        analysis = code_analyzer.analyze_source_code(tmp_path)
        api_calls = code_analyzer.extract_api_calls(tmp_path)
        secrets = code_analyzer.find_hardcoded_secrets(tmp_path)
        crypto_usage = code_analyzer.extract_crypto_usage(tmp_path)
        control_flow = code_analyzer.analyze_control_flow(tmp_path)
        
        # AI agent analysis
        claude_agent = ClaudeAgent()
        claude_result = await claude_agent.run_task({
            "type": "source_analysis",
            "data": {"file_path": tmp_path}
        })
        
        return {
            "filename": file.filename,
            "language": analysis.get('language', language),
            "source_analysis": analysis,
            "api_calls": api_calls,
            "hardcoded_secrets": secrets,
            "crypto_usage": crypto_usage,
            "control_flow": control_flow,
            "ai_analysis": claude_result,
            "security_recommendations": _generate_security_recommendations(analysis, secrets, api_calls),
            "status": "success"
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Source analysis failed: {str(e)}")
    
    finally:
        # Cleanup temporary file
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)

@router.post("/extract-iocs")
async def extract_indicators_of_compromise(
    file: UploadFile = File(...)
):
    """Extract Indicators of Compromise from file"""
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")
    
    # Save uploaded file temporarily
    with tempfile.NamedTemporaryFile(delete=False, suffix=f"_{file.filename}") as tmp_file:
        shutil.copyfileobj(file.file, tmp_file)
        tmp_path = tmp_file.name
    
    try:
        # Extract IOCs
        iocs = malware_analyzer.extract_iocs(tmp_path)
        
        # Generate YARA rule
        yara_rule = malware_analyzer.generate_yara_rule(tmp_path, f"rule_{file.filename.replace('.', '_')}")
        
        return {
            "filename": file.filename,
            "iocs": iocs,
            "yara_rule": yara_rule,
            "ioc_count": sum(len(ioc_list) for ioc_list in iocs.values()),
            "status": "success"
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"IOC extraction failed: {str(e)}")
    
    finally:
        # Cleanup temporary file
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)

@router.post("/decompile-function")
async def decompile_function(
    file: UploadFile = File(...),
    function_address: str = Form(...)
):
    """Decompile specific function from binary"""
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")
    
    try:
        # Convert hex address to int
        addr = int(function_address, 16) if function_address.startswith('0x') else int(function_address)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid function address")
    
    # Save uploaded file temporarily
    with tempfile.NamedTemporaryFile(delete=False, suffix=f"_{file.filename}") as tmp_file:
        shutil.copyfileobj(file.file, tmp_file)
        tmp_path = tmp_file.name
    
    try:
        # Decompile function
        pseudo_code = reverse_engine.decompile_function(tmp_path, addr)
        
        return {
            "filename": file.filename,
            "function_address": function_address,
            "pseudo_code": pseudo_code,
            "status": "success"
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Decompilation failed: {str(e)}")
    
    finally:
        # Cleanup temporary file
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)

@router.post("/detect-malware-family")
async def detect_malware_family(
    file: UploadFile = File(...)
):
    """Detect malware family using pattern analysis"""
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")
    
    # Save uploaded file temporarily
    with tempfile.NamedTemporaryFile(delete=False, suffix=f"_{file.filename}") as tmp_file:
        shutil.copyfileobj(file.file, tmp_file)
        tmp_path = tmp_file.name
    
    try:
        # Grok agent for pattern analysis
        grok_agent = GrokAgent()
        
        family_result = await grok_agent.run_task({
            "type": "malware_family_detection",
            "data": {"file_path": tmp_path}
        })
        
        signature_result = await grok_agent.run_task({
            "type": "signature_detection", 
            "data": {"file_path": tmp_path}
        })
        
        return {
            "filename": file.filename,
            "family_detection": family_result,
            "signature_analysis": signature_result,
            "status": "success"
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Family detection failed: {str(e)}")
    
    finally:
        # Cleanup temporary file
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)

@router.post("/analyze-crypto-patterns")
async def analyze_crypto_patterns(
    file: UploadFile = File(...)
):
    """Analyze cryptographic patterns in file"""
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")
    
    # Save uploaded file temporarily
    with tempfile.NamedTemporaryFile(delete=False, suffix=f"_{file.filename}") as tmp_file:
        shutil.copyfileobj(file.file, tmp_file)
        tmp_path = tmp_file.name
    
    try:
        # Extract crypto keys
        crypto_keys = reverse_engine.extract_crypto_keys(tmp_path)
        
        # Grok agent for crypto pattern analysis
        grok_agent = GrokAgent()
        crypto_analysis = await grok_agent.run_task({
            "type": "crypto_pattern_analysis",
            "data": {"file_path": tmp_path}
        })
        
        return {
            "filename": file.filename,
            "crypto_keys": crypto_keys,
            "pattern_analysis": crypto_analysis,
            "ransomware_risk": _assess_ransomware_risk(crypto_keys, crypto_analysis),
            "status": "success"
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Crypto analysis failed: {str(e)}")
    
    finally:
        # Cleanup temporary file
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)

@router.post("/analyze-network-behavior")
async def analyze_network_behavior(
    file: UploadFile = File(...)
):
    """Analyze network behavior patterns"""
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")
    
    # Save uploaded file temporarily
    with tempfile.NamedTemporaryFile(delete=False, suffix=f"_{file.filename}") as tmp_file:
        shutil.copyfileobj(file.file, tmp_file)
        tmp_path = tmp_file.name
    
    try:
        # Network behavior analysis
        network_analysis = reverse_engine.analyze_network_behavior(tmp_path)
        
        # Grok agent for network pattern analysis
        grok_agent = GrokAgent()
        pattern_analysis = await grok_agent.run_task({
            "type": "network_pattern_analysis",
            "data": {"file_path": tmp_path}
        })
        
        return {
            "filename": file.filename,
            "network_indicators": network_analysis,
            "pattern_analysis": pattern_analysis,
            "c2_probability": _calculate_c2_probability(network_analysis, pattern_analysis),
            "status": "success"
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Network analysis failed: {str(e)}")
    
    finally:
        # Cleanup temporary file
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)

@router.get("/analysis-capabilities")
async def get_analysis_capabilities():
    """Get available reverse engineering capabilities"""
    return {
        "binary_analysis": {
            "supported_formats": [".exe", ".dll", ".so", ".dylib", ".bin", ".elf"],
            "capabilities": [
                "file_type_detection", "architecture_analysis", "section_analysis",
                "import_export_analysis", "string_extraction", "function_analysis",
                "vulnerability_scanning", "entry_point_detection"
            ]
        },
        "source_code_analysis": {
            "supported_languages": ["Python", "JavaScript", "TypeScript", "C", "C++", "Go", "Rust"],
            "capabilities": [
                "syntax_analysis", "vulnerability_detection", "api_call_extraction",
                "secret_detection", "complexity_analysis", "crypto_usage_analysis"
            ]
        },
        "malware_analysis": {
            "capabilities": [
                "signature_detection", "behavioral_analysis", "ioc_extraction",
                "family_classification", "packer_detection", "yara_rule_generation"
            ]
        },
        "ai_agents": {
            "claude": ["code_review", "compliance_check", "detailed_analysis"],
            "grok": ["pattern_recognition", "anomaly_detection", "signature_detection"]
        },
        "status": "operational"
    }

def _generate_security_recommendations(analysis: Dict, secrets: list, api_calls: list) -> list:
    """Generate security recommendations based on analysis"""
    recommendations = []
    
    if secrets:
        recommendations.append("Remove hardcoded secrets and use secure configuration")
    
    if analysis.get('vulnerabilities'):
        recommendations.append("Fix identified security vulnerabilities")
    
    high_risk_apis = [call for call in api_calls if call.get('risk_level') == 'High']
    if high_risk_apis:
        recommendations.append("Review high-risk API usage for security implications")
    
    complexity = analysis.get('control_flow', {}).get('complexity_score', 'Low')
    if complexity == 'High':
        recommendations.append("Refactor complex code to improve maintainability")
    
    return recommendations

def _assess_ransomware_risk(crypto_keys: list, crypto_analysis: Dict) -> str:
    """Assess ransomware risk based on crypto patterns"""
    risk_score = 0
    
    if crypto_keys:
        risk_score += len(crypto_keys) * 20
    
    if crypto_analysis.get('result', {}).get('crypto_analysis', {}).get('encryption_keys'):
        risk_score += 30
    
    if risk_score >= 70:
        return "High"
    elif risk_score >= 40:
        return "Medium"
    else:
        return "Low"

def _calculate_c2_probability(network_analysis: Dict, pattern_analysis: Dict) -> float:
    """Calculate command and control probability"""
    probability = 0.0
    
    if network_analysis.get('domains'):
        probability += 0.3
    
    if network_analysis.get('ips'):
        probability += 0.2
    
    pattern_result = pattern_analysis.get('result', {})
    if pattern_result.get('network_patterns', {}).get('c2_indicators'):
        probability += 0.4
    
    return min(probability, 1.0)