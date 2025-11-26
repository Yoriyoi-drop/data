"""
Source Code Reverse Engineering and Analysis
"""
import ast
import re
import os
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

@dataclass
class CodeFunction:
    name: str
    line_start: int
    line_end: int
    complexity: int
    parameters: List[str]
    return_type: Optional[str]
    calls: List[str]
    vulnerabilities: List[Dict]

class CodeAnalyzer:
    def __init__(self):
        self.vulnerability_patterns = self._load_vulnerability_patterns()
        self.crypto_patterns = self._load_crypto_patterns()
    
    def analyze_source_code(self, file_path: str) -> Dict[str, Any]:
        """Comprehensive source code analysis"""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Source file not found: {file_path}")
        
        file_ext = os.path.splitext(file_path)[1].lower()
        
        if file_ext == '.py':
            return self._analyze_python(file_path)
        elif file_ext in ['.js', '.ts']:
            return self._analyze_javascript(file_path)
        elif file_ext in ['.c', '.cpp', '.h', '.hpp']:
            return self._analyze_c_cpp(file_path)
        elif file_ext == '.go':
            return self._analyze_go(file_path)
        elif file_ext == '.rs':
            return self._analyze_rust(file_path)
        else:
            return self._analyze_generic(file_path)
    
    def extract_api_calls(self, file_path: str) -> List[Dict]:
        """Extract API calls and external dependencies"""
        api_calls = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Common API patterns
            patterns = [
                (r'requests\.(get|post|put|delete)\s*\(', 'HTTP Request'),
                (r'socket\.(socket|connect|bind)', 'Network Socket'),
                (r'subprocess\.(run|call|Popen)', 'Process Execution'),
                (r'os\.(system|popen|exec)', 'System Command'),
                (r'eval\s*\(', 'Code Evaluation'),
                (r'exec\s*\(', 'Code Execution'),
                (r'open\s*\(.*["\']w', 'File Write'),
                (r'sqlite3\.connect', 'Database Connection')
            ]
            
            for pattern, api_type in patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    api_calls.append({
                        'type': api_type,
                        'pattern': match.group(),
                        'line': line_num,
                        'risk_level': self._assess_api_risk(api_type)
                    })
        
        except Exception:
            pass
        
        return api_calls
    
    def find_hardcoded_secrets(self, file_path: str) -> List[Dict]:
        """Find hardcoded secrets and credentials"""
        secrets = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            secret_patterns = [
                (r'password\s*=\s*["\'][^"\']+["\']', 'Hardcoded Password'),
                (r'api_key\s*=\s*["\'][^"\']+["\']', 'API Key'),
                (r'secret\s*=\s*["\'][^"\']+["\']', 'Secret Key'),
                (r'token\s*=\s*["\'][^"\']+["\']', 'Access Token'),
                (r'["\'][A-Za-z0-9+/]{40,}["\']', 'Base64 Encoded Data'),
                (r'["\'][0-9a-fA-F]{32,}["\']', 'Hex Encoded Data')
            ]
            
            for line_num, line in enumerate(lines, 1):
                for pattern, secret_type in secret_patterns:
                    matches = re.finditer(pattern, line, re.IGNORECASE)
                    for match in matches:
                        secrets.append({
                            'type': secret_type,
                            'line': line_num,
                            'content': match.group()[:50] + '...',
                            'severity': 'High'
                        })
        
        except Exception:
            pass
        
        return secrets
    
    def analyze_control_flow(self, file_path: str) -> Dict:
        """Analyze control flow and complexity"""
        flow_analysis = {
            'cyclomatic_complexity': 0,
            'nesting_depth': 0,
            'function_count': 0,
            'class_count': 0,
            'complexity_score': 'Low'
        }
        
        try:
            if file_path.endswith('.py'):
                flow_analysis = self._analyze_python_flow(file_path)
            else:
                flow_analysis = self._analyze_generic_flow(file_path)
        except Exception:
            pass
        
        return flow_analysis
    
    def extract_crypto_usage(self, file_path: str) -> List[Dict]:
        """Extract cryptographic usage patterns"""
        crypto_usage = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            for pattern, crypto_type in self.crypto_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    crypto_usage.append({
                        'type': crypto_type,
                        'pattern': match.group(),
                        'line': line_num,
                        'strength': self._assess_crypto_strength(crypto_type)
                    })
        
        except Exception:
            pass
        
        return crypto_usage
    
    def _analyze_python(self, file_path: str) -> Dict[str, Any]:
        """Analyze Python source code"""
        analysis = {
            'language': 'Python',
            'functions': [],
            'classes': [],
            'imports': [],
            'vulnerabilities': [],
            'api_calls': [],
            'secrets': [],
            'control_flow': {},
            'crypto_usage': []
        }
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Parse AST
            tree = ast.parse(content)
            
            # Extract functions and classes
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    func_info = {
                        'name': node.name,
                        'line_start': node.lineno,
                        'line_end': node.end_lineno or node.lineno,
                        'args': [arg.arg for arg in node.args.args],
                        'decorators': [d.id if hasattr(d, 'id') else str(d) for d in node.decorator_list]
                    }
                    analysis['functions'].append(func_info)
                
                elif isinstance(node, ast.ClassDef):
                    class_info = {
                        'name': node.name,
                        'line_start': node.lineno,
                        'line_end': node.end_lineno or node.lineno,
                        'bases': [base.id if hasattr(base, 'id') else str(base) for base in node.bases]
                    }
                    analysis['classes'].append(class_info)
                
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        analysis['imports'].append(alias.name)
                
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        analysis['imports'].append(node.module)
            
            # Additional analysis
            analysis['api_calls'] = self.extract_api_calls(file_path)
            analysis['secrets'] = self.find_hardcoded_secrets(file_path)
            analysis['control_flow'] = self.analyze_control_flow(file_path)
            analysis['crypto_usage'] = self.extract_crypto_usage(file_path)
            analysis['vulnerabilities'] = self._scan_vulnerabilities(content)
        
        except Exception as e:
            analysis['error'] = str(e)
        
        return analysis
    
    def _analyze_javascript(self, file_path: str) -> Dict[str, Any]:
        """Analyze JavaScript/TypeScript source code"""
        analysis = {
            'language': 'JavaScript/TypeScript',
            'functions': [],
            'variables': [],
            'vulnerabilities': [],
            'api_calls': [],
            'secrets': []
        }
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Extract functions
            func_pattern = r'function\s+(\w+)\s*\([^)]*\)|(\w+)\s*=\s*function|\w+\s*=>\s*'
            functions = re.finditer(func_pattern, content)
            for match in functions:
                line_num = content[:match.start()].count('\n') + 1
                analysis['functions'].append({
                    'name': match.group(1) or 'anonymous',
                    'line': line_num,
                    'type': 'function'
                })
            
            # Extract variables
            var_pattern = r'(var|let|const)\s+(\w+)'
            variables = re.finditer(var_pattern, content)
            for match in variables:
                line_num = content[:match.start()].count('\n') + 1
                analysis['variables'].append({
                    'name': match.group(2),
                    'type': match.group(1),
                    'line': line_num
                })
            
            analysis['api_calls'] = self.extract_api_calls(file_path)
            analysis['secrets'] = self.find_hardcoded_secrets(file_path)
            analysis['vulnerabilities'] = self._scan_js_vulnerabilities(content)
        
        except Exception as e:
            analysis['error'] = str(e)
        
        return analysis
    
    def _analyze_c_cpp(self, file_path: str) -> Dict[str, Any]:
        """Analyze C/C++ source code"""
        analysis = {
            'language': 'C/C++',
            'functions': [],
            'includes': [],
            'vulnerabilities': [],
            'buffer_operations': []
        }
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Extract includes
            include_pattern = r'#include\s*[<"](.*?)[>"]'
            includes = re.finditer(include_pattern, content)
            for match in includes:
                analysis['includes'].append(match.group(1))
            
            # Extract functions
            func_pattern = r'(\w+)\s+(\w+)\s*\([^)]*\)\s*{'
            functions = re.finditer(func_pattern, content)
            for match in functions:
                line_num = content[:match.start()].count('\n') + 1
                analysis['functions'].append({
                    'return_type': match.group(1),
                    'name': match.group(2),
                    'line': line_num
                })
            
            # Check for dangerous functions
            dangerous_funcs = ['strcpy', 'strcat', 'sprintf', 'gets', 'scanf']
            for func in dangerous_funcs:
                if func in content:
                    analysis['vulnerabilities'].append({
                        'type': 'Buffer Overflow Risk',
                        'function': func,
                        'severity': 'High'
                    })
        
        except Exception as e:
            analysis['error'] = str(e)
        
        return analysis
    
    def _analyze_go(self, file_path: str) -> Dict[str, Any]:
        """Analyze Go source code"""
        analysis = {
            'language': 'Go',
            'functions': [],
            'imports': [],
            'structs': [],
            'vulnerabilities': []
        }
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Extract functions
            func_pattern = r'func\s+(\w+)\s*\([^)]*\)'
            functions = re.finditer(func_pattern, content)
            for match in functions:
                line_num = content[:match.start()].count('\n') + 1
                analysis['functions'].append({
                    'name': match.group(1),
                    'line': line_num
                })
            
            # Extract imports
            import_pattern = r'import\s+"([^"]+)"'
            imports = re.finditer(import_pattern, content)
            for match in imports:
                analysis['imports'].append(match.group(1))
        
        except Exception as e:
            analysis['error'] = str(e)
        
        return analysis
    
    def _analyze_rust(self, file_path: str) -> Dict[str, Any]:
        """Analyze Rust source code"""
        analysis = {
            'language': 'Rust',
            'functions': [],
            'structs': [],
            'traits': [],
            'unsafe_blocks': []
        }
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Extract functions
            func_pattern = r'fn\s+(\w+)\s*\([^)]*\)'
            functions = re.finditer(func_pattern, content)
            for match in functions:
                line_num = content[:match.start()].count('\n') + 1
                analysis['functions'].append({
                    'name': match.group(1),
                    'line': line_num
                })
            
            # Find unsafe blocks
            unsafe_pattern = r'unsafe\s*{'
            unsafe_blocks = re.finditer(unsafe_pattern, content)
            for match in unsafe_blocks:
                line_num = content[:match.start()].count('\n') + 1
                analysis['unsafe_blocks'].append({
                    'line': line_num,
                    'warning': 'Unsafe code block detected'
                })
        
        except Exception as e:
            analysis['error'] = str(e)
        
        return analysis
    
    def _analyze_generic(self, file_path: str) -> Dict[str, Any]:
        """Generic analysis for unknown file types"""
        analysis = {
            'language': 'Unknown',
            'line_count': 0,
            'secrets': [],
            'api_calls': []
        }
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            analysis['line_count'] = len(lines)
            analysis['secrets'] = self.find_hardcoded_secrets(file_path)
            analysis['api_calls'] = self.extract_api_calls(file_path)
        
        except Exception as e:
            analysis['error'] = str(e)
        
        return analysis
    
    def _analyze_python_flow(self, file_path: str) -> Dict:
        """Analyze Python control flow complexity"""
        complexity = 1  # Base complexity
        nesting_depth = 0
        max_nesting = 0
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            current_indent = 0
            for line in lines:
                stripped = line.lstrip()
                if not stripped or stripped.startswith('#'):
                    continue
                
                indent = len(line) - len(stripped)
                
                # Track nesting depth
                if indent > current_indent:
                    nesting_depth += 1
                    max_nesting = max(max_nesting, nesting_depth)
                elif indent < current_indent:
                    nesting_depth = max(0, nesting_depth - 1)
                
                current_indent = indent
                
                # Count complexity-increasing constructs
                if any(stripped.startswith(keyword) for keyword in ['if', 'elif', 'for', 'while', 'try', 'except']):
                    complexity += 1
        
        except Exception:
            pass
        
        return {
            'cyclomatic_complexity': complexity,
            'nesting_depth': max_nesting,
            'complexity_score': 'Low' if complexity < 10 else 'Medium' if complexity < 20 else 'High'
        }
    
    def _analyze_generic_flow(self, file_path: str) -> Dict:
        """Generic control flow analysis"""
        return {
            'cyclomatic_complexity': 1,
            'nesting_depth': 0,
            'complexity_score': 'Unknown'
        }
    
    def _scan_vulnerabilities(self, content: str) -> List[Dict]:
        """Scan for common vulnerabilities in code"""
        vulnerabilities = []
        
        for pattern, vuln_type, severity in self.vulnerability_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                vulnerabilities.append({
                    'type': vuln_type,
                    'line': line_num,
                    'pattern': match.group(),
                    'severity': severity
                })
        
        return vulnerabilities
    
    def _scan_js_vulnerabilities(self, content: str) -> List[Dict]:
        """Scan for JavaScript-specific vulnerabilities"""
        js_vulns = [
            (r'eval\s*\(', 'Code Injection', 'High'),
            (r'innerHTML\s*=', 'XSS Risk', 'Medium'),
            (r'document\.write\s*\(', 'XSS Risk', 'Medium'),
            (r'setTimeout\s*\(\s*["\']', 'Code Injection', 'High')
        ]
        
        vulnerabilities = []
        for pattern, vuln_type, severity in js_vulns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                vulnerabilities.append({
                    'type': vuln_type,
                    'line': line_num,
                    'pattern': match.group(),
                    'severity': severity
                })
        
        return vulnerabilities
    
    def _assess_api_risk(self, api_type: str) -> str:
        """Assess risk level of API call"""
        high_risk = ['Code Evaluation', 'Code Execution', 'System Command', 'Process Execution']
        medium_risk = ['Network Socket', 'File Write', 'Database Connection']
        
        if api_type in high_risk:
            return 'High'
        elif api_type in medium_risk:
            return 'Medium'
        else:
            return 'Low'
    
    def _assess_crypto_strength(self, crypto_type: str) -> str:
        """Assess cryptographic strength"""
        strong = ['AES-256', 'RSA-2048', 'SHA-256']
        weak = ['MD5', 'SHA-1', 'DES']
        
        if any(strong_algo in crypto_type for strong_algo in strong):
            return 'Strong'
        elif any(weak_algo in crypto_type for weak_algo in weak):
            return 'Weak'
        else:
            return 'Medium'
    
    def _load_vulnerability_patterns(self) -> List[tuple]:
        """Load vulnerability detection patterns"""
        return [
            (r'eval\s*\(', 'Code Injection', 'High'),
            (r'exec\s*\(', 'Code Execution', 'High'),
            (r'os\.system\s*\(', 'Command Injection', 'High'),
            (r'subprocess\.call\s*\(', 'Command Execution', 'Medium'),
            (r'pickle\.loads\s*\(', 'Deserialization', 'High'),
            (r'input\s*\(.*\)', 'Input Validation', 'Medium'),
            (r'open\s*\(.*["\']w', 'File Write', 'Medium')
        ]
    
    def _load_crypto_patterns(self) -> List[tuple]:
        """Load cryptographic pattern detection"""
        return [
            (r'AES\.new\s*\(', 'AES Encryption'),
            (r'RSA\.generate\s*\(', 'RSA Key Generation'),
            (r'hashlib\.md5\s*\(', 'MD5 Hash'),
            (r'hashlib\.sha256\s*\(', 'SHA-256 Hash'),
            (r'Crypto\.Cipher', 'PyCrypto Usage'),
            (r'cryptography\.', 'Cryptography Library')
        ]

# Global instance
code_analyzer = CodeAnalyzer()