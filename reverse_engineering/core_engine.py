"""
Core Reverse Engineering Engine
Multi-language binary analysis and code reconstruction
"""
import os
import struct
import hashlib
import json
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from pathlib import Path

@dataclass
class BinaryAnalysis:
    file_path: str
    file_type: str
    architecture: str
    entry_point: str
    sections: List[Dict]
    imports: List[str]
    exports: List[str]
    strings: List[str]
    functions: List[Dict]
    vulnerabilities: List[Dict]

class ReverseEngineeringEngine:
    def __init__(self):
        self.supported_formats = ['.exe', '.dll', '.so', '.dylib', '.bin', '.elf']
        self.analysis_cache = {}
    
    def analyze_binary(self, file_path: str) -> BinaryAnalysis:
        """Comprehensive binary analysis"""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Binary not found: {file_path}")
        
        file_hash = self._get_file_hash(file_path)
        if file_hash in self.analysis_cache:
            return self.analysis_cache[file_hash]
        
        analysis = BinaryAnalysis(
            file_path=file_path,
            file_type=self._detect_file_type(file_path),
            architecture=self._detect_architecture(file_path),
            entry_point=self._find_entry_point(file_path),
            sections=self._analyze_sections(file_path),
            imports=self._extract_imports(file_path),
            exports=self._extract_exports(file_path),
            strings=self._extract_strings(file_path),
            functions=self._analyze_functions(file_path),
            vulnerabilities=self._scan_vulnerabilities(file_path)
        )
        
        self.analysis_cache[file_hash] = analysis
        return analysis
    
    def decompile_function(self, binary_path: str, function_addr: int) -> str:
        """Decompile specific function to pseudo-code"""
        try:
            # Simulate decompilation process
            with open(binary_path, 'rb') as f:
                f.seek(function_addr)
                raw_bytes = f.read(256)
            
            # Basic disassembly simulation
            pseudo_code = self._bytes_to_pseudocode(raw_bytes, function_addr)
            return pseudo_code
        except Exception as e:
            return f"// Decompilation failed: {str(e)}"
    
    def extract_crypto_keys(self, binary_path: str) -> List[Dict]:
        """Extract potential cryptographic keys and constants"""
        keys = []
        try:
            with open(binary_path, 'rb') as f:
                data = f.read()
            
            # Look for common crypto patterns
            patterns = [
                (b'\x30\x82', 'RSA Private Key'),
                (b'-----BEGIN', 'PEM Certificate'),
                (b'\x04\x08\x0c\x10\x14\x18\x1c', 'AES S-Box'),
                (b'\x67\x45\x23\x01', 'MD5 Constants')
            ]
            
            for pattern, key_type in patterns:
                offset = data.find(pattern)
                if offset != -1:
                    keys.append({
                        'type': key_type,
                        'offset': hex(offset),
                        'size': len(pattern),
                        'confidence': 0.8
                    })
        except Exception:
            pass
        
        return keys
    
    def analyze_network_behavior(self, binary_path: str) -> Dict:
        """Analyze network-related functionality"""
        network_analysis = {
            'domains': [],
            'ips': [],
            'ports': [],
            'protocols': [],
            'api_calls': []
        }
        
        try:
            strings = self._extract_strings(binary_path)
            
            # Look for network indicators
            for string in strings:
                if '.' in string and len(string.split('.')) == 4:
                    # Potential IP address
                    network_analysis['ips'].append(string)
                elif string.startswith('http'):
                    # URL/domain
                    network_analysis['domains'].append(string)
                elif string in ['socket', 'connect', 'send', 'recv']:
                    # Network API calls
                    network_analysis['api_calls'].append(string)
        except Exception:
            pass
        
        return network_analysis
    
    def _get_file_hash(self, file_path: str) -> str:
        """Calculate file hash for caching"""
        with open(file_path, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    
    def _detect_file_type(self, file_path: str) -> str:
        """Detect binary file type"""
        try:
            with open(file_path, 'rb') as f:
                header = f.read(16)
            
            if header.startswith(b'MZ'):
                return 'PE (Windows Executable)'
            elif header.startswith(b'\x7fELF'):
                return 'ELF (Linux Executable)'
            elif header.startswith(b'\xfe\xed\xfa'):
                return 'Mach-O (macOS Executable)'
            else:
                return 'Unknown Binary Format'
        except Exception:
            return 'Analysis Failed'
    
    def _detect_architecture(self, file_path: str) -> str:
        """Detect target architecture"""
        try:
            with open(file_path, 'rb') as f:
                header = f.read(64)
            
            if b'x86_64' in header or b'AMD64' in header:
                return 'x86_64'
            elif b'i386' in header or b'x86' in header:
                return 'x86'
            elif b'ARM' in header:
                return 'ARM'
            else:
                return 'Unknown Architecture'
        except Exception:
            return 'Detection Failed'
    
    def _find_entry_point(self, file_path: str) -> str:
        """Find binary entry point"""
        try:
            with open(file_path, 'rb') as f:
                f.seek(0x18)  # PE entry point offset
                entry_bytes = f.read(4)
                entry_point = struct.unpack('<I', entry_bytes)[0]
                return hex(entry_point)
        except Exception:
            return '0x00000000'
    
    def _analyze_sections(self, file_path: str) -> List[Dict]:
        """Analyze binary sections"""
        sections = []
        try:
            # Simulate section analysis
            common_sections = [
                {'name': '.text', 'offset': '0x1000', 'size': '0x5000', 'permissions': 'rx'},
                {'name': '.data', 'offset': '0x6000', 'size': '0x2000', 'permissions': 'rw'},
                {'name': '.rdata', 'offset': '0x8000', 'size': '0x1000', 'permissions': 'r'}
            ]
            sections.extend(common_sections)
        except Exception:
            pass
        
        return sections
    
    def _extract_imports(self, file_path: str) -> List[str]:
        """Extract imported functions"""
        imports = []
        try:
            # Simulate import extraction
            common_imports = [
                'kernel32.dll!CreateFileA',
                'kernel32.dll!ReadFile',
                'kernel32.dll!WriteFile',
                'ws2_32.dll!socket',
                'ws2_32.dll!connect'
            ]
            imports.extend(common_imports)
        except Exception:
            pass
        
        return imports
    
    def _extract_exports(self, file_path: str) -> List[str]:
        """Extract exported functions"""
        exports = []
        try:
            # Simulate export extraction
            if file_path.endswith('.dll'):
                exports = ['DllMain', 'ExportedFunction1', 'ExportedFunction2']
        except Exception:
            pass
        
        return exports
    
    def _extract_strings(self, file_path: str) -> List[str]:
        """Extract readable strings from binary"""
        strings = []
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            # Extract ASCII strings (length >= 4)
            current_string = ""
            for byte in data:
                if 32 <= byte <= 126:  # Printable ASCII
                    current_string += chr(byte)
                else:
                    if len(current_string) >= 4:
                        strings.append(current_string)
                    current_string = ""
            
            # Add final string if valid
            if len(current_string) >= 4:
                strings.append(current_string)
                
        except Exception:
            pass
        
        return strings[:100]  # Limit to first 100 strings
    
    def _analyze_functions(self, file_path: str) -> List[Dict]:
        """Analyze functions in binary"""
        functions = []
        try:
            # Simulate function analysis
            sample_functions = [
                {'name': 'main', 'address': '0x401000', 'size': 256, 'calls': ['printf', 'malloc']},
                {'name': 'sub_401100', 'address': '0x401100', 'size': 128, 'calls': ['strcpy', 'strlen']},
                {'name': 'sub_401200', 'address': '0x401200', 'size': 64, 'calls': ['socket', 'connect']}
            ]
            functions.extend(sample_functions)
        except Exception:
            pass
        
        return functions
    
    def _scan_vulnerabilities(self, file_path: str) -> List[Dict]:
        """Scan for potential vulnerabilities"""
        vulnerabilities = []
        try:
            strings = self._extract_strings(file_path)
            
            # Check for dangerous functions
            dangerous_funcs = ['strcpy', 'sprintf', 'gets', 'scanf']
            for func in dangerous_funcs:
                if any(func in s for s in strings):
                    vulnerabilities.append({
                        'type': 'Buffer Overflow Risk',
                        'function': func,
                        'severity': 'High',
                        'description': f'Use of dangerous function: {func}'
                    })
            
            # Check for hardcoded credentials
            for string in strings:
                if any(keyword in string.lower() for keyword in ['password', 'secret', 'key']):
                    vulnerabilities.append({
                        'type': 'Hardcoded Credentials',
                        'string': string,
                        'severity': 'Medium',
                        'description': 'Potential hardcoded sensitive data'
                    })
                    
        except Exception:
            pass
        
        return vulnerabilities
    
    def _bytes_to_pseudocode(self, raw_bytes: bytes, base_addr: int) -> str:
        """Convert raw bytes to pseudo-code representation"""
        pseudocode = f"// Function at 0x{base_addr:08x}\n"
        pseudocode += "function_start:\n"
        
        # Simulate basic instruction analysis
        for i in range(0, min(len(raw_bytes), 64), 4):
            chunk = raw_bytes[i:i+4]
            addr = base_addr + i
            
            # Basic pattern matching for common instructions
            if chunk[0] == 0x55:  # push ebp
                pseudocode += f"  0x{addr:08x}: push ebp\n"
            elif chunk[0] == 0x89:  # mov
                pseudocode += f"  0x{addr:08x}: mov instruction\n"
            elif chunk[0] == 0xc3:  # ret
                pseudocode += f"  0x{addr:08x}: return\n"
                break
            else:
                pseudocode += f"  0x{addr:08x}: unknown_instruction\n"
        
        pseudocode += "function_end:\n"
        return pseudocode

# Global instance
reverse_engine = ReverseEngineeringEngine()