"""
Assembly Interface - Bridge between Python and ASM Security Core
"""
import ctypes
import os
from ctypes import Structure, c_int, c_char_p, c_void_p, POINTER

class ASMSecurityCore:
    def __init__(self):
        self.lib_path = os.path.join(os.path.dirname(__file__), 'libsecurity_core.so')
        self.lib = None
        self.load_library()
    
    def load_library(self):
        """Load ASM shared library"""
        try:
            if os.path.exists(self.lib_path):
                self.lib = ctypes.CDLL(self.lib_path)
                self.setup_functions()
            else:
                print(f"ASM library not found: {self.lib_path}")
                print("Run build.sh to compile ASM components")
        except Exception as e:
            print(f"Failed to load ASM library: {e}")
    
    def setup_functions(self):
        """Setup function signatures"""
        if not self.lib:
            return
        
        # security_init
        self.lib.security_init.argtypes = []
        self.lib.security_init.restype = None
        
        # fast_scan
        self.lib.fast_scan.argtypes = [c_char_p, c_int]
        self.lib.fast_scan.restype = c_int
        
        # threat_detect
        self.lib.threat_detect.argtypes = [c_char_p, c_int]
        self.lib.threat_detect.restype = c_int
        
        # memory_protect
        self.lib.memory_protect.argtypes = [c_void_p, c_int]
        self.lib.memory_protect.restype = c_int
        
        # crypto_hash
        self.lib.crypto_hash.argtypes = [c_char_p, c_int, POINTER(c_int)]
        self.lib.crypto_hash.restype = None
        
        # get_scan_stats
        self.lib.get_scan_stats.argtypes = []
        self.lib.get_scan_stats.restype = c_int
    
    def initialize(self):
        """Initialize ASM security core"""
        if self.lib:
            self.lib.security_init()
            return True
        return False
    
    def fast_scan(self, data):
        """Perform fast security scan"""
        if not self.lib:
            return 0
        
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        return self.lib.fast_scan(data, len(data))
    
    def threat_detect(self, data):
        """Advanced threat detection"""
        if not self.lib:
            return 0
        
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        return self.lib.threat_detect(data, len(data))
    
    def protect_memory(self, address, size):
        """Enable memory protection"""
        if not self.lib:
            return 0
        
        return self.lib.memory_protect(address, size)
    
    def compute_hash(self, data):
        """Compute cryptographic hash"""
        if not self.lib:
            return None
        
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        hash_result = (c_int * 3)()
        self.lib.crypto_hash(data, len(data), hash_result)
        
        return [hash_result[0], hash_result[1], hash_result[2]]
    
    def get_statistics(self):
        """Get scan statistics"""
        if not self.lib:
            return {"scan_count": 0, "threat_count": 0, "blocked_count": 0}
        
        # This is simplified - real implementation would return all stats
        scan_count = self.lib.get_scan_stats()
        
        return {
            "scan_count": scan_count,
            "threat_count": 0,  # Would be implemented in ASM
            "blocked_count": 0  # Would be implemented in ASM
        }

# Global instance
asm_security = ASMSecurityCore()

def scan_with_asm(data):
    """High-level interface for ASM scanning"""
    if not asm_security.lib:
        # Fallback to Python implementation
        return python_fallback_scan(data)
    
    return asm_security.fast_scan(data)

def python_fallback_scan(data):
    """Python fallback when ASM is not available"""
    threat_patterns = ['SELECT', '<script>', '; rm -rf', 'DROP TABLE']
    
    for pattern in threat_patterns:
        if pattern.lower() in data.lower():
            return 1  # Threat detected
    
    return 0  # Clean

if __name__ == "__main__":
    # Test ASM interface
    print("Testing ASM Security Interface...")
    
    if asm_security.initialize():
        print("ASM Security Core initialized successfully")
        
        # Test scans
        test_data = [
            "normal user input",
            "SELECT * FROM users",
            "<script>alert('xss')</script>",
            "; rm -rf /",
            "clean data"
        ]
        
        for data in test_data:
            result = asm_security.fast_scan(data)
            status = "THREAT" if result else "CLEAN"
            print(f"Scan: '{data[:30]}...' -> {status}")
        
        # Get statistics
        stats = asm_security.get_statistics()
        print(f"Statistics: {stats}")
        
    else:
        print("ASM Security Core not available, using Python fallback")
        
        for data in ["SELECT * FROM users", "normal input"]:
            result = python_fallback_scan(data)
            status = "THREAT" if result else "CLEAN"
            print(f"Fallback scan: '{data}' -> {status}")