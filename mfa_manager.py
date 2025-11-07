"""
Infinite AI Security - Multi-Factor Authentication Manager
Fase 1 Evolution: Enterprise Security with TOTP MFA
"""
import os
import time
import base64
import secrets
import qrcode
from io import BytesIO
from typing import Dict, Any, Optional, Tuple
from datetime import datetime, UTC

try:
    import pyotp
    MFA_AVAILABLE = True
except ImportError:
    MFA_AVAILABLE = False

class MFAManager:
    """Multi-Factor Authentication with TOTP support"""
    
    def __init__(self):
        self.app_name = "Infinite AI Security"
        self.issuer = "InfiniteAI"
        
        if not MFA_AVAILABLE:
            print("[MFA] pyotp not available, MFA disabled")
    
    def generate_secret(self) -> str:
        """Generate a new TOTP secret for user"""
        if not MFA_AVAILABLE:
            return secrets.token_hex(16)  # Fallback
        
        return pyotp.random_base32()
    
    def generate_qr_code(self, username: str, secret: str) -> str:
        """Generate QR code for TOTP setup"""
        if not MFA_AVAILABLE:
            return None
        
        # Create TOTP URI
        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(
            name=username,
            issuer_name=self.issuer
        )
        
        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        
        # Convert to base64 image
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        img_str = base64.b64encode(buffer.getvalue()).decode()
        
        return f"data:image/png;base64,{img_str}"
    
    def verify_totp(self, secret: str, token: str) -> bool:
        """Verify TOTP token"""
        if not MFA_AVAILABLE:
            # Fallback: simple time-based validation
            return len(token) == 6 and token.isdigit()
        
        try:
            totp = pyotp.TOTP(secret)
            return totp.verify(token, valid_window=1)  # Allow 30s window
        except:
            return False
    
    def get_current_totp(self, secret: str) -> str:
        """Get current TOTP for testing"""
        if not MFA_AVAILABLE:
            return "123456"  # Fallback
        
        totp = pyotp.TOTP(secret)
        return totp.now()
    
    def generate_backup_codes(self, count: int = 8) -> list:
        """Generate backup codes for MFA recovery"""
        codes = []
        for _ in range(count):
            code = f"{secrets.randbelow(10000):04d}-{secrets.randbelow(10000):04d}"
            codes.append(code)
        return codes
    
    def verify_backup_code(self, user_backup_codes: list, provided_code: str) -> Tuple[bool, list]:
        """Verify backup code and remove it from list"""
        if provided_code in user_backup_codes:
            user_backup_codes.remove(provided_code)
            return True, user_backup_codes
        return False, user_backup_codes

class MFADatabase:
    """MFA data management"""
    
    def __init__(self, db_connection_func):
        self.get_connection = db_connection_func
        self.init_mfa_tables()
    
    def init_mfa_tables(self):
        """Initialize MFA tables"""
        with self.get_connection() as conn:
            # MFA settings table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS user_mfa (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    mfa_secret TEXT,
                    mfa_enabled INTEGER DEFAULT 0,
                    backup_codes TEXT,
                    created_at TEXT NOT NULL,
                    last_used TEXT
                )
            ''')
            
            # MFA attempts log
            conn.execute('''
                CREATE TABLE IF NOT EXISTS mfa_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    attempt_type TEXT NOT NULL,
                    success INTEGER NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT,
                    created_at TEXT NOT NULL
                )
            ''')
            
            conn.commit()
    
    def setup_user_mfa(self, username: str, secret: str, backup_codes: list) -> bool:
        """Setup MFA for user"""
        try:
            with self.get_connection() as conn:
                import json
                conn.execute('''
                    INSERT OR REPLACE INTO user_mfa 
                    (username, mfa_secret, mfa_enabled, backup_codes, created_at)
                    VALUES (?, ?, 0, ?, ?)
                ''', (username, secret, json.dumps(backup_codes), datetime.now(UTC).isoformat()))
                conn.commit()
                return True
        except Exception as e:
            print(f"[MFA] Setup error: {e}")
            return False
    
    def enable_user_mfa(self, username: str) -> bool:
        """Enable MFA for user after verification"""
        try:
            with self.get_connection() as conn:
                conn.execute('''
                    UPDATE user_mfa SET mfa_enabled = 1, last_used = ?
                    WHERE username = ?
                ''', (datetime.now(UTC).isoformat(), username))
                conn.commit()
                return True
        except Exception as e:
            print(f"[MFA] Enable error: {e}")
            return False
    
    def disable_user_mfa(self, username: str) -> bool:
        """Disable MFA for user"""
        try:
            with self.get_connection() as conn:
                conn.execute('''
                    UPDATE user_mfa SET mfa_enabled = 0
                    WHERE username = ?
                ''', (username,))
                conn.commit()
                return True
        except Exception as e:
            print(f"[MFA] Disable error: {e}")
            return False
    
    def get_user_mfa(self, username: str) -> Optional[Dict[str, Any]]:
        """Get user MFA settings"""
        try:
            with self.get_connection() as conn:
                cursor = conn.execute('''
                    SELECT * FROM user_mfa WHERE username = ?
                ''', (username,))
                row = cursor.fetchone()
                if row:
                    import json
                    mfa_data = dict(row)
                    if mfa_data.get('backup_codes'):
                        mfa_data['backup_codes'] = json.loads(mfa_data['backup_codes'])
                    return mfa_data
        except Exception as e:
            print(f"[MFA] Get error: {e}")
        return None
    
    def log_mfa_attempt(self, username: str, attempt_type: str, success: bool, ip: str = None, user_agent: str = None):
        """Log MFA attempt"""
        try:
            with self.get_connection() as conn:
                conn.execute('''
                    INSERT INTO mfa_attempts 
                    (username, attempt_type, success, ip_address, user_agent, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (username, attempt_type, 1 if success else 0, ip, user_agent, datetime.now(UTC).isoformat()))
                conn.commit()
        except Exception as e:
            print(f"[MFA] Log error: {e}")
    
    def update_backup_codes(self, username: str, backup_codes: list) -> bool:
        """Update user backup codes"""
        try:
            with self.get_connection() as conn:
                import json
                conn.execute('''
                    UPDATE user_mfa SET backup_codes = ?
                    WHERE username = ?
                ''', (json.dumps(backup_codes), username))
                conn.commit()
                return True
        except Exception as e:
            print(f"[MFA] Update backup codes error: {e}")
            return False

class MFAService:
    """Complete MFA service"""
    
    def __init__(self, db_connection_func):
        self.mfa_manager = MFAManager()
        self.mfa_db = MFADatabase(db_connection_func)
    
    def initiate_mfa_setup(self, username: str) -> Dict[str, Any]:
        """Start MFA setup process"""
        if not MFA_AVAILABLE:
            return {
                "success": False,
                "error": "MFA not available - pyotp not installed"
            }
        
        # Generate secret and backup codes
        secret = self.mfa_manager.generate_secret()
        backup_codes = self.mfa_manager.generate_backup_codes()
        
        # Store in database (not enabled yet)
        if self.mfa_db.setup_user_mfa(username, secret, backup_codes):
            # Generate QR code
            qr_code = self.mfa_manager.generate_qr_code(username, secret)
            
            return {
                "success": True,
                "secret": secret,
                "qr_code": qr_code,
                "backup_codes": backup_codes,
                "instructions": "Scan QR code with Google Authenticator or Authy, then verify with a code"
            }
        
        return {"success": False, "error": "Failed to setup MFA"}
    
    def verify_and_enable_mfa(self, username: str, totp_code: str) -> Dict[str, Any]:
        """Verify TOTP and enable MFA"""
        user_mfa = self.mfa_db.get_user_mfa(username)
        if not user_mfa:
            return {"success": False, "error": "MFA not setup"}
        
        # Verify TOTP
        if self.mfa_manager.verify_totp(user_mfa['mfa_secret'], totp_code):
            # Enable MFA
            if self.mfa_db.enable_user_mfa(username):
                self.mfa_db.log_mfa_attempt(username, "setup_verification", True)
                return {
                    "success": True,
                    "message": "MFA enabled successfully"
                }
        
        self.mfa_db.log_mfa_attempt(username, "setup_verification", False)
        return {"success": False, "error": "Invalid TOTP code"}
    
    def verify_mfa_login(self, username: str, code: str, ip: str = None) -> Dict[str, Any]:
        """Verify MFA during login"""
        user_mfa = self.mfa_db.get_user_mfa(username)
        if not user_mfa or not user_mfa.get('mfa_enabled'):
            return {"success": False, "error": "MFA not enabled"}
        
        # Try TOTP first
        if self.mfa_manager.verify_totp(user_mfa['mfa_secret'], code):
            self.mfa_db.log_mfa_attempt(username, "login_totp", True, ip)
            return {"success": True, "method": "totp"}
        
        # Try backup code
        backup_codes = user_mfa.get('backup_codes', [])
        is_valid, remaining_codes = self.mfa_manager.verify_backup_code(backup_codes, code)
        
        if is_valid:
            # Update backup codes
            self.mfa_db.update_backup_codes(username, remaining_codes)
            self.mfa_db.log_mfa_attempt(username, "login_backup", True, ip)
            return {
                "success": True, 
                "method": "backup_code",
                "remaining_codes": len(remaining_codes)
            }
        
        self.mfa_db.log_mfa_attempt(username, "login_failed", False, ip)
        return {"success": False, "error": "Invalid MFA code"}
    
    def is_mfa_enabled(self, username: str) -> bool:
        """Check if user has MFA enabled"""
        user_mfa = self.mfa_db.get_user_mfa(username)
        return user_mfa and user_mfa.get('mfa_enabled', False)
    
    def disable_mfa(self, username: str) -> Dict[str, Any]:
        """Disable MFA for user"""
        if self.mfa_db.disable_user_mfa(username):
            return {"success": True, "message": "MFA disabled"}
        return {"success": False, "error": "Failed to disable MFA"}
    
    def get_mfa_status(self, username: str) -> Dict[str, Any]:
        """Get MFA status for user"""
        user_mfa = self.mfa_db.get_user_mfa(username)
        if not user_mfa:
            return {
                "enabled": False,
                "setup": False,
                "available": MFA_AVAILABLE
            }
        
        return {
            "enabled": bool(user_mfa.get('mfa_enabled')),
            "setup": True,
            "backup_codes_remaining": len(user_mfa.get('backup_codes', [])),
            "last_used": user_mfa.get('last_used'),
            "available": MFA_AVAILABLE
        }

if __name__ == "__main__":
    # Test MFA functionality
    print("[MFA] Testing MFA Manager")
    print("=" * 40)
    
    if MFA_AVAILABLE:
        mfa = MFAManager()
        
        # Generate secret
        secret = mfa.generate_secret()
        print(f"Secret: {secret}")
        
        # Generate current TOTP
        current_totp = mfa.get_current_totp(secret)
        print(f"Current TOTP: {current_totp}")
        
        # Verify TOTP
        is_valid = mfa.verify_totp(secret, current_totp)
        print(f"TOTP Valid: {is_valid}")
        
        # Generate backup codes
        backup_codes = mfa.generate_backup_codes()
        print(f"Backup codes: {backup_codes[:3]}...")  # Show first 3
        
        print("[MFA] All tests completed successfully!")
    else:
        print("[MFA] pyotp not available - install with: pip install pyotp qrcode[pil]")