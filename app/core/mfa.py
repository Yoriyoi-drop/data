"""
Multi-Factor Authentication (MFA) Implementation
"""
import pyotp
import qrcode
from io import BytesIO
import base64
from typing import Optional
from app.core.config import settings

class MFAManager:
    """Multi-Factor Authentication Manager"""
    
    def __init__(self):
        self.issuer_name = settings.APP_NAME
    
    def generate_secret(self) -> str:
        """Generate new TOTP secret"""
        return pyotp.random_base32()
    
    def generate_qr_code(self, username: str, secret: str) -> str:
        """Generate QR code for TOTP setup"""
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=username,
            issuer_name=self.issuer_name
        )
        
        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        
        # Convert to base64 image
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = BytesIO()
        img.save(buffer, format="PNG")
        
        return base64.b64encode(buffer.getvalue()).decode()
    
    def verify_totp(self, secret: str, token: str, window: int = 1) -> bool:
        """Verify TOTP token"""
        totp = pyotp.TOTP(secret)
        return totp.verify(token, valid_window=window)
    
    def get_backup_codes(self, count: int = 10) -> list:
        """Generate backup codes"""
        import secrets
        return [secrets.token_hex(4).upper() for _ in range(count)]

# Global MFA manager
mfa_manager = MFAManager()