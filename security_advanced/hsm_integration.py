"""
Hardware Security Module (HSM) Integration
Provides hardware-backed cryptographic operations and key management
"""
import os
import json
import hashlib
import hmac
from typing import Dict, Any, Optional, Tuple
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import boto3
import logging

logger = logging.getLogger(__name__)

class HSMInterface:
    """Abstract HSM interface for different HSM providers"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.initialized = False
    
    async def initialize(self) -> bool:
        """Initialize HSM connection"""
        raise NotImplementedError
    
    async def generate_key(self, key_id: str, key_type: str = "AES256") -> bool:
        """Generate new cryptographic key"""
        raise NotImplementedError
    
    async def encrypt(self, key_id: str, plaintext: bytes) -> bytes:
        """Encrypt data using HSM key"""
        raise NotImplementedError
    
    async def decrypt(self, key_id: str, ciphertext: bytes) -> bytes:
        """Decrypt data using HSM key"""
        raise NotImplementedError
    
    async def sign(self, key_id: str, data: bytes) -> bytes:
        """Create digital signature"""
        raise NotImplementedError
    
    async def verify(self, key_id: str, data: bytes, signature: bytes) -> bool:
        """Verify digital signature"""
        raise NotImplementedError

class AWSCloudHSM(HSMInterface):
    """AWS CloudHSM implementation"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.kms_client = None
        self.cluster_id = config.get("cluster_id")
        self.region = config.get("region", "us-east-1")
    
    async def initialize(self) -> bool:
        """Initialize AWS CloudHSM connection"""
        try:
            self.kms_client = boto3.client('kms', region_name=self.region)
            
            # Test connection
            response = self.kms_client.list_keys(Limit=1)
            self.initialized = True
            logger.info("AWS CloudHSM initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize AWS CloudHSM: {e}")
            return False
    
    async def generate_key(self, key_id: str, key_type: str = "AES256") -> bool:
        """Generate new key in AWS KMS"""
        try:
            if not self.initialized:
                await self.initialize()
            
            key_spec = "SYMMETRIC_DEFAULT" if key_type == "AES256" else "RSA_2048"
            key_usage = "ENCRYPT_DECRYPT" if key_type == "AES256" else "SIGN_VERIFY"
            
            response = self.kms_client.create_key(
                Description=f"Infinite Security Key: {key_id}",
                KeyUsage=key_usage,
                KeySpec=key_spec,
                Origin='HSM' if self.cluster_id else 'AWS_KMS'
            )
            
            # Create alias
            self.kms_client.create_alias(
                AliasName=f"alias/infinite-security-{key_id}",
                TargetKeyId=response['KeyMetadata']['KeyId']
            )
            
            logger.info(f"Generated key {key_id} in AWS KMS")
            return True
            
        except Exception as e:
            logger.error(f"Failed to generate key {key_id}: {e}")
            return False
    
    async def encrypt(self, key_id: str, plaintext: bytes) -> bytes:
        """Encrypt using AWS KMS"""
        try:
            response = self.kms_client.encrypt(
                KeyId=f"alias/infinite-security-{key_id}",
                Plaintext=plaintext
            )
            return response['CiphertextBlob']
            
        except Exception as e:
            logger.error(f"Encryption failed for key {key_id}: {e}")
            raise
    
    async def decrypt(self, key_id: str, ciphertext: bytes) -> bytes:
        """Decrypt using AWS KMS"""
        try:
            response = self.kms_client.decrypt(
                CiphertextBlob=ciphertext
            )
            return response['Plaintext']
            
        except Exception as e:
            logger.error(f"Decryption failed for key {key_id}: {e}")
            raise
    
    async def sign(self, key_id: str, data: bytes) -> bytes:
        """Create digital signature using AWS KMS"""
        try:
            # Hash the data first
            digest = hashlib.sha256(data).digest()
            
            response = self.kms_client.sign(
                KeyId=f"alias/infinite-security-{key_id}",
                Message=digest,
                MessageType='DIGEST',
                SigningAlgorithm='RSASSA_PSS_SHA_256'
            )
            
            return response['Signature']
            
        except Exception as e:
            logger.error(f"Signing failed for key {key_id}: {e}")
            raise
    
    async def verify(self, key_id: str, data: bytes, signature: bytes) -> bool:
        """Verify digital signature using AWS KMS"""
        try:
            digest = hashlib.sha256(data).digest()
            
            response = self.kms_client.verify(
                KeyId=f"alias/infinite-security-{key_id}",
                Message=digest,
                MessageType='DIGEST',
                Signature=signature,
                SigningAlgorithm='RSASSA_PSS_SHA_256'
            )
            
            return response['SignatureValid']
            
        except Exception as e:
            logger.error(f"Signature verification failed for key {key_id}: {e}")
            return False

class SoftwareHSM(HSMInterface):
    """Software-based HSM simulation for development/testing"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.keys = {}
        self.key_store_path = config.get("key_store_path", "/tmp/hsm_keys")
        os.makedirs(self.key_store_path, exist_ok=True)
    
    async def initialize(self) -> bool:
        """Initialize software HSM"""
        try:
            # Load existing keys
            await self._load_keys()
            self.initialized = True
            logger.info("Software HSM initialized")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize Software HSM: {e}")
            return False
    
    async def _load_keys(self):
        """Load keys from disk"""
        key_file = os.path.join(self.key_store_path, "keys.json")
        if os.path.exists(key_file):
            with open(key_file, 'r') as f:
                stored_keys = json.load(f)
                for key_id, key_data in stored_keys.items():
                    if key_data['type'] == 'AES256':
                        self.keys[key_id] = {
                            'type': 'AES256',
                            'key': bytes.fromhex(key_data['key'])
                        }
                    elif key_data['type'] == 'RSA':
                        private_key = serialization.load_pem_private_key(
                            key_data['private_key'].encode(),
                            password=None,
                            backend=default_backend()
                        )
                        public_key = serialization.load_pem_public_key(
                            key_data['public_key'].encode(),
                            backend=default_backend()
                        )
                        self.keys[key_id] = {
                            'type': 'RSA',
                            'private_key': private_key,
                            'public_key': public_key
                        }
    
    async def _save_keys(self):
        """Save keys to disk"""
        stored_keys = {}
        for key_id, key_data in self.keys.items():
            if key_data['type'] == 'AES256':
                stored_keys[key_id] = {
                    'type': 'AES256',
                    'key': key_data['key'].hex()
                }
            elif key_data['type'] == 'RSA':
                private_pem = key_data['private_key'].private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                public_pem = key_data['public_key'].public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                stored_keys[key_id] = {
                    'type': 'RSA',
                    'private_key': private_pem.decode(),
                    'public_key': public_pem.decode()
                }
        
        key_file = os.path.join(self.key_store_path, "keys.json")
        with open(key_file, 'w') as f:
            json.dump(stored_keys, f, indent=2)
    
    async def generate_key(self, key_id: str, key_type: str = "AES256") -> bool:
        """Generate new cryptographic key"""
        try:
            if key_type == "AES256":
                key = os.urandom(32)  # 256-bit key
                self.keys[key_id] = {
                    'type': 'AES256',
                    'key': key
                }
            elif key_type == "RSA":
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048,
                    backend=default_backend()
                )
                public_key = private_key.public_key()
                self.keys[key_id] = {
                    'type': 'RSA',
                    'private_key': private_key,
                    'public_key': public_key
                }
            
            await self._save_keys()
            logger.info(f"Generated {key_type} key: {key_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to generate key {key_id}: {e}")
            return False
    
    async def encrypt(self, key_id: str, plaintext: bytes) -> bytes:
        """Encrypt data using stored key"""
        if key_id not in self.keys:
            raise ValueError(f"Key {key_id} not found")
        
        key_data = self.keys[key_id]
        
        if key_data['type'] == 'AES256':
            # AES-GCM encryption
            iv = os.urandom(12)  # 96-bit IV for GCM
            cipher = Cipher(
                algorithms.AES(key_data['key']),
                modes.GCM(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()
            
            # Return IV + tag + ciphertext
            return iv + encryptor.tag + ciphertext
        
        elif key_data['type'] == 'RSA':
            # RSA-OAEP encryption
            ciphertext = key_data['public_key'].encrypt(
                plaintext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return ciphertext
        
        raise ValueError(f"Unsupported key type: {key_data['type']}")
    
    async def decrypt(self, key_id: str, ciphertext: bytes) -> bytes:
        """Decrypt data using stored key"""
        if key_id not in self.keys:
            raise ValueError(f"Key {key_id} not found")
        
        key_data = self.keys[key_id]
        
        if key_data['type'] == 'AES256':
            # Extract IV, tag, and ciphertext
            iv = ciphertext[:12]
            tag = ciphertext[12:28]
            encrypted_data = ciphertext[28:]
            
            cipher = Cipher(
                algorithms.AES(key_data['key']),
                modes.GCM(iv, tag),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(encrypted_data) + decryptor.finalize()
            return plaintext
        
        elif key_data['type'] == 'RSA':
            plaintext = key_data['private_key'].decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return plaintext
        
        raise ValueError(f"Unsupported key type: {key_data['type']}")
    
    async def sign(self, key_id: str, data: bytes) -> bytes:
        """Create digital signature"""
        if key_id not in self.keys:
            raise ValueError(f"Key {key_id} not found")
        
        key_data = self.keys[key_id]
        
        if key_data['type'] == 'RSA':
            signature = key_data['private_key'].sign(
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return signature
        
        raise ValueError(f"Signing not supported for key type: {key_data['type']}")
    
    async def verify(self, key_id: str, data: bytes, signature: bytes) -> bool:
        """Verify digital signature"""
        if key_id not in self.keys:
            raise ValueError(f"Key {key_id} not found")
        
        key_data = self.keys[key_id]
        
        if key_data['type'] == 'RSA':
            try:
                key_data['public_key'].verify(
                    signature,
                    data,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                return True
            except Exception:
                return False
        
        raise ValueError(f"Verification not supported for key type: {key_data['type']}")

class HSMManager:
    """HSM management and operations"""
    
    def __init__(self, hsm_type: str = "software", config: Dict[str, Any] = None):
        self.config = config or {}
        
        if hsm_type == "aws":
            self.hsm = AWSCloudHSM(self.config)
        elif hsm_type == "software":
            self.hsm = SoftwareHSM(self.config)
        else:
            raise ValueError(f"Unsupported HSM type: {hsm_type}")
    
    async def initialize(self) -> bool:
        """Initialize HSM"""
        return await self.hsm.initialize()
    
    async def setup_audit_signing_key(self) -> bool:
        """Setup key for audit log signing"""
        return await self.hsm.generate_key("audit_signing", "RSA")
    
    async def setup_data_encryption_key(self) -> bool:
        """Setup key for data encryption"""
        return await self.hsm.generate_key("data_encryption", "AES256")
    
    async def sign_audit_entry(self, audit_data: Dict[str, Any]) -> str:
        """Sign audit log entry"""
        try:
            # Serialize audit data
            audit_json = json.dumps(audit_data, sort_keys=True)
            audit_bytes = audit_json.encode('utf-8')
            
            # Create signature
            signature = await self.hsm.sign("audit_signing", audit_bytes)
            
            # Return base64 encoded signature
            import base64
            return base64.b64encode(signature).decode('utf-8')
            
        except Exception as e:
            logger.error(f"Failed to sign audit entry: {e}")
            raise
    
    async def verify_audit_entry(self, audit_data: Dict[str, Any], signature: str) -> bool:
        """Verify audit log entry signature"""
        try:
            # Serialize audit data
            audit_json = json.dumps(audit_data, sort_keys=True)
            audit_bytes = audit_json.encode('utf-8')
            
            # Decode signature
            import base64
            signature_bytes = base64.b64decode(signature.encode('utf-8'))
            
            # Verify signature
            return await self.hsm.verify("audit_signing", audit_bytes, signature_bytes)
            
        except Exception as e:
            logger.error(f"Failed to verify audit entry: {e}")
            return False
    
    async def encrypt_sensitive_data(self, data: bytes) -> bytes:
        """Encrypt sensitive data"""
        return await self.hsm.encrypt("data_encryption", data)
    
    async def decrypt_sensitive_data(self, encrypted_data: bytes) -> bytes:
        """Decrypt sensitive data"""
        return await self.hsm.decrypt("data_encryption", encrypted_data)

# Usage example
async def setup_hsm():
    """Setup HSM for Infinite Security"""
    
    # Initialize HSM (use software HSM for development)
    hsm_manager = HSMManager("software", {
        "key_store_path": "/opt/infinite_security/hsm_keys"
    })
    
    if not await hsm_manager.initialize():
        raise Exception("Failed to initialize HSM")
    
    # Setup required keys
    await hsm_manager.setup_audit_signing_key()
    await hsm_manager.setup_data_encryption_key()
    
    logger.info("HSM setup completed successfully")
    return hsm_manager

if __name__ == "__main__":
    import asyncio
    asyncio.run(setup_hsm())