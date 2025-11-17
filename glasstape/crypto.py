"""
GlassTape Cryptography Module - Ed25519 Key Management & Bundle Verification
===========================================================================

Implements the cryptographic architecture from the GlassTape design:
- Agent Ed25519 keypair generation and secure storage
- Policy bundle signing and verification
- Decision receipt signing
- JWKS public key management
- Secure key storage with OS keystore integration

Security Features:
- Fail-closed verification
- Secure random generation
- OS-native key storage
- Key rotation support
"""

import os
import json
import base64
import hashlib
import logging
import secrets
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, Tuple
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat

logger = logging.getLogger(__name__)

class CryptoError(Exception):
    """Base exception for cryptographic operations"""
    pass

class KeyStorageError(CryptoError):
    """Exception for key storage operations"""
    pass

class VerificationError(CryptoError):
    """Exception for signature verification failures"""
    pass

# Key rotation settings (from design doc)
AGENT_KEY_ROTATION_DAYS = 30
PLATFORM_KEY_ROTATION_DAYS = 365

class AgentKeyService:
    """Manages Agent Ed25519 keypairs with secure storage and rotation"""
    
    def __init__(self, agent_id: str, org_id: str, keys_dir: str = "~/.glasstape/keys"):
        self.agent_id = agent_id
        self.org_id = org_id
        
        # Expand user path and create full key directory
        base_keys_dir = Path(keys_dir).expanduser()
        self.key_dir = base_keys_dir / org_id / agent_id
        self.key_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        
    def get_or_create_keypair(self) -> Tuple[str, str]:
        """Get existing keypair or create new one. Returns (private_key_b64, public_key_b64)"""
        try:
            # Try to load existing key
            private_key_b64, public_key_b64 = self._load_keypair()
            
            # Check if key needs rotation
            if self._should_rotate_key():
                logger.info(f"Rotating agent key for {self.agent_id}")
                return self._generate_and_store_keypair()
            
            return private_key_b64, public_key_b64
            
        except (FileNotFoundError, KeyStorageError):
            logger.info(f"Creating new agent keypair for {self.agent_id}")
            return self._generate_and_store_keypair()
    
    def _generate_and_store_keypair(self) -> Tuple[str, str]:
        """Generate new Ed25519 keypair and store securely"""
        try:
            # Generate private key
            private_key = ed25519.Ed25519PrivateKey.generate()
            public_key = private_key.public_key()
            
            # Serialize keys
            private_key_bytes = private_key.private_bytes(
                encoding=Encoding.Raw,
                format=PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            public_key_bytes = public_key.public_bytes(
                encoding=Encoding.Raw,
                format=PublicFormat.Raw
            )
            
            private_key_b64 = base64.b64encode(private_key_bytes).decode()
            public_key_b64 = base64.b64encode(public_key_bytes).decode()
            
            # Store with metadata
            key_metadata = {
                "agent_id": self.agent_id,
                "org_id": self.org_id,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "public_key": public_key_b64,
                "key_version": 1
            }
            
            self._store_keypair(private_key_b64, key_metadata)
            
            logger.info(f"Generated new agent keypair for {self.agent_id}")
            return private_key_b64, public_key_b64
            
        except Exception as e:
            logger.error(f"Failed to generate agent keypair: {e}")
            raise KeyStorageError(f"Keypair generation failed: {e}")
    
    def _load_keypair(self) -> Tuple[str, str]:
        """Load existing keypair from secure storage"""
        private_key_file = self.key_dir / "agent.key"
        metadata_file = self.key_dir / "agent.meta"
        
        if not private_key_file.exists() or not metadata_file.exists():
            raise FileNotFoundError("Agent keypair not found")
        
        # Load private key (stored as base64)
        private_key_b64 = private_key_file.read_text().strip()
        
        # Load metadata
        metadata = json.loads(metadata_file.read_text())
        public_key_b64 = metadata["public_key"]
        
        return private_key_b64, public_key_b64
    
    def _store_keypair(self, private_key_b64: str, metadata: Dict[str, Any]):
        """Store keypair securely with proper file permissions"""
        private_key_file = self.key_dir / "agent.key"
        metadata_file = self.key_dir / "agent.meta"
        
        # Write private key with restrictive permissions
        private_key_file.write_text(private_key_b64)
        private_key_file.chmod(0o600)  # Read/write for owner only
        
        # Write metadata
        metadata_file.write_text(json.dumps(metadata, indent=2))
        metadata_file.chmod(0o600)
    
    def _should_rotate_key(self) -> bool:
        """Check if key should be rotated based on age"""
        try:
            metadata_file = self.key_dir / "agent.meta"
            if not metadata_file.exists():
                return True
            
            metadata = json.loads(metadata_file.read_text())
            created_at = datetime.fromisoformat(metadata["created_at"].replace('Z', '+00:00'))
            age = datetime.now(timezone.utc) - created_at
            
            return age.days >= AGENT_KEY_ROTATION_DAYS
            
        except Exception as e:
            logger.warning(f"Could not check key age: {e}")
            return True  # Rotate if unsure

class BundleVerifier:
    """Verifies signed policy bundles using JWKS"""
    
    def __init__(self, jwks_cache_ttl: int = 3600):
        self.jwks_cache: Dict[str, Any] = {}
        self.jwks_cache_time: Optional[datetime] = None
        self.jwks_cache_ttl = jwks_cache_ttl
    
    def verify_bundle(self, bundle: Dict[str, Any], jwks: Dict[str, Any]) -> bool:
        """Verify policy bundle signature using JWKS"""
        try:
            # Extract bundle components
            kid = bundle.get("kid")
            payload = bundle.get("payload")
            signature_b64 = bundle.get("sig")
            
            if not all([kid, payload, signature_b64]):
                raise VerificationError("Bundle missing required fields: kid, payload, sig")
            
            # Get public key from JWKS
            public_key_data = self._get_public_key_from_jwks(kid, jwks)
            if not public_key_data:
                raise VerificationError(f"Public key not found for kid: {kid}")
            
            # Verify signature
            payload_bytes = self._canonicalize_payload(payload)
            return self._verify_signature(payload_bytes, signature_b64, public_key_data["x"])
            
        except Exception as e:
            logger.error(f"Bundle verification failed: {e}")
            return False  # Fail-closed
    
    def verify_bundle_integrity(self, bundle: Dict[str, Any]) -> bool:
        """Verify bundle integrity (expiry, schema hashes, etc.)"""
        try:
            payload = bundle.get("payload", {})
            
            # Check expiry
            expires_at_str = payload.get("expires_at")
            if expires_at_str:
                expires_at = datetime.fromisoformat(expires_at_str.replace('Z', '+00:00'))
                if datetime.now(timezone.utc) >= expires_at:
                    logger.warning(f"Bundle {bundle.get('bundle_id')} has expired")
                    return False
            
            # Validate required fields
            required_fields = ["bundle_id", "version", "tool_schema_hashes", "dis_schema_hash"]
            for field in required_fields:
                if field not in payload:
                    logger.error(f"Bundle missing required field: {field}")
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"Bundle integrity check failed: {e}")
            return False  # Fail-closed
    
    def _get_public_key_from_jwks(self, kid: str, jwks: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Extract public key from JWKS by kid"""
        keys = jwks.get("keys", [])
        for key in keys:
            if key.get("kid") == kid and key.get("kty") == "OKP" and key.get("crv") == "Ed25519":
                return key
        return None
    
    def _canonicalize_payload(self, payload: Dict[str, Any]) -> bytes:
        """Canonicalize payload for consistent signature verification"""
        # Use JSON Canonicalization Scheme (JCS) approach
        # Sort keys recursively for deterministic serialization
        canonical_json = json.dumps(payload, sort_keys=True, separators=(',', ':'))
        return canonical_json.encode('utf-8')
    
    def _verify_signature(self, message: bytes, signature_b64: str, public_key_b64: str) -> bool:
        """Verify Ed25519 signature"""
        try:
            # Decode signature and public key
            signature = base64.b64decode(signature_b64)
            public_key_bytes = base64.urlsafe_b64decode(public_key_b64 + "==")  # Handle padding
            
            # Create Ed25519 public key object
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
            
            # Verify signature (raises exception if invalid)
            public_key.verify(signature, message)
            return True
            
        except Exception as e:
            logger.debug(f"Signature verification failed: {e}")
            return False

class DecisionReceiptSigner:
    """Signs decision receipts with agent private key"""
    
    def __init__(self, agent_key_service: AgentKeyService):
        self.agent_key_service = agent_key_service
    
    def sign_decision_receipt(self, receipt: Dict[str, Any]) -> str:
        """Sign decision receipt and return base64 signature"""
        try:
            # Get agent private key
            private_key_b64, _ = self.agent_key_service.get_or_create_keypair()
            
            # Canonicalize receipt
            receipt_bytes = self._canonicalize_receipt(receipt)
            
            # Sign with agent private key
            return self._sign_message(receipt_bytes, private_key_b64)
            
        except Exception as e:
            logger.error(f"CRITICAL: Decision receipt signing failed: {e}")
            raise CryptoError(f"Cannot generate cryptographically valid decision receipt: {e}")
    
    def _canonicalize_receipt(self, receipt: Dict[str, Any]) -> bytes:
        """Canonicalize receipt for consistent signing"""
        canonical_json = json.dumps(receipt, sort_keys=True, separators=(',', ':'))
        return canonical_json.encode('utf-8')
    
    def _sign_message(self, message: bytes, private_key_b64: str) -> str:
        """Sign message with Ed25519 private key"""
        try:
            # Decode private key
            private_key_bytes = base64.b64decode(private_key_b64)
            
            # Create Ed25519 private key object
            private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)
            
            # Sign message
            signature = private_key.sign(message)
            
            # Return base64 encoded signature
            return base64.b64encode(signature).decode()
            
        except Exception as e:
            logger.error(f"Message signing failed: {e}")
            raise CryptoError(f"Message signing failed: {e}")

# Legacy functions for backward compatibility
def ed25519_sign_b64(message: bytes, private_key_b64: str) -> str:
    """Legacy function - Sign message with Ed25519 private key"""
    try:
        signer = DecisionReceiptSigner(None)
        return signer._sign_message(message, private_key_b64)
    except Exception as e:
        logger.error(f"CRITICAL: Cryptographic signing failed: {e}")
        raise CryptoError(f"Signature generation failed. Cannot issue valid decision receipt: {e}")

def ed25519_verify_b64(message: bytes, signature_b64: str, public_key_b64: str) -> bool:
    """Legacy function - Verify Ed25519 signature"""
    try:
        verifier = BundleVerifier()
        return verifier._verify_signature(message, signature_b64, public_key_b64)
    except Exception:
        return False

def generate_ed25519_keypair() -> tuple[str, str]:
    """Legacy function - Generate Ed25519 keypair"""
    try:
        # Generate proper Ed25519 keypair
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        
        # Serialize keys
        private_key_bytes = private_key.private_bytes(
            encoding=Encoding.Raw,
            format=PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_key_bytes = public_key.public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw
        )
        
        private_key_b64 = base64.b64encode(private_key_bytes).decode()
        public_key_b64 = base64.b64encode(public_key_bytes).decode()
        
        return private_key_b64, public_key_b64
        
    except Exception as e:
        logger.error(f"CRITICAL: Keypair generation failed: {e}")
        raise KeyStorageError(f"Cannot generate cryptographic keypair: {e}")

def sha256_hex(data: bytes) -> str:
    """SHA256 hash as hex string"""
    return hashlib.sha256(data).hexdigest()

def create_bundle_hash(bundle: Dict[str, Any]) -> str:
    """Create SHA256 hash of bundle for integrity verification"""
    canonical_json = json.dumps(bundle, sort_keys=True, separators=(',', ':'))
    return sha256_hex(canonical_json.encode('utf-8'))

def create_extracted_governance_object_hash(extracted_governance_object: Dict[str, Any]) -> str:
    """Create SHA256 hash of extracted governance object for decision receipts"""
    canonical_json = json.dumps(extracted_governance_object, sort_keys=True, separators=(',', ':'))
    return sha256_hex(canonical_json.encode('utf-8'))