"""
Tests for GlassTape Cryptography Module
"""

import pytest
import json
import base64
import tempfile
import shutil
from pathlib import Path
from unittest.mock import patch, MagicMock
from glasstape.crypto import (
    AgentKeyService, BundleVerifier, DecisionReceiptSigner,
    CryptoError, KeyStorageError, VerificationError,
    ed25519_sign_b64, ed25519_verify_b64, generate_ed25519_keypair,
    sha256_hex, create_bundle_hash, create_extracted_governance_object_hash
)


class TestAgentKeyService:
    """Test AgentKeyService class"""

    def setup_method(self):
        """Setup for each test"""
        self.temp_dir = tempfile.mkdtemp()
        self.agent_id = "test-agent"
        self.org_id = "test-org"
        self.service = AgentKeyService(self.agent_id, self.org_id, self.temp_dir)

    def teardown_method(self):
        """Cleanup after each test"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_agent_key_service_initialization(self):
        """Test AgentKeyService initialization"""
        assert self.service.agent_id == "test-agent"
        assert self.service.org_id == "test-org"
        assert self.service.key_dir.exists()
        assert self.service.key_dir.name == "test-agent"

    def test_get_or_create_keypair_new(self):
        """Test get_or_create_keypair creates new keypair"""
        private_key_b64, public_key_b64 = self.service.get_or_create_keypair()
        
        assert isinstance(private_key_b64, str)
        assert isinstance(public_key_b64, str)
        assert len(base64.b64decode(private_key_b64)) == 32  # Ed25519 private key size
        assert len(base64.b64decode(public_key_b64)) == 32   # Ed25519 public key size

    def test_get_or_create_keypair_existing(self):
        """Test get_or_create_keypair loads existing keypair"""
        # Create initial keypair
        private_key_b64_1, public_key_b64_1 = self.service.get_or_create_keypair()
        
        # Get keypair again - should be the same
        private_key_b64_2, public_key_b64_2 = self.service.get_or_create_keypair()
        
        assert private_key_b64_1 == private_key_b64_2
        assert public_key_b64_1 == public_key_b64_2

    def test_generate_and_store_keypair(self):
        """Test _generate_and_store_keypair method"""
        private_key_b64, public_key_b64 = self.service._generate_and_store_keypair()
        
        # Check that files were created
        private_key_file = self.service.key_dir / "agent.key"
        metadata_file = self.service.key_dir / "agent.meta"
        
        assert private_key_file.exists()
        assert metadata_file.exists()
        
        # Check file permissions
        assert oct(private_key_file.stat().st_mode)[-3:] == "600"
        assert oct(metadata_file.stat().st_mode)[-3:] == "600"
        
        # Check file contents
        stored_private_key = private_key_file.read_text().strip()
        assert stored_private_key == private_key_b64
        
        metadata = json.loads(metadata_file.read_text())
        assert metadata["agent_id"] == "test-agent"
        assert metadata["org_id"] == "test-org"
        assert metadata["public_key"] == public_key_b64

    def test_load_keypair(self):
        """Test _load_keypair method"""
        # First create a keypair
        original_private, original_public = self.service._generate_and_store_keypair()
        
        # Then load it
        loaded_private, loaded_public = self.service._load_keypair()
        
        assert loaded_private == original_private
        assert loaded_public == original_public

    def test_load_keypair_not_found(self):
        """Test _load_keypair raises FileNotFoundError when files don't exist"""
        with pytest.raises(FileNotFoundError):
            self.service._load_keypair()

    def test_should_rotate_key_old(self):
        """Test _should_rotate_key returns True for old key"""
        from datetime import datetime, timezone, timedelta
        
        # Create a keypair first
        self.service._generate_and_store_keypair()
        
        # Manually modify the metadata file to have an old timestamp
        metadata_file = self.service.key_dir / "agent.meta"
        metadata = json.loads(metadata_file.read_text())
        old_time = datetime.now(timezone.utc) - timedelta(days=31)
        metadata["created_at"] = old_time.isoformat()
        metadata_file.write_text(json.dumps(metadata, indent=2))
        
        result = self.service._should_rotate_key()
        assert result is True

    def test_should_rotate_key_recent(self):
        """Test _should_rotate_key returns False for recent key"""
        from datetime import datetime, timezone, timedelta
        
        # Create a keypair first
        self.service._generate_and_store_keypair()
        
        # Manually modify the metadata file to have a recent timestamp
        metadata_file = self.service.key_dir / "agent.meta"
        metadata = json.loads(metadata_file.read_text())
        recent_time = datetime.now(timezone.utc) - timedelta(days=1)
        metadata["created_at"] = recent_time.isoformat()
        metadata_file.write_text(json.dumps(metadata, indent=2))
        
        result = self.service._should_rotate_key()
        assert result is False


class TestBundleVerifier:
    """Test BundleVerifier class"""

    def setup_method(self):
        """Setup for each test"""
        self.verifier = BundleVerifier()

    def test_bundle_verifier_initialization(self):
        """Test BundleVerifier initialization"""
        assert self.verifier.jwks_cache == {}
        assert self.verifier.jwks_cache_time is None
        assert self.verifier.jwks_cache_ttl == 3600

    def test_verify_bundle_missing_fields(self):
        """Test verify_bundle with missing required fields"""
        bundle = {"kid": "key1", "payload": {}}  # Missing sig
        jwks = {}
        
        result = self.verifier.verify_bundle(bundle, jwks)
        assert result is False

    def test_verify_bundle_key_not_found(self):
        """Test verify_bundle with key not found in JWKS"""
        bundle = {
            "kid": "missing-key",
            "payload": {"test": "data"},
            "sig": "signature"
        }
        jwks = {"keys": []}
        
        result = self.verifier.verify_bundle(bundle, jwks)
        assert result is False

    def test_get_public_key_from_jwks_found(self):
        """Test _get_public_key_from_jwks finds correct key"""
        jwks = {
            "keys": [
                {
                    "kid": "key1",
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": "test_key_data"
                },
                {
                    "kid": "key2",
                    "kty": "RSA"  # Different key type
                }
            ]
        }
        
        key = self.verifier._get_public_key_from_jwks("key1", jwks)
        assert key is not None
        assert key["kid"] == "key1"
        assert key["x"] == "test_key_data"

    def test_get_public_key_from_jwks_not_found(self):
        """Test _get_public_key_from_jwks returns None when key not found"""
        jwks = {"keys": []}
        
        key = self.verifier._get_public_key_from_jwks("missing-key", jwks)
        assert key is None

    def test_canonicalize_payload(self):
        """Test _canonicalize_payload method"""
        payload = {"b": 2, "a": 1, "c": {"z": 26, "y": 25}}
        
        canonical = self.verifier._canonicalize_payload(payload)
        expected = b'{"a":1,"b":2,"c":{"y":25,"z":26}}'
        
        assert canonical == expected

    def test_verify_bundle_integrity_success(self):
        """Test verify_bundle_integrity with valid bundle"""
        from datetime import datetime, timezone, timedelta
        
        future_time = datetime.now(timezone.utc) + timedelta(hours=1)
        bundle = {
            "payload": {
                "bundle_id": "test-bundle",
                "version": "1.0",
                "tool_schema_hashes": {"test": "hash"},
                "dis_schema_hash": "hash123",
                "expires_at": future_time.isoformat()
            }
        }
        
        result = self.verifier.verify_bundle_integrity(bundle)
        assert result is True

    def test_verify_bundle_integrity_expired(self):
        """Test verify_bundle_integrity with expired bundle"""
        from datetime import datetime, timezone, timedelta
        
        past_time = datetime.now(timezone.utc) - timedelta(hours=1)
        bundle = {
            "payload": {
                "bundle_id": "test-bundle",
                "version": "1.0",
                "tool_schema_hashes": {"test": "hash"},
                "dis_schema_hash": "hash123",
                "expires_at": past_time.isoformat()
            }
        }
        
        result = self.verifier.verify_bundle_integrity(bundle)
        assert result is False

    def test_verify_bundle_integrity_missing_fields(self):
        """Test verify_bundle_integrity with missing required fields"""
        bundle = {
            "payload": {
                "bundle_id": "test-bundle"
                # Missing other required fields
            }
        }
        
        result = self.verifier.verify_bundle_integrity(bundle)
        assert result is False


class TestDecisionReceiptSigner:
    """Test DecisionReceiptSigner class"""

    def setup_method(self):
        """Setup for each test"""
        self.temp_dir = tempfile.mkdtemp()
        self.agent_service = AgentKeyService("test-agent", "test-org", self.temp_dir)
        self.signer = DecisionReceiptSigner(self.agent_service)

    def teardown_method(self):
        """Cleanup after each test"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_decision_receipt_signer_initialization(self):
        """Test DecisionReceiptSigner initialization"""
        assert self.signer.agent_key_service == self.agent_service

    def test_sign_decision_receipt(self):
        """Test sign_decision_receipt method"""
        receipt = {
            "agent_id": "test-agent",
            "decision": "allow",
            "reason": "Test reason",
            "timestamp": "2023-01-01T00:00:00Z"
        }
        
        signature = self.signer.sign_decision_receipt(receipt)
        
        assert isinstance(signature, str)
        # Should be base64 encoded
        decoded = base64.b64decode(signature)
        assert len(decoded) == 64  # Ed25519 signature length

    def test_canonicalize_receipt(self):
        """Test _canonicalize_receipt method"""
        receipt = {"b": 2, "a": 1}
        
        canonical = self.signer._canonicalize_receipt(receipt)
        expected = b'{"a":1,"b":2}'
        
        assert canonical == expected

    def test_sign_message(self):
        """Test _sign_message method"""
        message = b"test message"
        private_key_b64, _ = self.agent_service.get_or_create_keypair()
        
        signature = self.signer._sign_message(message, private_key_b64)
        
        assert isinstance(signature, str)
        decoded = base64.b64decode(signature)
        assert len(decoded) == 64  # Ed25519 signature length


class TestLegacyFunctions:
    """Test legacy cryptographic functions"""

    def test_generate_ed25519_keypair(self):
        """Test generate_ed25519_keypair function"""
        private_key_b64, public_key_b64 = generate_ed25519_keypair()
        
        assert isinstance(private_key_b64, str)
        assert isinstance(public_key_b64, str)
        
        # Verify key lengths
        private_key_bytes = base64.b64decode(private_key_b64)
        public_key_bytes = base64.b64decode(public_key_b64)
        
        assert len(private_key_bytes) == 32
        assert len(public_key_bytes) == 32

    def test_ed25519_sign_b64(self):
        """Test ed25519_sign_b64 function"""
        message = b"test message"
        private_key_b64, _ = generate_ed25519_keypair()
        
        signature = ed25519_sign_b64(message, private_key_b64)
        
        assert isinstance(signature, str)
        decoded = base64.b64decode(signature)
        assert len(decoded) == 64

    def test_ed25519_verify_b64(self):
        """Test ed25519_verify_b64 function"""
        message = b"test message"
        private_key_b64, public_key_b64 = generate_ed25519_keypair()
        
        # Sign the message
        signature = ed25519_sign_b64(message, private_key_b64)
        
        # Verify the signature
        result = ed25519_verify_b64(message, signature, public_key_b64)
        assert result is True

    def test_ed25519_verify_b64_invalid(self):
        """Test ed25519_verify_b64 with invalid signature"""
        message = b"test message"
        _, public_key_b64 = generate_ed25519_keypair()
        invalid_signature = base64.b64encode(b"invalid" * 8).decode()  # 64 bytes of invalid data
        
        result = ed25519_verify_b64(message, invalid_signature, public_key_b64)
        assert result is False

    def test_sha256_hex(self):
        """Test sha256_hex function"""
        data = b"test data"
        hash_hex = sha256_hex(data)
        
        assert isinstance(hash_hex, str)
        assert len(hash_hex) == 64  # SHA256 hex length
        
        # Verify it's actually the correct hash
        import hashlib
        expected = hashlib.sha256(data).hexdigest()
        assert hash_hex == expected

    def test_create_bundle_hash(self):
        """Test create_bundle_hash function"""
        bundle = {"key": "value", "number": 123}
        hash_hex = create_bundle_hash(bundle)
        
        assert isinstance(hash_hex, str)
        assert len(hash_hex) == 64  # SHA256 hex length

    def test_create_extracted_governance_object_hash(self):
        """Test create_extracted_governance_object_hash function"""
        governance_object = {"policy": "test", "decision": "allow"}
        hash_hex = create_extracted_governance_object_hash(governance_object)
        
        assert isinstance(hash_hex, str)
        assert len(hash_hex) == 64  # SHA256 hex length


class TestCryptoErrors:
    """Test crypto error handling"""

    def test_crypto_error(self):
        """Test CryptoError exception"""
        with pytest.raises(CryptoError):
            raise CryptoError("Test crypto error")

    def test_key_storage_error(self):
        """Test KeyStorageError exception"""
        with pytest.raises(KeyStorageError):
            raise KeyStorageError("Test key storage error")

    def test_verification_error(self):
        """Test VerificationError exception"""
        with pytest.raises(VerificationError):
            raise VerificationError("Test verification error")

    def test_ed25519_sign_b64_failure(self):
        """Test ed25519_sign_b64 raises CryptoError on failure"""
        message = b"test message"
        invalid_private_key = "invalid_key"
        
        with pytest.raises(CryptoError):
            ed25519_sign_b64(message, invalid_private_key)

    def test_generate_ed25519_keypair_failure(self):
        """Test generate_ed25519_keypair raises KeyStorageError on failure"""
        with patch('glasstape.crypto.ed25519.Ed25519PrivateKey.generate') as mock_generate:
            mock_generate.side_effect = Exception("Crypto library error")
            
            with pytest.raises(KeyStorageError):
                generate_ed25519_keypair()


class TestIntegration:
    """Integration tests for crypto components"""

    def setup_method(self):
        """Setup for each test"""
        self.temp_dir = tempfile.mkdtemp()

    def teardown_method(self):
        """Cleanup after each test"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_full_signing_verification_flow(self):
        """Test complete signing and verification flow"""
        # Create agent key service
        agent_service = AgentKeyService("test-agent", "test-org", self.temp_dir)
        
        # Create signer
        signer = DecisionReceiptSigner(agent_service)
        
        # Create and sign a receipt
        receipt = {
            "agent_id": "test-agent",
            "decision": "allow",
            "reason": "Test decision",
            "timestamp": "2023-01-01T00:00:00Z"
        }
        
        signature = signer.sign_decision_receipt(receipt)
        
        # Verify we can decode the signature
        decoded_signature = base64.b64decode(signature)
        assert len(decoded_signature) == 64
        
        # Get the public key for verification
        _, public_key_b64 = agent_service.get_or_create_keypair()
        
        # Canonicalize the receipt for verification
        canonical_receipt = signer._canonicalize_receipt(receipt)
        
        # Verify the signature
        result = ed25519_verify_b64(canonical_receipt, signature, public_key_b64)
        assert result is True

    def test_key_rotation_flow(self):
        """Test key rotation functionality"""
        agent_service = AgentKeyService("test-agent", "test-org", self.temp_dir)
        
        # Get initial keypair
        private1, public1 = agent_service.get_or_create_keypair()
        
        # Force rotation by removing metadata file
        metadata_file = agent_service.key_dir / "agent.meta"
        metadata_file.unlink()
        
        # Get keypair again - should generate new one
        private2, public2 = agent_service.get_or_create_keypair()
        
        # Keys should be different
        assert private1 != private2
        assert public1 != public2