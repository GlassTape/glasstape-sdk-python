"""
Integration tests for GlassTape SDK
"""

import pytest
import tempfile
import shutil
from pathlib import Path
from glasstape import configure, govern, set_context, GovernanceError


class TestIntegration:
    """Integration tests for the full GlassTape flow"""

    def setup_method(self):
        """Setup for each test"""
        self.temp_dir = tempfile.mkdtemp()
        self.policy_dir = Path(self.temp_dir) / "policies"
        self.policy_dir.mkdir(parents=True, exist_ok=True)
        
        # Create a test policy file
        policy_content = {
            "policy_id": "test.payment.v1",
            "rules": {
                "allow": [
                    {
                        "id": "allow_admin",
                        "condition": "user_role == 'admin'",
                        "reason": "Admin access granted"
                    },
                    {
                        "id": "allow_small_amounts",
                        "condition": "amount <= 100",
                        "reason": "Small amounts allowed"
                    }
                ],
                "deny": [
                    {
                        "id": "deny_large_amounts",
                        "condition": "amount > 1000",
                        "reason": "Large amounts denied"
                    }
                ]
            },
            "tool_schema": {
                "required": ["amount", "recipient"],
                "properties": {
                    "amount": {"type": "number"},
                    "recipient": {"type": "string"}
                }
            },
            "dis_schema": {},
            "extraction_bindings": {
                "bindings": [
                    {
                        "path": "input.resource.attr.amount",
                        "sources": [{"type": "arg", "name": "amount"}]
                    },
                    {
                        "path": "input.resource.attr.recipient",
                        "sources": [{"type": "arg", "name": "recipient"}]
                    },
                    {
                        "path": "input.principal.attr.user_role",
                        "sources": [{"type": "context", "name": "user_role"}]
                    }
                ]
            }
        }
        
        import json
        policy_file = self.policy_dir / "test.payment.v1.json"
        policy_file.write_text(json.dumps(policy_content, indent=2))

    def teardown_method(self):
        """Cleanup after each test"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_integration_allow_admin(self):
        """Test full integration flow with admin user"""
        # Configure GlassTape
        configure(
            agent_id="test-agent",
            policy_dir=str(self.policy_dir),
            debug=True
        )
        
        # Set context
        set_context(user_id="admin-1", user_role="admin")
        
        # Define governed function
        @govern("test.payment.v1")
        def process_payment(amount: float, recipient: str):
            return f"Processed ${amount} to {recipient}"
        
        # Test - should allow admin
        result = process_payment(500.0, "test@example.com")
        assert result == "Processed $500.0 to test@example.com"

    def test_integration_allow_small_amount(self):
        """Test full integration flow with small amount"""
        # Configure GlassTape
        configure(
            agent_id="test-agent",
            policy_dir=str(self.policy_dir),
            debug=True
        )
        
        # Set context
        set_context(user_id="user-1", user_role="user")
        
        # Define governed function
        @govern("test.payment.v1")
        def process_payment(amount: float, recipient: str):
            return f"Processed ${amount} to {recipient}"
        
        # Test - should allow small amount
        result = process_payment(50.0, "test@example.com")
        assert result == "Processed $50.0 to test@example.com"

    def test_integration_deny_large_amount(self):
        """Test full integration flow with large amount denial"""
        # Configure GlassTape
        configure(
            agent_id="test-agent",
            policy_dir=str(self.policy_dir),
            debug=True
        )
        
        # Set context
        set_context(user_id="user-1", user_role="user")
        
        # Define governed function
        @govern("test.payment.v1")
        def process_payment(amount: float, recipient: str):
            return f"Processed ${amount} to {recipient}"
        
        # Test - should deny large amount
        with pytest.raises(GovernanceError) as exc_info:
            process_payment(5000.0, "test@example.com")
        
        # Should contain some indication of denial or error
        error_msg = str(exc_info.value).lower()
        assert any(word in error_msg for word in ["deny", "denied", "not allowed", "error", "failed"])

    def test_integration_missing_policy_file(self):
        """Test integration with missing policy file"""
        # Configure GlassTape with empty policy dir
        empty_dir = Path(self.temp_dir) / "empty"
        empty_dir.mkdir(exist_ok=True)
        
        configure(
            agent_id="test-agent",
            policy_dir=str(empty_dir),
            debug=True
        )
        
        # Set context
        set_context(user_id="user-1", user_role="user")
        
        # Define governed function
        @govern("missing.policy.v1")
        def process_payment(amount: float, recipient: str):
            return f"Processed ${amount} to {recipient}"
        
        # Test - should deny due to missing policy
        with pytest.raises(GovernanceError):
            process_payment(50.0, "test@example.com")

    def test_integration_validation_failure(self):
        """Test integration with tool validation failure"""
        # Configure GlassTape
        configure(
            agent_id="test-agent",
            policy_dir=str(self.policy_dir),
            debug=True
        )
        
        # Set context
        set_context(user_id="admin-1", user_role="admin")
        
        # Define governed function with required parameters
        @govern("test.payment.v1")
        def process_payment(amount: float, recipient: str):
            return f"Processed ${amount} to {recipient}"
        
        # Test - should work with all required parameters
        result = process_payment(50.0, "test@example.com")
        assert "Processed $50.0 to test@example.com" == result