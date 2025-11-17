"""
Tests for GlassTape decorators
"""

import pytest
import asyncio
from unittest.mock import patch, MagicMock
from glasstape import govern, monitor, configure, set_context, GovernanceError


class TestGovernDecorator:
    """Test the @govern decorator"""

    def setup_method(self):
        """Setup for each test"""
        configure(agent_id="test-agent", policy_dir="./test_policies")

    def test_govern_sync_function(self):
        """Test @govern with synchronous function"""
        @govern("test.policy.v1")
        def test_function(amount: float):
            return f"Processed ${amount}"

        # Mock the policy enforcement to allow
        with patch('glasstape.router.ModeRouter') as mock_router:
            mock_instance = MagicMock()
            mock_router.return_value = mock_instance
            
            # Create a mock decision that allows the action
            mock_decision = MagicMock()
            mock_decision.decision = "allow"
            mock_decision.reason = "Policy allows"
            
            # Make the enforce_policy method return the allow decision
            async def mock_enforce(*args, **kwargs):
                return mock_decision
            
            mock_instance.enforce_policy = mock_enforce
            
            result = test_function(50.0)
            assert result == "Processed $50.0"

    @pytest.mark.asyncio
    async def test_govern_async_function(self):
        """Test @govern with asynchronous function"""
        @govern("test.policy.v1")
        async def test_async_function(amount: float):
            return f"Async processed ${amount}"

        with patch('glasstape.router.ModeRouter') as mock_router:
            mock_instance = MagicMock()
            mock_router.return_value = mock_instance
            
            mock_decision = MagicMock()
            mock_decision.decision = "allow"
            mock_decision.reason = "Policy allows"
            
            async def mock_enforce(*args, **kwargs):
                return mock_decision
            
            mock_instance.enforce_policy = mock_enforce
            
            result = await test_async_function(75.0)
            assert result == "Async processed $75.0"

    def test_govern_blocks_denied_request(self):
        """Test that @govern blocks requests denied by policy"""
        @govern("test.policy.v1")
        def test_function(amount: float):
            return f"Processed ${amount}"

        with patch('glasstape.router.ModeRouter') as mock_router:
            mock_instance = MagicMock()
            mock_router.return_value = mock_instance
            
            mock_decision = MagicMock()
            mock_decision.decision = "deny"
            mock_decision.reason = "Amount exceeds limit"
            
            async def mock_enforce(*args, **kwargs):
                return mock_decision
            
            mock_instance.enforce_policy = mock_enforce
            
            with pytest.raises(GovernanceError) as exc_info:
                test_function(1000.0)
            
            assert "Amount exceeds limit" in str(exc_info.value)

    def test_govern_with_context(self):
        """Test @govern with request context"""
        set_context(user_id="test-user", user_role="admin")
        
        @govern("test.policy.v1")
        def test_function(amount: float):
            return f"Processed ${amount}"

        with patch('glasstape.router.ModeRouter') as mock_router:
            mock_instance = MagicMock()
            mock_router.return_value = mock_instance
            
            mock_decision = MagicMock()
            mock_decision.decision = "allow"
            mock_decision.reason = "Admin access granted"
            
            async def mock_enforce(*args, **kwargs):
                # Verify context is passed
                context = kwargs.get('context', {})
                assert context.get('user_id') == 'test-user'
                assert context.get('user_role') == 'admin'
                return mock_decision
            
            mock_instance.enforce_policy = mock_enforce
            
            result = test_function(100.0)
            assert result == "Processed $100.0"


class TestMonitorDecorator:
    """Test the @monitor decorator"""

    def setup_method(self):
        """Setup for each test"""
        configure(agent_id="test-agent", policy_dir="./test_policies")

    def test_monitor_sync_function(self):
        """Test @monitor with synchronous function"""
        @monitor("test.monitoring.v1")
        def test_function(data: str):
            return f"Monitored: {data}"

        # Monitor should not block execution
        result = test_function("test data")
        assert result == "Monitored: test data"

    @pytest.mark.asyncio
    async def test_monitor_async_function(self):
        """Test @monitor with asynchronous function"""
        @monitor("test.monitoring.v1")
        async def test_async_function(data: str):
            return f"Async monitored: {data}"

        result = await test_async_function("async data")
        assert result == "Async monitored: async data"

    def test_monitor_does_not_block_on_policy_failure(self):
        """Test that @monitor doesn't block execution even if policy evaluation fails"""
        @monitor("test.monitoring.v1")
        def test_function(data: str):
            return f"Monitored: {data}"

        with patch('glasstape.router.ModeRouter') as mock_router:
            # Make the router raise an exception
            mock_router.side_effect = Exception("Policy evaluation failed")
            
            # Function should still execute successfully
            result = test_function("test data")
            assert result == "Monitored: test data"


class TestDecoratorIntegration:
    """Test decorator integration scenarios"""

    def test_multiple_decorators_on_same_function(self):
        """Test multiple GlassTape decorators on the same function"""
        @monitor("test.monitoring.v1")
        @govern("test.policy.v1")
        def test_function(amount: float):
            return f"Processed ${amount}"

        with patch('glasstape.router.ModeRouter') as mock_router:
            mock_instance = MagicMock()
            mock_router.return_value = mock_instance
            
            mock_decision = MagicMock()
            mock_decision.decision = "allow"
            mock_decision.reason = "Policy allows"
            
            async def mock_enforce(*args, **kwargs):
                return mock_decision
            
            mock_instance.enforce_policy = mock_enforce
            
            result = test_function(50.0)
            assert result == "Processed $50.0"

    def test_decorator_with_framework_decorator(self):
        """Test GlassTape decorator with framework decorators (e.g., LangChain @tool)"""
        # Simulate LangChain @tool decorator
        def tool(func):
            func._is_tool = True
            return func

        @tool
        @govern("test.policy.v1")
        def test_tool(query: str):
            return f"Tool result: {query}"

        with patch('glasstape.router.ModeRouter') as mock_router:
            mock_instance = MagicMock()
            mock_router.return_value = mock_instance
            
            mock_decision = MagicMock()
            mock_decision.decision = "allow"
            mock_decision.reason = "Policy allows"
            
            async def mock_enforce(*args, **kwargs):
                return mock_decision
            
            mock_instance.enforce_policy = mock_enforce
            
            result = test_tool("test query")
            assert result == "Tool result: test query"
            assert hasattr(test_tool, '_is_tool')
            assert test_tool._is_tool is True