"""
Tests for GlassTape configuration
"""

import os
import pytest
from glasstape.config import GlassTapeConfig, configure, get_config


class TestGlassTapeConfig:
    """Test GlassTapeConfig class"""

    def test_default_config(self):
        """Test default configuration values"""
        config = GlassTapeConfig()
        
        assert config.agent_id == "default-agent"
        assert config.org_id == "default-org"
        assert config.mode == "local"
        assert config.policy_dir == "./policies"
        assert config.log_file == "./glasstape.log"
        assert config.debug is False

    def test_config_from_env(self):
        """Test configuration from environment variables"""
        env_vars = {
            "GT_AGENT_ID": "test-agent",
            "GT_ORG_ID": "test-org",
            "GT_MODE": "local",
            "GT_POLICY_DIR": "./test_policies",
            "GT_LOG_FILE": "./test.log",
            "GT_DEBUG": "true"
        }
        
        with patch_env(env_vars):
            config = GlassTapeConfig.from_env()
            
            assert config.agent_id == "test-agent"
            assert config.org_id == "test-org"
            assert config.mode == "local"
            assert config.policy_dir == "./test_policies"
            assert config.log_file == "./test.log"
            assert config.debug is True

    def test_llm_configuration(self):
        """Test LLM configuration detection"""
        # Test with OpenAI API key
        env_vars = {"OPENAI_API_KEY": "sk-test123", "GT_LLM_PROVIDER": "openai"}
        
        with patch_env(env_vars):
            config = GlassTapeConfig.from_env()
            assert config.llm_api_key == "sk-test123"
            assert config.llm_provider == "openai"
            assert config.use_llm_extraction is True

        # Test with Anthropic API key
        env_vars = {"ANTHROPIC_API_KEY": "ant-test123", "GT_LLM_PROVIDER": "anthropic"}
        
        with patch_env(env_vars):
            config = GlassTapeConfig.from_env()
            assert config.llm_api_key == "ant-test123"
            assert config.llm_provider == "anthropic"
            assert config.use_llm_extraction is True

    def test_invalid_mode_validation(self):
        """Test validation of invalid mode"""
        with pytest.raises(ValueError, match="Invalid mode"):
            GlassTapeConfig(mode="invalid")

    def test_platform_mode_validation(self):
        """Test platform mode validation (future feature)"""
        with pytest.raises(ValueError, match="Platform mode requires"):
            GlassTapeConfig(mode="platform")

    def test_web3_mode_validation(self):
        """Test web3 mode validation (future feature)"""
        with pytest.raises(ValueError, match="Web3 mode requires"):
            GlassTapeConfig(mode="web3")


class TestConfigureFunctions:
    """Test configuration functions"""

    def test_configure_function(self):
        """Test configure() function"""
        config = configure(
            agent_id="test-agent",
            policy_dir="./test_policies",
            debug=True
        )
        
        assert config.agent_id == "test-agent"
        assert config.policy_dir == "./test_policies"
        assert config.debug is True

    def test_get_config_creates_default(self):
        """Test get_config() creates default config if none exists"""
        # Clear any existing config
        import glasstape.config
        glasstape.config._global_config = None
        
        config = get_config()
        assert config.agent_id == "default-agent"
        assert config.mode == "local"

    def test_configure_overrides_env(self):
        """Test that explicit configure() arguments override environment"""
        env_vars = {"GT_AGENT_ID": "env-agent"}
        
        with patch_env(env_vars):
            config = configure(agent_id="explicit-agent")
            assert config.agent_id == "explicit-agent"  # Explicit wins

    def test_configure_merges_with_env(self):
        """Test that configure() merges with environment variables"""
        env_vars = {
            "GT_AGENT_ID": "env-agent",
            "GT_ORG_ID": "env-org"
        }
        
        with patch_env(env_vars):
            config = configure(agent_id="explicit-agent")
            assert config.agent_id == "explicit-agent"  # Explicit wins
            assert config.org_id == "env-org"  # Env value preserved


def patch_env(env_vars):
    """Context manager to patch environment variables"""
    import contextlib
    
    @contextlib.contextmanager
    def _patch():
        old_env = os.environ.copy()
        try:
            os.environ.update(env_vars)
            yield
        finally:
            os.environ.clear()
            os.environ.update(old_env)
    
    return _patch()