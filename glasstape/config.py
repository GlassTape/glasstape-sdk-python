"""
GlassTape Configuration
=======================

Elegant configuration that starts simple and scales to enterprise.

Philosophy:
    - Local by default (zero dependencies, works offline)
    - Extensible by design (platform and web3 ready)
    - Sensible defaults (just works out of the box)
"""

import os
from dataclasses import dataclass
from typing import Optional, Literal
from pathlib import Path

# Type-safe mode definitions
Mode = Literal["local", "platform", "web3"]

@dataclass
class GlassTapeConfig:
    """
    Configuration for GlassTape SDK.
    
    Starts simple with local mode, scales to platform and web3.
    Every field has a sensible default for local development.
    """
    
    # === Core Identity ===
    agent_id: str = "default-agent"
    org_id: str = "default-org"
    
    # === Mode Selection ===
    mode: Mode = "local"
    
    # === Local Mode Configuration ===
    policy_dir: str = "./policies"
    log_file: str = "./glasstape.log"
    
    # === Platform Mode Configuration (future) ===
    platform_url: Optional[str] = None
    api_key: Optional[str] = None
    
    # === Web3 Mode Configuration (future) ===
    web3_network: Optional[str] = None
    web3_contract: Optional[str] = None
    
    # === LLM Integration (optional) ===
    llm_provider: Optional[str] = None  # "openai" | "anthropic"
    llm_api_key: Optional[str] = None
    llm_model: Optional[str] = None
    
    # === Cryptography ===
    ed25519_private_key: Optional[str] = None
    keys_dir: str = "~/.glasstape/keys"
    
    # === Performance ===
    cache_ttl: int = 300  # 5 minutes
    timeout_seconds: int = 10
    cerbos_cel_enabled: bool = True  # Built-in CEL evaluation (Cerbos-compatible)
    
    # === Developer Experience ===
    debug: bool = False
    
    @property
    def use_llm_extraction(self) -> bool:
        """Smart extraction: use LLM if configured, otherwise rules-based"""
        return bool(self.llm_api_key and self.llm_provider)
    
    def __post_init__(self):
        """Validate and setup configuration"""
        self._validate_mode()
        self._setup_directories()
    
    def _validate_mode(self):
        """Validate mode and required fields"""
        if self.mode not in ("local", "platform", "web3"):
            raise ValueError(
                f"Invalid mode: {self.mode}. "
                f"Must be 'local', 'platform', or 'web3'"
            )
        
        # Future: Add platform/web3 validation when implemented
        if self.mode == "platform":
            if not self.platform_url or not self.api_key:
                raise ValueError(
                    "Platform mode requires platform_url and api_key. "
                    "Coming soon in v2.0!"
                )
        
        if self.mode == "web3":
            if not self.web3_network or not self.web3_contract:
                raise ValueError(
                    "Web3 mode requires web3_network and web3_contract. "
                    "Coming soon in v2.0!"
                )
    
    def _setup_directories(self):
        """Setup required directories for local mode"""
        if self.mode == "local":
            Path(self.policy_dir).mkdir(parents=True, exist_ok=True)
            Path(self.keys_dir).expanduser().mkdir(parents=True, exist_ok=True)
    
    @classmethod
    def from_env(cls) -> 'GlassTapeConfig':
        """
        Create configuration from environment variables.
        
        Follows the principle of sensible defaults:
        - Everything optional except what's truly required
        - Local mode by default
        - Smart LLM detection from common env vars
        """
        return cls(
            # Identity
            agent_id=os.getenv("GT_AGENT_ID", "default-agent"),
            org_id=os.getenv("GT_ORG_ID", "default-org"),
            
            # Mode
            mode=os.getenv("GT_MODE", "local"),  # type: ignore
            
            # Local mode
            policy_dir=os.getenv("GT_POLICY_DIR", "./policies"),
            log_file=os.getenv("GT_LOG_FILE", "./glasstape.log"),
            
            # Platform mode (future)
            platform_url=os.getenv("GT_PLATFORM_URL"),
            api_key=os.getenv("GT_API_KEY"),
            
            # Web3 mode (future)
            web3_network=os.getenv("GT_WEB3_NETWORK"),
            web3_contract=os.getenv("GT_WEB3_CONTRACT"),
            
            # LLM integration
            llm_provider=os.getenv("GT_LLM_PROVIDER"),
            llm_api_key=(
                os.getenv("GT_LLM_API_KEY") or
                os.getenv("ANTHROPIC_API_KEY") or
                os.getenv("OPENAI_API_KEY")
            ),
            llm_model=os.getenv("GT_LLM_MODEL"),
            
            # Cryptography
            ed25519_private_key=os.getenv("GT_ED25519_PRIVATE_KEY"),
            keys_dir=os.getenv("GT_KEYS_DIR", "~/.glasstape/keys"),
            
            # Performance
            cache_ttl=int(os.getenv("GT_CACHE_TTL", "300")),
            timeout_seconds=int(os.getenv("GT_TIMEOUT", "10")),
            cerbos_cel_enabled=os.getenv("GT_CERBOS_CEL_ENABLED", "true").lower() == "true",
            
            # Developer experience
            debug=os.getenv("GT_DEBUG", "false").lower() == "true"
        )

# Global configuration instance
_global_config: Optional[GlassTapeConfig] = None

def configure(**kwargs) -> GlassTapeConfig:
    """Configure GlassTape SDK with elegant defaults"""
    global _global_config
    
    # Merge environment variables with explicit arguments
    env_config = GlassTapeConfig.from_env()
    
    # Override with explicit arguments
    config_dict = env_config.__dict__.copy()
    config_dict.update(kwargs)
    
    _global_config = GlassTapeConfig(**config_dict)
    return _global_config

def get_config() -> GlassTapeConfig:
    """Get current configuration, creating default if needed"""
    global _global_config
    
    if _global_config is None:
        _global_config = configure()
    
    return _global_config