"""
GlassTape Mode Router
=====================

Elegant routing that makes adding new modes trivial.

Philosophy:
    - Abstract the interface (PolicyEngine protocol)
    - Concrete implementations per mode (Local, Platform, Web3)
    - Factory pattern for clean instantiation
"""

from typing import Dict, Any, Protocol
from .config import GlassTapeConfig
from .modes.local import LocalEngine
from .policy_engine import PolicyDecision

class PolicyEngine(Protocol):
    """
    Protocol defining what every policy engine must implement.
    
    This is the contract that makes multi-mode support elegant.
    Local, Platform, and Web3 engines all implement this interface.
    """
    
    async def enforce_policy(
        self,
        policy_id: str,
        tool_name: str,
        tool_args: Dict[str, Any],
        context: Dict[str, Any]
    ) -> PolicyDecision:
        """Enforce a policy and return the decision"""
        ...

class ModeRouter:
    """
    Routes governance requests to the appropriate mode engine.
    
    Design:
        - Factory pattern for engine creation
        - Single responsibility: routing to the right engine
        - Extensible: adding a new mode is just a new case
    """
    
    def __init__(self, config: GlassTapeConfig):
        self.config = config
        self.engine = self._create_engine()
    
    def _create_engine(self) -> PolicyEngine:
        """
        Factory method: create the right engine for the configured mode.
        
        Local: Ready now (file-based policies)
        Platform: Coming in v2.0 (API-based policies)
        Web3: Coming in v2.0 (blockchain policies)
        """
        if self.config.mode == "local":
            return LocalEngine(self.config)
        
        elif self.config.mode == "platform":
            # Future: from .modes.platform import PlatformEngine
            # return PlatformEngine(self.config)
            raise NotImplementedError(
                "Platform mode coming in v2.0! "
                "Star us on GitHub to follow progress."
            )
        
        elif self.config.mode == "web3":
            # Future: from .modes.web3 import Web3Engine
            # return Web3Engine(self.config)
            raise NotImplementedError(
                "Web3 mode coming in v2.0! "
                "Star us on GitHub to follow progress."
            )
        
        else:
            raise ValueError(f"Unknown mode: {self.config.mode}")
    
    async def enforce_policy(
        self,
        policy_id: str,
        tool_name: str,
        tool_args: Dict[str, Any],
        context: Dict[str, Any]
    ) -> PolicyDecision:
        """
        Enforce a policy using the configured engine.
        
        This is the single entry point that works across all modes.
        The beauty: your code never changes, regardless of mode.
        """
        return await self.engine.enforce_policy(
            policy_id, tool_name, tool_args, context
        )