"""
Local Mode Engine - File-based Policies and Logging
===================================================

Self-contained local mode that requires no external dependencies.
Perfect for development, testing, and air-gapped deployments.
"""

import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional

from ..cerbos_evaluator import CerbosEvaluator
from ..policy_engine import ICPExtractor, PolicyDecision
from ..config import GlassTapeConfig

logger = logging.getLogger(__name__)

class LocalEngine:
    """Local mode engine for file-based governance"""
    
    def __init__(self, config: GlassTapeConfig):
        self.config = config
        self.evaluator = CerbosEvaluator()
        self.extractor = ICPExtractor(config)
        self.policy_cache = {}
        
        # LLM extractor will be initialized by ICPExtractor if needed
        
        # Ensure directories exist
        Path(config.policy_dir).mkdir(parents=True, exist_ok=True)
        Path(config.log_file).parent.mkdir(parents=True, exist_ok=True)
    

    
    async def enforce_policy(
        self,
        policy_id: str,
        tool_name: str,
        tool_args: Dict[str, Any],
        context: Dict[str, Any]
    ) -> PolicyDecision:
        """Enforce policy using local files"""
        
        start_time = time.time()
        
        try:
            # Load policy from local file
            policy_bundle = self._load_policy(policy_id)
            
            # Extract to ICP format
            extraction_bindings = policy_bundle.get("extraction_bindings", {"bindings": []})
            icp_schema = policy_bundle.get("icp_schema", {})
            
            icp = await self.extractor.extract_to_icp(
                tool_args, context, extraction_bindings, icp_schema
            )
            
            # Debug: Show ICP generation
            if self.config.debug:
                amount = icp.get("input", {}).get("resource", {}).get("attr", {}).get("amount", 0)
                user_role = icp.get("input", {}).get("principal", {}).get("attr", {}).get("user_role", "unknown")
                logger.debug(f"ICP Generated: amount=${amount}, user_role={user_role}")
                logger.debug(f"Evaluating policy: amount > $50? role check?")
            
            # Evaluate policy
            decision = self._evaluate_policy(policy_bundle, icp)
            decision.evaluation_time_ms = (time.time() - start_time) * 1000
            
            # Debug: Show policy decision
            if self.config.debug:
                logger.debug(f"Policy Decision: {decision.decision.upper()}")
                logger.debug(f"Reason: {decision.reason}")
            
            # Log decision
            await self._log_decision(policy_id, tool_name, tool_args, decision, context)
            
            return decision
            
        except Exception as e:
            # Fail-closed: deny on any error
            decision = PolicyDecision(
                decision="deny",
                reason=f"Local enforcement error: {e}",
                evaluation_time_ms=(time.time() - start_time) * 1000
            )
            
            await self._log_decision(policy_id, tool_name, tool_args, decision, context)
            return decision
    
    def _load_policy(self, policy_id: str) -> Dict[str, Any]:
        """Load policy from local file with caching"""
        
        # Check cache first
        if policy_id in self.policy_cache:
            return self.policy_cache[policy_id]
        
        # Try different file extensions
        policy_file = None
        for ext in [".json", ".yaml", ".yml"]:
            candidate = Path(self.config.policy_dir) / f"{policy_id}{ext}"
            if candidate.exists():
                policy_file = candidate
                break
        
        if not policy_file:
            raise FileNotFoundError(f"Policy file not found: {policy_id}")
        
        # Load and cache policy
        if policy_file.suffix == ".json":
            with open(policy_file, 'r') as f:
                policy_bundle = json.load(f)
        else:
            # YAML support
            import yaml
            with open(policy_file, 'r') as f:
                policy_bundle = yaml.safe_load(f)
        
        self.policy_cache[policy_id] = policy_bundle
        return policy_bundle
    
    def _evaluate_policy(self, policy_bundle: Dict[str, Any], icp: Dict[str, Any]) -> PolicyDecision:
        """Evaluate policy using local engine"""
        
        # Convert ICP to request format for evaluation
        request = {
            "resource": icp.get("input", {}).get("resource", {}),
            "actions": icp.get("input", {}).get("actions", ["execute"]),
            "principal": icp.get("input", {}).get("principal", {}),
            "environment": icp.get("input", {}).get("environment", {})
        }
        
        # Try CEL evaluation first (Cerbos-compatible)
        cerbos_yaml = policy_bundle.get("cerbos_policy_yaml")
        if cerbos_yaml and self.evaluator.is_available():
            try:
                cerbos_decision = self.evaluator.evaluate(cerbos_yaml, icp)
                return PolicyDecision(
                    decision="allow" if cerbos_decision.decision == "EFFECT_ALLOW" else "deny",
                    reason=cerbos_decision.reason,
                    evaluation_time_ms=cerbos_decision.evaluation_time_ms
                )
            except Exception:
                pass  # Fall back to legacy rules
        
        # Fallback to legacy rules evaluation
        rules = policy_bundle.get("rules", {})
        
        # Check deny rules first (fail-closed)
        for rule in rules.get("deny", []):
            if self._evaluate_rule_condition(rule.get("condition", ""), request):
                return PolicyDecision(
                    decision="deny",
                    reason=rule.get("reason", "Policy violation"),
                    rule_id=rule.get("id")
                )
        
        # Check allow rules
        for rule in rules.get("allow", []):
            condition = rule.get("condition", "")
            if not condition or self._evaluate_rule_condition(condition, request):
                return PolicyDecision(
                    decision="allow",
                    reason=rule.get("reason", "Policy allows"),
                    rule_id=rule.get("id")
                )
        
        # Default deny
        return PolicyDecision(
            decision="deny",
            reason="No matching allow rules found"
        )
    
    def _evaluate_rule_condition(self, condition: str, request: Dict[str, Any]) -> bool:
        """Evaluate rule condition using Cerbos evaluator for proper CEL support"""
        if not condition:
            return True
        
        # Use Cerbos evaluator for proper condition evaluation (handles AND, OR, user_role, etc.)
        try:
            return self.evaluator._evaluate_with_pattern_matching(condition, request)
        except Exception as e:
            if self.config.debug:
                logger.debug(f"Condition evaluation error: {e}")
            return False
    
    async def _log_decision(
        self,
        policy_id: str,
        tool_name: str,
        tool_args: Dict[str, Any],
        decision: PolicyDecision,
        context: Dict[str, Any]
    ):
        """Log decision to local file"""
        
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            "agent_id": context.get("agent_id", self.config.agent_id),
            "org_id": context.get("org_id", self.config.org_id),
            "policy_id": policy_id,
            "tool_name": tool_name,
            "tool_args": tool_args,
            "decision": decision.decision,
            "reason": decision.reason,
            "rule_id": decision.rule_id,
            "evaluation_time_ms": decision.evaluation_time_ms,
            "mode": "local"
        }
        
        # Append to log file
        try:
            with open(self.config.log_file, 'a') as f:
                f.write(json.dumps(log_entry) + "\n")
        except Exception as e:
            # Don't fail governance on logging errors
            logger.warning(f"Failed to write log entry: {e}")
    
    def clear_policy_cache(self):
        """Clear policy cache (useful for development)"""
        self.policy_cache.clear()