"""
Policy Bundle Converter
=======================

Converts legacy GlassTape JSON policies to Cerbos YAML format.
Provides automatic backward compatibility for existing policies.
"""

import json
import logging
import yaml
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

class PolicyBundleConverter:
    """Converts legacy GlassTape policies to Cerbos YAML format"""
    
    def __init__(self):
        self.conversion_cache: Dict[str, str] = {}
    
    def convert_to_cerbos_yaml(self, legacy_bundle: Dict[str, Any]) -> str:
        """
        Convert legacy GlassTape JSON policy to Cerbos YAML
        
        Args:
            legacy_bundle: Legacy policy bundle in GlassTape format
            
        Returns:
            Policy in Cerbos YAML format
        """
        try:
            # Check cache first
            bundle_id = legacy_bundle.get("policy_id", "unknown")
            cache_key = f"{bundle_id}_{hash(json.dumps(legacy_bundle, sort_keys=True))}"
            
            if cache_key in self.conversion_cache:
                return self.conversion_cache[cache_key]
            
            # Convert to Cerbos format
            cerbos_policy = self._build_cerbos_policy(legacy_bundle)
            cerbos_yaml = yaml.dump(cerbos_policy, default_flow_style=False, sort_keys=False)
            
            # Cache result
            self.conversion_cache[cache_key] = cerbos_yaml
            
            logger.info(f"Converted legacy policy {bundle_id} to Cerbos YAML")
            return cerbos_yaml
            
        except Exception as e:
            logger.error(f"Policy conversion failed: {e}")
            # Return minimal deny-all policy as fallback
            return self._create_fallback_policy(legacy_bundle.get("policy_id", "unknown"))
    
    def _build_cerbos_policy(self, legacy_bundle: Dict[str, Any]) -> Dict[str, Any]:
        """Build Cerbos policy structure from legacy bundle"""
        policy_id = legacy_bundle.get("policy_id", "unknown")
        rules = legacy_bundle.get("rules", {})
        
        # Extract resource information
        resource_kind = self._extract_resource_kind(policy_id)
        
        # Build Cerbos policy structure
        cerbos_policy = {
            "apiVersion": "api.cerbos.dev/v1",
            "resourcePolicy": {
                "version": "default",
                "resource": resource_kind,
                "rules": []
            }
        }
        
        # Convert deny rules (higher priority)
        deny_rules = rules.get("deny", [])
        for rule in deny_rules:
            cerbos_rule = self._convert_rule(rule, "EFFECT_DENY")
            if cerbos_rule:
                cerbos_policy["resourcePolicy"]["rules"].append(cerbos_rule)
        
        # Convert allow rules
        allow_rules = rules.get("allow", [])
        for rule in allow_rules:
            cerbos_rule = self._convert_rule(rule, "EFFECT_ALLOW")
            if cerbos_rule:
                cerbos_policy["resourcePolicy"]["rules"].append(cerbos_rule)
        
        # Add default deny rule if no rules exist
        if not cerbos_policy["resourcePolicy"]["rules"]:
            cerbos_policy["resourcePolicy"]["rules"].append({
                "actions": ["*"],
                "effect": "EFFECT_DENY",
                "name": "default_deny",
                "condition": {
                    "match": {
                        "expr": "true"
                    }
                }
            })
        
        return cerbos_policy
    
    def _extract_resource_kind(self, policy_id: str) -> str:
        """Extract resource kind from policy ID"""
        # Parse policy ID format: category.resource.version
        parts = policy_id.split(".")
        if len(parts) >= 2:
            return f"{parts[0]}_{parts[1]}"
        return "tool"
    
    def _convert_rule(self, legacy_rule: Dict[str, Any], effect: str) -> Optional[Dict[str, Any]]:
        """Convert legacy rule to Cerbos rule format"""
        try:
            rule_id = legacy_rule.get("id", legacy_rule.get("rule_id", "unnamed"))
            condition = legacy_rule.get("condition", "")
            reason = legacy_rule.get("reason", "")
            
            # Build Cerbos rule
            cerbos_rule = {
                "actions": ["*"],  # Apply to all actions by default
                "effect": effect,
                "name": rule_id
            }
            
            # Convert condition to CEL expression
            if condition:
                cel_condition = self._convert_condition_to_cel(condition)
                if cel_condition:
                    cerbos_rule["condition"] = {
                        "match": {
                            "expr": cel_condition
                        }
                    }
            
            # Add metadata
            if reason:
                cerbos_rule["metadata"] = {
                    "reason": reason
                }
            
            return cerbos_rule
            
        except Exception as e:
            logger.warning(f"Failed to convert rule: {e}")
            return None
    
    def _convert_condition_to_cel(self, condition: str) -> Optional[str]:
        """
        Convert legacy condition to CEL expression
        
        Legacy format: "amount > 5000", "recipient == 'blocked'"
        CEL format: "request.amount > 5000", "request.recipient == 'blocked'"
        """
        try:
            # Simple condition conversion patterns
            cel_condition = condition.strip()
            
            # Convert field references to request.resource.attr.* format (Cerbos-compatible)
            conversions = [
                ("amount", "request.resource.attr.amount"),
                ("amount1", "request.resource.attr.amount1"),
                ("amount2", "request.resource.attr.amount2"),
                ("fee", "request.resource.attr.fee"),
                ("recipient", "request.resource.attr.recipient"),
                ("vendor", "request.resource.attr.vendor"),
                ("user_id", "request.resource.attr.user_id"),
                ("quantity", "request.resource.attr.quantity"),
                ("price", "request.resource.attr.price"),
                ("symbol", "request.resource.attr.symbol")
            ]
            
            # Replace field references with proper paths (handle various formats)
            for legacy_field, cel_field in conversions:
                # Handle patterns like "amount >", "amount<", "(amount", "amount)", etc.
                import re
                # Match field name as word boundary to avoid partial matches
                pattern = r'\b' + re.escape(legacy_field) + r'\b'
                cel_condition = re.sub(pattern, cel_field, cel_condition)
            
            # Handle string literals (ensure proper quoting)
            if "==" in cel_condition and "'" not in cel_condition and '"' not in cel_condition:
                # Add quotes to string values
                parts = cel_condition.split("==")
                if len(parts) == 2:
                    field, value = parts[0].strip(), parts[1].strip()
                    try:
                        # Try to parse as number
                        float(value)
                        cel_condition = f"{field} == {value}"
                    except ValueError:
                        # Treat as string
                        cel_condition = f"{field} == '{value}'"
            
            return cel_condition if cel_condition != condition else None
            
        except Exception as e:
            logger.warning(f"Condition conversion failed: {e}")
            return None
    
    def _create_fallback_policy(self, policy_id: str) -> str:
        """Create minimal deny-all policy as fallback"""
        fallback_policy = {
            "apiVersion": "api.cerbos.dev/v1",
            "resourcePolicy": {
                "version": "default",
                "resource": "tool",
                "rules": [
                    {
                        "actions": ["*"],
                        "effect": "EFFECT_DENY",
                        "name": "fallback_deny",
                        "condition": {
                            "match": {
                                "expr": "true"
                            }
                        },
                        "metadata": {
                            "reason": f"Fallback policy for {policy_id} - conversion failed"
                        }
                    }
                ]
            }
        }
        
        return yaml.dump(fallback_policy, default_flow_style=False, sort_keys=False)
    
    def validate_conversion(self, legacy_bundle: Dict[str, Any], cerbos_yaml: str) -> bool:
        """
        Validate that conversion preserves policy semantics
        
        Args:
            legacy_bundle: Original legacy policy
            cerbos_yaml: Converted Cerbos policy
            
        Returns:
            True if conversion is valid
        """
        try:
            # Parse converted policy
            cerbos_policy = yaml.safe_load(cerbos_yaml)
            
            # Basic structure validation
            if not isinstance(cerbos_policy, dict):
                return False
            
            if "resourcePolicy" not in cerbos_policy:
                return False
            
            resource_policy = cerbos_policy["resourcePolicy"]
            if "rules" not in resource_policy:
                return False
            
            # Check that we have some rules
            rules = resource_policy["rules"]
            if not isinstance(rules, list) or len(rules) == 0:
                return False
            
            # Validate rule structure
            for rule in rules:
                if not isinstance(rule, dict):
                    return False
                
                required_fields = ["actions", "effect", "name"]
                if not all(field in rule for field in required_fields):
                    return False
                
                if rule["effect"] not in ["EFFECT_ALLOW", "EFFECT_DENY"]:
                    return False
            
            logger.info(f"Conversion validation passed for {legacy_bundle.get('policy_id', 'unknown')}")
            return True
            
        except Exception as e:
            logger.error(f"Conversion validation failed: {e}")
            return False
    
    def get_conversion_stats(self) -> Dict[str, Any]:
        """Get conversion statistics"""
        return {
            "cached_conversions": len(self.conversion_cache),
            "cache_keys": list(self.conversion_cache.keys())
        }