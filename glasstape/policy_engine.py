"""
GlassTape Policy Engine with Cerbos-Compatible CEL Evaluation
===================================================

Implements the policy engine design with:
- Policy bundle verification and caching
- ICP (Intermediate Canonical Policy) extraction and normalization
- Tool Schema vs ICP separation (execution truth vs governance truth)
- LLM-based parameter extraction for natural language inputs
- Built-in CEL policy evaluation (Cerbos-compatible) for high accuracy
- Automatic legacy policy conversion
- Decision receipt generation and signing
- Unified ICP format (consistent with sister project glasstape-policy-builder-mcp)

Key Benefits of ICP Consolidation:
- Single canonical format eliminates multiple intermediate states
- Cerbos-compatible structure enables direct mapping
- Consistent with sister project for unified architecture
- Simplified conversion pipeline (Tool Args → ICP → Cerbos)
"""

import asyncio
import hashlib
import json
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple, List
from dataclasses import dataclass

# Cerbos integration
from .cerbos_evaluator import CerbosEvaluator, CerbosDecision
from .policy_converter import PolicyBundleConverter

# Optional imports for LLM providers
try:
    import openai
except ImportError:
    openai = None

try:
    import anthropic
except ImportError:
    anthropic = None

logger = logging.getLogger(__name__)

# Constants
ALLOW = "allow"
DENY = "deny"
CONDITIONAL = "conditional"

@dataclass
class PolicyDecision:
    """Policy decision result with metadata"""
    decision: str  # "allow", "deny", "conditional"
    reason: str = ""
    conditions: List[str] = None
    evaluation_time_ms: float = 0.0
    rule_id: Optional[str] = None
    bundle_id: Optional[str] = None
    bundle_version: Optional[int] = None
    
    def __post_init__(self):
        if self.conditions is None:
            self.conditions = []

@dataclass
class DecisionReceipt:
    """Cryptographic decision receipt for audit trail (aligned with crypto design)"""
    agent_id: str
    bundle_id: str
    bundle_hash: str
    dis_hash: str
    decision: str
    reason: str
    ts: str  # timestamp in ISO format
    signature: Optional[str] = None

class PolicyBundle:
    """Policy bundle with JWS-style format, Ed25519 signature verification, and Cerbos integration"""
    
    def __init__(self, bundle_data: Dict[str, Any], jwks: Dict[str, Any] = None):
        # Support both JWS-style and legacy formats
        if "payload" in bundle_data and "kid" in bundle_data and "sig" in bundle_data:
            # JWS-style format from crypto design
            self.bundle_id = bundle_data.get("bundle_id")
            self.kid = bundle_data.get("kid")
            self.payload = bundle_data.get("payload", {})
            self.signature = bundle_data.get("sig")
            self.jwks = jwks or {}
        else:
            # Legacy format - wrap in JWS structure
            self.bundle_id = bundle_data.get("policy_id", "unknown")
            self.kid = "platform-key-default"
            self.payload = bundle_data
            self.signature = None
            self.jwks = jwks or {}
        
        self._verified = False
        self._expired = False
        
        # Cerbos integration components
        self.cerbos_evaluator = CerbosEvaluator()
        self.converter = PolicyBundleConverter()
        
    def verify(self) -> bool:
        """Verify bundle signature and integrity using Ed25519"""
        try:
            # Check if we have JWKS and signature to verify
            if self.signature and self.kid in self.jwks:
                return self._verify_ed25519_signature()
            
            # Fallback: basic validation for legacy bundles
            required_fields = ["rules", "tool_schema", "dis_schema"]
            if not all(field in self.payload for field in required_fields):
                return False
                
            # Check expiry
            expires_at = self.payload.get("expires_at")
            if expires_at:
                expiry_time = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
                if datetime.now(timezone.utc) > expiry_time:
                    self._expired = True
                    return False
            
            self._verified = True
            return True
            
        except Exception as e:
            logger.warning(f"Bundle verification failed: {e}")
            return False
    
    def _verify_ed25519_signature(self) -> bool:
        """Verify Ed25519 signature using JWKS"""
        try:
            import base64
            from cryptography.hazmat.primitives.asymmetric import ed25519
            from cryptography.hazmat.primitives import serialization
            
            # Get public key from JWKS
            jwk = self.jwks.get(self.kid)
            if not jwk:
                logger.warning(f"Key ID {self.kid} not found in JWKS")
                return False
            
            # Decode public key (assuming base64url encoding)
            public_key_bytes = base64.urlsafe_b64decode(jwk["x"] + "==")
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
            
            # Verify signature
            payload_json = json.dumps(self.payload, sort_keys=True).encode('utf-8')
            signature_bytes = base64.b64decode(self.signature)
            public_key.verify(signature_bytes, payload_json)
            
            # Check expiry
            expires_at = self.payload.get("expires_at")
            if expires_at:
                expiry_time = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
                if datetime.now(timezone.utc) > expiry_time:
                    self._expired = True
                    return False
            
            self._verified = True
            return True
            
        except Exception as e:
            logger.warning(f"Ed25519 signature verification failed: {e}")
            return False
    
    def is_expired(self) -> bool:
        """Check if bundle is expired"""
        return self._expired
    
    def evaluate(self, icp: Dict[str, Any]) -> PolicyDecision:
        """Evaluate policy using CEL expressions (Cerbos-compatible - simplified approach)
        
        Uses unified ICP format for direct mapping to Cerbos request structure.
        """
        if not self._verified:
            return PolicyDecision(DENY, "Bundle not verified")
            
        if self.is_expired():
            return PolicyDecision(DENY, "Bundle expired")
        
        start_time = time.time()
        
        # Simple check: Is Cerbos available?
        if not self.cerbos_evaluator.is_available():
            return self._emergency_legacy_fallback(icp, start_time)
        
        try:
            # Get or convert policy to Cerbos format
            cerbos_yaml = self.payload.get("cerbos_policy_yaml")
            if not cerbos_yaml:
                # Auto-convert legacy GlassTape JSON → Cerbos YAML
                cerbos_yaml = self.converter.convert_to_cerbos_yaml(self.payload)
                self.payload["_converted"] = cerbos_yaml  # Cache it
            
            # Always evaluate with Cerbos (ICP format simplifies conversion)
            cerbos_decision = self.cerbos_evaluator.evaluate(cerbos_yaml, icp)
            
            # Convert Cerbos decision to PolicyDecision
            return self._convert_cerbos_decision(cerbos_decision, start_time)
            
        except Exception as e:
            logger.error(f"Cerbos evaluation failed: {e}")
            return self._emergency_legacy_fallback(icp, start_time)
    
    def _convert_cerbos_decision(self, cerbos_decision: CerbosDecision, start_time: float) -> PolicyDecision:
        """Convert Cerbos decision to PolicyDecision format"""
        # Map Cerbos effects to GlassTape decisions
        if cerbos_decision.decision == "EFFECT_ALLOW":
            decision = ALLOW
        elif cerbos_decision.decision == "EFFECT_DENY":
            decision = DENY
        else:
            decision = DENY  # Default to deny for unknown effects
        
        return PolicyDecision(
            decision=decision,
            reason=cerbos_decision.reason,
            conditions=cerbos_decision.metadata.get("conditions", []),
            evaluation_time_ms=cerbos_decision.evaluation_time_ms,
            rule_id=cerbos_decision.metadata.get("rule_id"),
            bundle_id=self.bundle_id,
            bundle_version=self.payload.get("version")
        )
    
    def _emergency_legacy_fallback(self, icp: Dict[str, Any], start_time: float) -> PolicyDecision:
        """Emergency fallback to legacy evaluation when Cerbos is unavailable"""
        logger.warning("Using emergency legacy fallback - Cerbos unavailable")
        
        rules = self.payload.get("rules", {})
        
        # Check deny rules first (fail-closed approach)
        for rule in rules.get("deny", []):
            condition = rule.get("condition", "")
            if condition and self._evaluate_legacy_condition(condition, icp):
                return PolicyDecision(
                    decision=DENY,
                    reason=rule.get("reason", "Policy violation (legacy fallback)"),
                    rule_id=rule.get("id"),
                    evaluation_time_ms=(time.time() - start_time) * 1000
                )
        
        # Check allow rules
        for rule in rules.get("allow", []):
            condition = rule.get("condition", "")
            if condition and self._evaluate_legacy_condition(condition, icp):
                return PolicyDecision(
                    decision=ALLOW,
                    reason=f"Matched rule: {rule.get('id', 'unknown')} (legacy fallback)",
                    conditions=rule.get("conditions", []),
                    rule_id=rule.get("id"),
                    evaluation_time_ms=(time.time() - start_time) * 1000
                )
            elif not condition:  # Allow rules without conditions match by default
                return PolicyDecision(
                    decision=ALLOW,
                    reason=f"Matched unconditional rule: {rule.get('id', 'unknown')} (legacy fallback)",
                    conditions=rule.get("conditions", []),
                    rule_id=rule.get("id"),
                    evaluation_time_ms=(time.time() - start_time) * 1000
                )
        
        # Default deny if no rules match
        return PolicyDecision(
            decision=DENY,
            reason="No matching allow rules found (legacy fallback)",
            evaluation_time_ms=(time.time() - start_time) * 1000
        )
    
    def _evaluate_legacy_condition(self, condition: str, icp: Dict[str, Any]) -> bool:
        """Legacy condition evaluation (kept for emergency fallback)
        
        Evaluates legacy conditions against ICP format.
        """
        if not condition:
            return False
        
        try:
            # Simple condition evaluation for MVP
            if ">" in condition:
                parts = condition.split(">")
                if len(parts) == 2:
                    field, value = parts[0].strip(), parts[1].strip()
                    return self._get_icp_value(icp, field) > float(value)
            elif "<" in condition:
                parts = condition.split("<")
                if len(parts) == 2:
                    field, value = parts[0].strip(), parts[1].strip()
                    return self._get_icp_value(icp, field) < float(value)
            elif "==" in condition:
                parts = condition.split("==")
                if len(parts) == 2:
                    field, value = parts[0].strip(), parts[1].strip().strip('"\'')
                    return str(self._get_icp_value(icp, field)) == value
            
            return False
        except (ValueError, TypeError):
            return False
    
    def _get_icp_value(self, icp: Dict[str, Any], field_path: str) -> Any:
        """Get value from ICP using dot notation with legacy path mapping
        
        Maps legacy paths to ICP structure:
        - request.amount → input.resource.attr.amount
        - amount → input.resource.attr.amount
        """
        try:
            # Convert legacy paths to ICP paths
            if field_path.startswith("request."):
                icp_path = field_path.replace("request.", "input.resource.attr.")
            elif "." not in field_path:
                # Simple field name, assume it's in resource.attr
                icp_path = f"input.resource.attr.{field_path}"
            else:
                icp_path = field_path
            
            # Navigate ICP structure
            parts = icp_path.split('.')
            value = icp
            for part in parts:
                value = value[part]
            return value
        except (KeyError, TypeError):
            return None

class LLMParameterExtractor:
    """LLM-based parameter extraction for natural language inputs"""
    
    def __init__(self, config=None):
        self.config = config
        self.openai_client = None
        self.anthropic_client = None
        self._init_clients()
    
    def _init_clients(self):
        """Initialize LLM clients based on config"""
        if not self.config or not self.config.use_llm_extraction:
            return
            
        try:
            if hasattr(self.config, 'llm_provider') and self.config.llm_provider == "openai" and openai:
                self.openai_client = openai.OpenAI(api_key=self.config.llm_api_key)
            elif hasattr(self.config, 'llm_provider') and self.config.llm_provider == "anthropic" and anthropic:
                self.anthropic_client = anthropic.Anthropic(api_key=self.config.llm_api_key)
        except Exception as e:
            logger.warning(f"Failed to initialize {self.config.llm_provider} client: {e}")
    
    def is_available(self) -> bool:
        """Check if LLM extraction is available"""
        return self.openai_client is not None or self.anthropic_client is not None
    
    async def extract_with_llm(self, tool_args: Dict[str, Any], nl_prompt: str, 
                              icp_schema: Dict[str, Any]) -> Dict[str, Any]:
        """Extract parameters using LLM"""
        try:
            # Start with structured parameters
            structured_params = {k: v for k, v in tool_args.items() if k != "nl_prompt"}
            
            if not nl_prompt.strip():
                return structured_params
            
            # Build extraction prompt
            prompt = self._build_extraction_prompt(nl_prompt, icp_schema)
            
            # Call LLM using config
            model = self.config.llm_model if self.config else "claude-3-haiku-20240307"
            
            if self.config.debug:
                provider = getattr(self.config, 'llm_provider', 'anthropic')
                logger.debug(f"{provider.title()} API Call: '{nl_prompt}'")
            
            if self.openai_client:
                response = self.openai_client.chat.completions.create(
                    model=model,
                    messages=[
                        {"role": "system", "content": "Extract parameters as JSON only. No explanations."},
                        {"role": "user", "content": prompt}
                    ],
                    max_tokens=150,
                    temperature=0.1,
                    response_format={"type": "json_object"}
                )
                response_text = response.choices[0].message.content
            elif self.anthropic_client:
                response = self.anthropic_client.messages.create(
                    model=model,
                    max_tokens=150,
                    temperature=0.1,
                    messages=[{"role": "user", "content": f"Extract as JSON:\n{prompt}"}]
                )
                response_text = response.content[0].text
            else:
                raise ValueError("No LLM client available")
            
            if self.config.debug:
                logger.debug(f"API Response: {response_text}")
            
            # Parse response
            llm_params = self._parse_llm_response(response_text)
            
            # Merge params: LLM values take precedence over zero/empty structured defaults
            merged_params = {}
            for key in set(list(structured_params.keys()) + list(llm_params.keys())):
                structured_val = structured_params.get(key)
                llm_val = llm_params.get(key)
                
                # Use LLM value if it exists and structured is empty/zero/None
                if llm_val is not None and (structured_val is None or structured_val == 0 or structured_val == ""):
                    merged_params[key] = llm_val
                # Otherwise use structured value
                elif structured_val is not None:
                    merged_params[key] = structured_val
                # Fallback to LLM value
                elif llm_val is not None:
                    merged_params[key] = llm_val
            
            if self.config.debug:
                logger.debug(f"LLM Extracted: {merged_params}")
            
            return merged_params
            
        except Exception as e:
            logger.warning(f"LLM extraction failed: {e}")
            return structured_params
    
    def _build_extraction_prompt(self, nl_prompt: str, icp_schema: Dict[str, Any]) -> str:
        """Build optimized extraction prompt for ICP format"""
        # Extract properties from ICP schema structure
        input_schema = icp_schema.get("input", {})
        resource_schema = input_schema.get("resource", {}).get("attr", {})
        properties = resource_schema.get("properties", {})
        required = resource_schema.get("required", [])
        
        field_specs = []
        for field in required:
            field_config = properties.get(field, {})
            field_type = field_config.get("type", "string")
            description = field_config.get("description", "")
            if description:
                field_specs.append(f"{field} ({field_type}): {description}")
            else:
                field_specs.append(f"{field}: {field_type}")
        
        # Build generic extraction prompt based on schema
        prompt_parts = [f"Extract structured data from: \"{nl_prompt}\""]
        
        if field_specs:
            prompt_parts.append("\nRequired fields:")
            prompt_parts.extend(f"- {spec}" for spec in field_specs)
        
        # Add generic instructions for numeric fields
        numeric_fields = [field for field in required 
                         if properties.get(field, {}).get("type") == "number"]
        if numeric_fields:
            prompt_parts.append("\nInstructions:")
            for field in numeric_fields:
                prompt_parts.append(f"- If multiple {field} values mentioned, sum them into single '{field}' field")
        
        prompt_parts.append("\nReturn JSON with exact field names:")
        return "\n".join(prompt_parts)
    
    def _parse_llm_response(self, response_text: str) -> Dict[str, Any]:
        """Parse LLM response with fallback"""
        try:
            # Try to parse as JSON
            return json.loads(response_text)
        except json.JSONDecodeError:
            # Fallback: try to extract JSON from response
            import re
            json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
            if json_match:
                try:
                    return json.loads(json_match.group())
                except json.JSONDecodeError:
                    pass
            
            # Last resort: return empty dict
            logger.warning(f"Failed to parse LLM response as JSON: {response_text[:100]}...")
            return {}

class ICPExtractor:
    """ICP (Intermediate Canonical Policy) extraction and normalization
    
    Consolidates all intermediate states (DIS, extraction output, context objects)
    into unified ICP format for consistency with sister project.
    
    This is a pure transformation engine. It extracts values from tool arguments
    and context, applies simple transforms (to_number, currency_normalize), and
    maps them to the ICP structure. Business logic (computations, aggregations,
    complex operations) belongs in the policy engine via Cerbos CEL expressions.
    
    Principle: Extractor = Pure Transformation, Policy Engine = Business Logic
    """
    
    def __init__(self, config=None):
        self.config = config
        # Initialize LLM extractor if API key is available
        if config and config.use_llm_extraction:
            self.llm_extractor = LLMParameterExtractor(config)
        else:
            self.llm_extractor = None
    
    async def extract_to_icp(self, tool_args: Dict[str, Any], context: Dict[str, Any], 
                           extraction_bindings: Dict[str, Any], icp_schema: Dict[str, Any]) -> Dict[str, Any]:
        """Extract and normalize parameters into ICP (Intermediate Canonical Policy) format
        
        ICP format is Cerbos-compatible and eliminates multiple intermediate transformations.
        """
        try:
            # Check if we have natural language input and LLM extraction is enabled
            nl_prompt = tool_args.get("nl_prompt", "")
            
            if (self.config and 
                self.config.use_llm_extraction and 
                self.llm_extractor and 
                self.llm_extractor.is_available() and 
                nl_prompt.strip()):
                # Use LLM extraction for natural language
                try:
                    llm_params = await self.llm_extractor.extract_with_llm(tool_args, nl_prompt, icp_schema)
                    return self._build_icp_from_structured(llm_params, context, extraction_bindings, icp_schema)
                except Exception as e:
                    logger.warning(f"LLM extraction failed, falling back to structured: {e}")
            
            # Use structured extraction (rules-based)
            return self._build_icp_from_structured(tool_args, context, extraction_bindings, icp_schema)
            
        except Exception as e:
            logger.error(f"ICP extraction failed: {e}")
            return self._build_icp_from_structured(tool_args, context, extraction_bindings, icp_schema)
    
    def _build_icp_from_structured(self, tool_args: Dict[str, Any], context: Dict[str, Any],
                                 extraction_bindings: Dict[str, Any], icp_schema: Dict[str, Any]) -> Dict[str, Any]:
        """Build ICP from structured parameters using extraction bindings
        
        ICP format is Cerbos-compatible with direct mapping to Cerbos request structure.
        """
        # Initialize ICP with version and input structure (Cerbos-compatible)
        icp = {
            "version": "1.0.0",
            "input": {
                "principal": {},
                "resource": {"attr": {}},
                "actions": [],
                "environment": {}
            }
        }
        
        # Apply extraction bindings to build ICP structure
        bindings = extraction_bindings.get("bindings", [])
        for binding in bindings:
            path = binding.get("path", "")
            sources = binding.get("sources", [])
            required = binding.get("required", False)
            
            value = self._extract_value_from_sources(sources, tool_args, context)
            
            if value is not None:
                # Apply transforms if specified
                transforms = binding.get("transform", [])
                for transform in transforms:
                    value = self._apply_transform(value, transform)
                
                # Set value in ICP using dot notation (maps to Cerbos structure)
                self._set_icp_value(icp, path, value)
            elif required:
                logger.warning(f"Required field {path} not found in sources")
        
        # Ensure required ICP structure is complete
        self._finalize_icp_structure(icp, context)
        
        return icp
    
    def _extract_value_from_sources(self, sources: List[Dict[str, Any]], tool_args: Dict[str, Any], 
                                  context: Dict[str, Any]) -> Any:
        """Extract value from specified sources - pure transformation only
        
        This method performs pure data extraction and transformation. Business logic
        (computations, aggregations, complex operations) belongs in the policy engine
        via Cerbos CEL expressions, not in the extractor.
        
        Supported source types:
        - "arg": Extract from tool arguments
        - "context": Extract from execution context
        - "literal": Use literal value
        
        For computations (sum, max, min, aggregations), extract individual fields
        and perform computations in Cerbos policy CEL expressions.
        """
        for source in sources:
            source_type = source.get("type", "")
            if source_type == "arg":
                name = source.get("name", "")
                if name in tool_args:
                    return tool_args[name]
            elif source_type == "context":
                name = source.get("name", "")
                if name in context:
                    return context[name]
            elif source_type == "literal":
                return source.get("value")
            # Removed: "computed" source type
            # Business logic (sum, max, min, aggregations) belongs in the policy engine
            # via Cerbos CEL expressions, not in the extractor.
            # Example: Extract individual fields (amount, fee, tax) and compute
            # total in Cerbos policy: request.resource.attr.amount + 
            #                         request.resource.attr.fee + 
            #                         request.resource.attr.tax > 5000
        
        return None
    
    def _apply_transform(self, value: Any, transform: Dict[str, Any]) -> Any:
        """Apply transformation to value"""
        transform_name = transform.get("name", "")
        
        if transform_name == "to_number":
            try:
                return float(value)
            except (ValueError, TypeError):
                return value
        elif transform_name == "currency_normalize":
            params = transform.get("params", {})
            default = params.get("default", "USD")
            if isinstance(value, str):
                return value.upper() if value.upper() in ["USD", "CAD", "EUR"] else default
            return value
        
        return value
    
    def _set_icp_value(self, icp: Dict[str, Any], path: str, value: Any):
        """Set value in ICP using dot notation (Cerbos-compatible paths)
        
        Maps legacy DIS paths to ICP structure:
        - request.* → input.resource.attr.*
        - principal → input.principal.id
        - action → input.actions
        """
        # Convert legacy DIS paths to ICP paths
        if path.startswith("request."):
            # request.amount → input.resource.attr.amount
            icp_path = path.replace("request.", "input.resource.attr.")
        elif path == "principal":
            # principal → input.principal.id
            icp_path = "input.principal.id"
        elif path == "action":
            # action → input.actions (as array)
            icp["input"]["actions"] = [value] if isinstance(value, str) else value
            return
        else:
            # Use path as-is if already ICP format
            icp_path = path
        
        # Set value using dot notation
        parts = icp_path.split('.')
        current = icp
        
        for part in parts[:-1]:
            if part not in current:
                current[part] = {}
            current = current[part]
        
        current[parts[-1]] = value
    
    def _finalize_icp_structure(self, icp: Dict[str, Any], context: Dict[str, Any]):
        """Finalize ICP structure with required fields and environment context"""
        input_data = icp["input"]
        
        # Ensure principal has required structure
        if "id" not in input_data["principal"]:
            input_data["principal"]["id"] = context.get("agent_id", "unknown")
        if "roles" not in input_data["principal"]:
            input_data["principal"]["roles"] = ["agent"]
        
        # Ensure resource has required structure
        if "kind" not in input_data["resource"]:
            input_data["resource"]["kind"] = "tool"
        if "id" not in input_data["resource"]:
            input_data["resource"]["id"] = f"resource-{int(time.time())}"
        
        # Ensure actions is populated
        if not input_data["actions"]:
            input_data["actions"] = ["execute"]
        
        # Add environment context (Cerbos-compatible)
        input_data["environment"].update({
            "region": context.get("region", "us"),
            "time": datetime.now(timezone.utc).isoformat(),
            "agent_id": context.get("agent_id", "unknown"),
            "org_id": context.get("org_id", "unknown")
        })

class PolicyEnforcementPoint:
    """Main PEP class that orchestrates policy enforcement according to the design"""
    
    def __init__(self, agent_id: str, org_id: str, config=None):
        self.agent_id = agent_id
        self.org_id = org_id
        self.config = config
        
        # Initialize components
        self.icp_extractor = ICPExtractor(config)
        self.bundle_cache: Dict[str, PolicyBundle] = {}
        
    async def enforce_policy(
        self,
        tool_name: str,
        tool_args: Dict[str, Any],
        context: Dict[str, Any],
        policy_bundle_data: Dict[str, Any],
        jwks: Dict[str, Any] = None
    ) -> Tuple[PolicyDecision, DecisionReceipt]:
        """Main enforcement method - validates, extracts, evaluates, and logs"""
        start_time = time.time()
        
        try:
            # 1. Get or create policy bundle
            bundle = self._get_policy_bundle(policy_bundle_data, jwks)
            
            # 2. Verify bundle integrity
            if not bundle.verify():
                decision = PolicyDecision(
                    decision=DENY,
                    reason="Bundle verification failed",
                    evaluation_time_ms=(time.time() - start_time) * 1000
                )
                receipt = self._create_decision_receipt(bundle, {}, decision)
                return decision, receipt
            
            # 3. Validate tool args against Tool Schema (execution truth)
            tool_schema = bundle.payload.get("tool_schema", {})
            if not self._validate_tool_args(tool_name, tool_args, tool_schema):
                decision = PolicyDecision(
                    decision=DENY,
                    reason="Tool validation failed",
                    evaluation_time_ms=(time.time() - start_time) * 1000
                )
                receipt = self._create_decision_receipt(bundle, {}, decision)
                return decision, receipt
            
            # 4. Extract parameters using ICP (governance truth)
            extraction_bindings = bundle.payload.get("extraction_bindings", {})
            icp_schema = bundle.payload.get("icp_schema", bundle.payload.get("dis_schema", {}))
            icp = await self.icp_extractor.extract_to_icp(tool_args, context, extraction_bindings, icp_schema)
            
            # Store ICP for debugging
            self._last_icp = icp
            
            # 5. Evaluate policy rules
            decision = bundle.evaluate(icp)
            
            # 6. Create decision receipt
            receipt = self._create_decision_receipt(bundle, icp, decision)
            
            # 7. Log decision (async, non-blocking)
            asyncio.create_task(self._log_decision(tool_name, tool_args, decision, receipt))
            
            return decision, receipt
            
        except Exception as e:
            logger.error(f"Policy enforcement failed: {e}")
            decision = PolicyDecision(
                decision=DENY,
                reason=f"Enforcement error: {e}",
                evaluation_time_ms=(time.time() - start_time) * 1000
            )
            receipt = self._create_decision_receipt(bundle, {}, decision)
            return decision, receipt
    
    def _get_policy_bundle(self, bundle_data: Dict[str, Any], jwks: Dict[str, Any] = None) -> PolicyBundle:
        """Get policy bundle with caching"""
        bundle_id = bundle_data.get("policy_id", "unknown")
        
        # Check cache
        if bundle_id in self.bundle_cache:
            return self.bundle_cache[bundle_id]
        
        # Create new bundle
        bundle = PolicyBundle(bundle_data, jwks)
        self.bundle_cache[bundle_id] = bundle
        return bundle
    
    def _validate_tool_args(self, tool_name: str, tool_args: Dict[str, Any], 
                           tool_schema: Dict[str, Any]) -> bool:
        """Validate tool arguments against tool schema (execution truth)"""
        try:
            required_fields = tool_schema.get("required", [])
            
            # Check required fields
            missing_fields = [field for field in required_fields if field not in tool_args]
            if missing_fields:
                logger.warning(f"Missing required fields: {missing_fields}")
                return False
            
            # Basic type validation
            properties = tool_schema.get("properties", {})
            for field_name, value in tool_args.items():
                if field_name in properties:
                    field_config = properties[field_name]
                    field_type = field_config.get("type", "string")
                    
                    if field_type == "number" and not isinstance(value, (int, float)):
                        try:
                            float(value)
                        except (ValueError, TypeError):
                            logger.warning(f"Field {field_name} must be a number")
                            return False
                    elif field_type == "integer" and not isinstance(value, int):
                        try:
                            int(value)
                        except (ValueError, TypeError):
                            logger.warning(f"Field {field_name} must be an integer")
                            return False
                    elif field_type == "boolean" and not isinstance(value, bool):
                        if not isinstance(value, str) or value.lower() not in ["true", "false", "1", "0"]:
                            logger.warning(f"Field {field_name} must be a boolean")
                            return False
            
            return True
            
        except Exception as e:
            logger.warning(f"Tool validation failed: {e}")
            return False
    
    def _create_decision_receipt(self, bundle: PolicyBundle, icp: Dict[str, Any], 
                               decision: PolicyDecision) -> DecisionReceipt:
        """Create cryptographic decision receipt (aligned with crypto design)"""
        bundle_id = bundle.bundle_id
        bundle_hash = hashlib.sha256(json.dumps(bundle.payload, sort_keys=True).encode()).hexdigest()
        
        # Create ICP hash
        icp_data = {
            "tool_name": bundle.payload.get("tool_name", "unknown"),
            "parameters": icp,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        icp_hash = hashlib.sha256(json.dumps(icp_data, sort_keys=True).encode()).hexdigest()
        
        # Create receipt (aligned with crypto design format)
        receipt = DecisionReceipt(
            agent_id=self.agent_id,
            bundle_id=bundle_id,
            bundle_hash=f"sha256:{bundle_hash}",
            dis_hash=f"sha256:{icp_hash}",  # Using ICP hash
            decision=decision.decision.title(),  # "Deny" or "Permit"
            reason=decision.reason,
            ts=datetime.now(timezone.utc).isoformat()
        )
        
        # Sign receipt with agent private key for non-repudiation
        receipt.signature = self._sign_decision_receipt(receipt)
        
        return receipt
    
    def _sign_decision_receipt(self, receipt: DecisionReceipt) -> str:
        """Sign decision receipt with agent Ed25519 private key"""
        try:
            import base64
            from cryptography.hazmat.primitives.asymmetric import ed25519
            
            # Get agent private key from config
            if hasattr(self.config, 'identity') and hasattr(self.config.identity, 'ed25519_private_key_b64'):
                private_key_b64 = self.config.identity.ed25519_private_key_b64
                if private_key_b64 == "demo_key":
                    # Generate deterministic key for demo
                    import hashlib
                    agent_key = f"{self.org_id}:{self.agent_id}:{self.config.principal.instance}"
                    seed = hashlib.sha256(agent_key.encode()).digest()[:32]
                    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
                else:
                    private_key_bytes = base64.b64decode(private_key_b64)
                    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)
                
                # Create receipt data for signing
                receipt_data = {
                    "agent_id": receipt.agent_id,
                    "bundle_id": receipt.bundle_id,
                    "bundle_hash": receipt.bundle_hash,
                    "dis_hash": receipt.dis_hash,
                    "decision": receipt.decision,
                    "reason": receipt.reason,
                    "ts": receipt.ts
                }
                
                # Sign the receipt
                data_to_sign = json.dumps(receipt_data, sort_keys=True).encode('utf-8')
                signature = private_key.sign(data_to_sign)
                return base64.b64encode(signature).decode('utf-8')
            
        except Exception as e:
            logger.warning(f"Failed to sign decision receipt: {e}")
        
        return None
    
    async def _log_decision(self, tool_name: str, tool_args: Dict[str, Any], 
                          decision: PolicyDecision, receipt: DecisionReceipt):
        """Log policy decision for audit trail"""
        try:
            # This would integrate with the platform's audit logging
            # For MVP: just log locally
            logger.info(f"Policy decision: {decision.decision} for {tool_name} - {decision.reason}")
        except Exception as e:
            logger.warning(f"Failed to log decision: {e}")
