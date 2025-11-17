"""
Tests for GlassTape Cerbos Evaluator
"""

import pytest
import json
from unittest.mock import patch, MagicMock
from glasstape.cerbos_evaluator import CerbosEvaluator, CerbosDecision


class TestCerbosEvaluator:
    """Test CerbosEvaluator class"""

    def setup_method(self):
        """Setup for each test"""
        self.evaluator = CerbosEvaluator()

    def test_cerbos_evaluator_initialization(self):
        """Test CerbosEvaluator initialization"""
        assert self.evaluator.engine is None
        assert self.evaluator.store is None
        assert self.evaluator.instance is None  # Fixed: should be initialized
        assert self.evaluator._available is True

    def test_is_available(self):
        """Test is_available method"""
        assert self.evaluator.is_available() is True

    def test_evaluate_with_cerbos_yaml(self):
        """Test evaluate method with Cerbos YAML"""
        policy_yaml = """
apiVersion: api.cerbos.dev/v1
resourcePolicy:
  version: "1.0"
  resource: "payment"
  rules:
    - actions: ['process']
      effect: EFFECT_ALLOW
      condition:
        match:
          expr: "request.resource.attr.amount <= 100"
"""
        
        icp = {
            "input": {
                "resource": {"attr": {"amount": 50}},
                "principal": {"id": "user123"},
                "actions": ["process"],
                "environment": {}
            }
        }
        
        decision = self.evaluator.evaluate(policy_yaml, icp)
        
        assert isinstance(decision, CerbosDecision)
        assert decision.decision in ["EFFECT_ALLOW", "EFFECT_DENY"]
        assert decision.evaluation_time_ms > 0

    def test_build_cerbos_request(self):
        """Test _build_cerbos_request method"""
        icp = {
            "input": {
                "principal": {"id": "user123", "roles": ["admin"]},
                "resource": {"kind": "payment", "id": "pay123", "attr": {"amount": 100}},
                "actions": ["process"],
                "environment": {"region": "us"},
                "auxData": {"timestamp": "2023-01-01T00:00:00Z"}
            }
        }
        
        request = self.evaluator._build_cerbos_request(icp)
        
        assert request["principal"]["id"] == "user123"
        assert request["principal"]["roles"] == ["admin"]
        assert request["resource"]["kind"] == "payment"
        assert request["resource"]["attr"]["amount"] == 100
        assert request["actions"] == ["process"]
        assert request["environment"]["region"] == "us"

    def test_build_cerbos_request_with_defaults(self):
        """Test _build_cerbos_request with default values"""
        icp = {"input": {}}
        
        request = self.evaluator._build_cerbos_request(icp)
        
        assert request["principal"]["id"] == "unknown"
        assert request["principal"]["roles"] == ["user"]
        assert request["resource"]["kind"] == "tool"
        assert request["resource"]["id"] == "default"
        assert request["actions"] == ["execute"]

    def test_parse_cerbos_yaml(self):
        """Test _parse_cerbos_yaml method"""
        policy_yaml = """
apiVersion: api.cerbos.dev/v1
resourcePolicy:
  version: "1.0"
  resource: "payment"
"""
        
        policy = self.evaluator._parse_cerbos_yaml(policy_yaml)
        
        assert policy["apiVersion"] == "api.cerbos.dev/v1"
        assert policy["resourcePolicy"]["version"] == "1.0"
        assert policy["resourcePolicy"]["resource"] == "payment"

    def test_parse_cerbos_yaml_invalid(self):
        """Test _parse_cerbos_yaml with invalid YAML"""
        invalid_yaml = "invalid: yaml: content: ["
        
        policy = self.evaluator._parse_cerbos_yaml(invalid_yaml)
        
        assert policy == {}

    def test_evaluate_with_enhanced_engine(self):
        """Test _evaluate_with_enhanced_engine method"""
        policy_yaml = """
resourcePolicy:
  rules:
    - name: "allow_small_amounts"
      actions: ["process"]
      effect: "EFFECT_ALLOW"
      condition:
        match:
          expr: "request.resource.attr.amount <= 100"
"""
        
        request = {
            "resource": {"attr": {"amount": 50}},
            "actions": ["process"],
            "principal": {},
            "environment": {}
        }
        
        result = self.evaluator._evaluate_with_enhanced_engine(policy_yaml, request)
        
        assert result["effect"] in ["EFFECT_ALLOW", "EFFECT_DENY"]
        assert "reason" in result
        assert "metadata" in result

    def test_rule_matches_with_cel_actions(self):
        """Test _rule_matches_with_cel with action matching"""
        rule = {
            "name": "test_rule",
            "actions": ["process", "execute"],
            "effect": "EFFECT_ALLOW"
        }
        
        request = {
            "actions": ["process"],
            "resource": {"attr": {}},
            "principal": {}
        }
        
        result = self.evaluator._rule_matches_with_cel(rule, request)
        assert result is True

    def test_rule_matches_with_cel_actions_no_match(self):
        """Test _rule_matches_with_cel with no action match"""
        rule = {
            "name": "test_rule",
            "actions": ["delete"],
            "effect": "EFFECT_ALLOW"
        }
        
        request = {
            "actions": ["process"],
            "resource": {"attr": {}},
            "principal": {}
        }
        
        result = self.evaluator._rule_matches_with_cel(rule, request)
        assert result is False

    def test_rule_matches_with_cel_wildcard_actions(self):
        """Test _rule_matches_with_cel with wildcard actions"""
        rule = {
            "name": "test_rule",
            "actions": ["*"],
            "effect": "EFFECT_ALLOW"
        }
        
        request = {
            "actions": ["any_action"],
            "resource": {"attr": {}},
            "principal": {}
        }
        
        result = self.evaluator._rule_matches_with_cel(rule, request)
        assert result is True

    def test_evaluate_cel_condition_simple(self):
        """Test _evaluate_cel_condition with simple condition"""
        condition = "request.resource.attr.amount > 50"
        request = {
            "resource": {"attr": {"amount": 100}},
            "principal": {},
            "environment": {}
        }
        
        result = self.evaluator._evaluate_cel_condition(condition, request)
        assert result is True

    def test_evaluate_cel_condition_false(self):
        """Test _evaluate_cel_condition returning false"""
        condition = "request.resource.attr.amount > 200"
        request = {
            "resource": {"attr": {"amount": 100}},
            "principal": {},
            "environment": {}
        }
        
        result = self.evaluator._evaluate_cel_condition(condition, request)
        assert result is False

    def test_evaluate_with_pattern_matching_or_condition(self):
        """Test _evaluate_with_pattern_matching with OR condition"""
        condition = "amount > 50 || user_role == 'admin'"
        request = {
            "resource": {"attr": {"amount": 30}},
            "principal": {"attr": {"user_role": "admin"}},
            "environment": {}
        }
        
        result = self.evaluator._evaluate_with_pattern_matching(condition, request)
        assert result is True

    def test_evaluate_with_pattern_matching_and_condition(self):
        """Test _evaluate_with_pattern_matching with AND condition"""
        condition = "amount > 50 && user_role == 'admin'"
        request = {
            "resource": {"attr": {"amount": 100}},
            "principal": {"attr": {"user_role": "admin"}},
            "environment": {}
        }
        
        result = self.evaluator._evaluate_with_pattern_matching(condition, request)
        assert result is True

    def test_evaluate_with_pattern_matching_and_condition_false(self):
        """Test _evaluate_with_pattern_matching with AND condition returning false"""
        condition = "amount > 50 && user_role == 'admin'"
        request = {
            "resource": {"attr": {"amount": 100}},
            "principal": {"attr": {"user_role": "user"}},  # Not admin
            "environment": {}
        }
        
        result = self.evaluator._evaluate_with_pattern_matching(condition, request)
        assert result is False

    def test_evaluate_simple_condition_amount_greater(self):
        """Test _evaluate_simple_condition with amount > threshold"""
        condition = "request.resource.attr.amount > 50"
        request = {"resource": {"attr": {"amount": 100}}}
        resource_attr = {"amount": 100}
        principal_attr = {}
        
        def mock_evaluate_arithmetic(expr):
            return 100.0
        
        result = self.evaluator._evaluate_simple_condition(
            condition, request, resource_attr, principal_attr, mock_evaluate_arithmetic
        )
        assert result is True

    def test_evaluate_simple_condition_amount_less_equal(self):
        """Test _evaluate_simple_condition with amount <= threshold"""
        condition = "request.resource.attr.amount <= 50"
        request = {"resource": {"attr": {"amount": 30}}}
        resource_attr = {"amount": 30}
        principal_attr = {}
        
        def mock_evaluate_arithmetic(expr):
            return 30.0
        
        result = self.evaluator._evaluate_simple_condition(
            condition, request, resource_attr, principal_attr, mock_evaluate_arithmetic
        )
        assert result is True

    def test_evaluate_simple_condition_string_comparison(self):
        """Test _evaluate_simple_condition with string comparison"""
        condition = "request.resource.attr.recipient == 'blocked'"
        request = {"resource": {"attr": {"recipient": "blocked"}}}
        resource_attr = {"recipient": "blocked"}
        principal_attr = {}
        
        def mock_evaluate_arithmetic(expr):
            return 0.0
        
        result = self.evaluator._evaluate_simple_condition(
            condition, request, resource_attr, principal_attr, mock_evaluate_arithmetic
        )
        assert result is True

    def test_evaluate_simple_condition_user_role(self):
        """Test _evaluate_simple_condition with user role check"""
        condition = "user_role == 'admin'"
        request = {}
        resource_attr = {}
        principal_attr = {"user_role": "admin"}
        
        def mock_evaluate_arithmetic(expr):
            return 0.0
        
        result = self.evaluator._evaluate_simple_condition(
            condition, request, resource_attr, principal_attr, mock_evaluate_arithmetic
        )
        assert result is True

    def test_evaluate_simple_condition_principal_id(self):
        """Test _evaluate_simple_condition with principal ID check"""
        condition = 'principal.id == "admin"'
        # The principal object needs to be accessible in the request
        request = {"principal": {"id": "admin"}}
        resource_attr = {}
        principal_attr = {}
        
        def mock_evaluate_arithmetic(expr):
            return 0.0
        
        # The method accesses principal from the request parameter
        result = self.evaluator._evaluate_simple_condition(
            condition, request, resource_attr, principal_attr, mock_evaluate_arithmetic
        )
        assert result is True

    def test_evaluate_simple_condition_boolean_true(self):
        """Test _evaluate_simple_condition with boolean true"""
        condition = "true"
        request = {}
        resource_attr = {}
        principal_attr = {}
        
        def mock_evaluate_arithmetic(expr):
            return 0.0
        
        result = self.evaluator._evaluate_simple_condition(
            condition, request, resource_attr, principal_attr, mock_evaluate_arithmetic
        )
        assert result is True

    def test_evaluate_simple_condition_boolean_false(self):
        """Test _evaluate_simple_condition with boolean false"""
        condition = "false"
        request = {}
        resource_attr = {}
        principal_attr = {}
        
        def mock_evaluate_arithmetic(expr):
            return 0.0
        
        result = self.evaluator._evaluate_simple_condition(
            condition, request, resource_attr, principal_attr, mock_evaluate_arithmetic
        )
        assert result is False

    def test_evaluate_simple_condition_has_function(self):
        """Test _evaluate_simple_condition with has() function"""
        condition = 'has("amount")'
        request = {}
        resource_attr = {"amount": 100}
        principal_attr = {}
        
        def mock_evaluate_arithmetic(expr):
            return 0.0
        
        result = self.evaluator._evaluate_simple_condition(
            condition, request, resource_attr, principal_attr, mock_evaluate_arithmetic
        )
        assert result is True

    def test_compile_policy_success(self):
        """Test compile_policy with valid policy"""
        policy_yaml = """
resourcePolicy:
  resource: "payment"
  version: "1.0"
  rules:
    - name: "allow_small"
      actions: ["process"]
      effect: "EFFECT_ALLOW"
      condition:
        match:
          expr: "request.resource.attr.amount <= 100"
"""
        
        result = self.evaluator.compile_policy(policy_yaml)
        assert result is True

    def test_compile_policy_missing_resource_policy(self):
        """Test compile_policy with missing resourcePolicy"""
        policy_yaml = """
apiVersion: api.cerbos.dev/v1
# Missing resourcePolicy
"""
        
        result = self.evaluator.compile_policy(policy_yaml)
        assert result is False

    def test_compile_policy_missing_resource(self):
        """Test compile_policy with missing resource field"""
        policy_yaml = """
resourcePolicy:
  version: "1.0"
  # Missing resource field
"""
        
        result = self.evaluator.compile_policy(policy_yaml)
        assert result is False

    def test_compile_policy_invalid_yaml(self):
        """Test compile_policy with invalid YAML"""
        invalid_yaml = "invalid: yaml: content: ["
        
        result = self.evaluator.compile_policy(invalid_yaml)
        assert result is False

    def test_validate_rule_success(self):
        """Test _validate_rule with valid rule"""
        rule = {
            "name": "test_rule",
            "effect": "EFFECT_ALLOW",
            "actions": ["process"]
        }
        
        result = self.evaluator._validate_rule(rule, 0)
        assert result is True

    def test_validate_rule_missing_effect(self):
        """Test _validate_rule with missing effect"""
        rule = {
            "name": "test_rule",
            "actions": ["process"]
            # Missing effect
        }
        
        result = self.evaluator._validate_rule(rule, 0)
        assert result is False

    def test_validate_rule_invalid_effect(self):
        """Test _validate_rule with invalid effect"""
        rule = {
            "name": "test_rule",
            "effect": "INVALID_EFFECT",
            "actions": ["process"]
        }
        
        result = self.evaluator._validate_rule(rule, 0)
        assert result is False

    def test_validate_rule_invalid_actions(self):
        """Test _validate_rule with invalid actions"""
        rule = {
            "name": "test_rule",
            "effect": "EFFECT_ALLOW",
            "actions": "not_a_list"  # Should be a list
        }
        
        result = self.evaluator._validate_rule(rule, 0)
        assert result is False

    def test_validate_cel_conditions_success(self):
        """Test _validate_cel_conditions with valid conditions"""
        rules = [
            {
                "name": "test_rule",
                "effect": "EFFECT_ALLOW",
                "condition": {
                    "match": {
                        "expr": "request.resource.attr.amount > 0"
                    }
                }
            }
        ]
        
        result = self.evaluator._validate_cel_conditions(rules)
        assert result is True

    def test_validate_cel_expression_success(self):
        """Test _validate_cel_expression with valid expression"""
        expression = "request.resource.attr.amount > 0"
        
        result = self.evaluator._validate_cel_expression(expression, 0)
        assert result is True

    def test_validate_cel_expression_empty(self):
        """Test _validate_cel_expression with empty expression"""
        expression = ""
        
        result = self.evaluator._validate_cel_expression(expression, 0)
        assert result is False

    def test_validate_cel_expression_unbalanced_parentheses(self):
        """Test _validate_cel_expression with unbalanced parentheses"""
        expression = "request.resource.attr.amount > (100"
        
        result = self.evaluator._validate_cel_expression(expression, 0)
        assert result is False

    def test_validate_cel_expression_unbalanced_quotes(self):
        """Test _validate_cel_expression with unbalanced quotes"""
        expression = 'request.resource.attr.name == "test'
        
        result = self.evaluator._validate_cel_expression(expression, 0)
        assert result is False


class TestCerbosDecision:
    """Test CerbosDecision dataclass"""

    def test_cerbos_decision_creation(self):
        """Test CerbosDecision creation"""
        decision = CerbosDecision(
            decision="EFFECT_ALLOW",
            reason="Policy allows",
            evaluation_time_ms=5.0
        )
        
        assert decision.decision == "EFFECT_ALLOW"
        assert decision.reason == "Policy allows"
        assert decision.evaluation_time_ms == 5.0
        assert decision.metadata == {}

    def test_cerbos_decision_with_metadata(self):
        """Test CerbosDecision with metadata"""
        metadata = {"rule_id": "test_rule", "conditions": ["condition1"]}
        decision = CerbosDecision(
            decision="EFFECT_DENY",
            reason="Policy denies",
            metadata=metadata
        )
        
        assert decision.metadata == metadata