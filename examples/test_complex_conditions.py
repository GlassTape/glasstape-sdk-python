#!/usr/bin/env python3
"""
Complex Policy Conditions Test
===============================

Test complex CEL expressions and multi-field conditions
"""

import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from glasstape import configure, govern, set_context, GovernanceError

configure(
    agent_id="complex-agent",
    policy_dir=os.path.join(os.path.dirname(__file__), '..', 'policies'),
    debug=True
)

@govern("finance.payments.v1")
def process_payment(amount: float, recipient: str):
    return f"Payment of ${amount} to {recipient}"

print("=" * 80)
print("🧪 COMPLEX POLICY CONDITIONS TEST")
print("=" * 80)

# Set analyst context
set_context(user_id="analyst-1", user_role="analyst")

test_cases = [
    (10.0, "Small payment", True),
    (50.0, "At limit", True),
    (50.01, "Just over limit", False),
    (100.0, "Double the limit", False),
    (1000.0, "Large payment", False),
]

for amount, description, should_allow in test_cases:
    print(f"\n📝 TEST: ${amount} - {description}")
    try:
        result = process_payment(amount, "vendor-test")
        if should_allow:
            print(f"✅ ALLOWED (Expected): {result}")
        else:
            print(f"⚠️  ALLOWED (Unexpected): {result}")
    except GovernanceError as e:
        if not should_allow:
            print(f"❌ DENIED (Expected): {str(e)[:60]}...")
        else:
            print(f"⚠️  DENIED (Unexpected): {e}")

print("\n" + "=" * 80)
print("✅ Complex conditions test complete!")

