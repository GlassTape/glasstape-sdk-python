#!/usr/bin/env python3
"""
Role-Based Access Control Test
===============================

Test RBAC with different user roles
"""

import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from glasstape import configure, govern, set_context, clear_context, GovernanceError

configure(
    agent_id="rbac-agent",
    policy_dir=os.path.join(os.path.dirname(__file__), '..', 'policies'),
    debug=True
)

@govern("finance.payments.v1")
def process_payment(amount: float, recipient: str):
    return f"Payment of ${amount} to {recipient}"

print("=" * 80)
print("🧪 ROLE-BASED ACCESS CONTROL TEST")
print("=" * 80)

test_amount = 100.0  # Over $50 limit

roles = [
    ("analyst", False, "Analysts limited to $50"),
    ("admin", True, "Admins have no limit"),
    ("manager", False, "Managers not explicitly allowed"),  
]

for role, should_allow, description in roles:
    print(f"\n📝 TEST: {role.upper()} role - {description}")
    clear_context()
    set_context(user_id=f"user-{role}", user_role=role)
    
    try:
        result = process_payment(test_amount, "vendor-test")
        if should_allow:
            print(f"✅ ALLOWED (Expected): {result}")
        else:
            print(f"⚠️  ALLOWED (Unexpected): {result}")
    except GovernanceError as e:
        if not should_allow:
            print(f"❌ DENIED (Expected): {e}")
        else:
            print(f"⚠️  DENIED (Unexpected): {e}")

print("\n" + "=" * 80)
print("✅ RBAC test complete!")

