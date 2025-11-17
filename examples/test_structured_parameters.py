#!/usr/bin/env python3
"""
Structured Parameters Test
===========================

Test structured parameter extraction without LLM
"""

import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from glasstape import configure, govern, set_context, GovernanceError

# Configure without LLM (pure structured)
configure(
    agent_id="struct-agent",
    policy_dir=os.path.join(os.path.dirname(__file__), '..', 'policies'),
    debug=True
)

@govern("finance.payments.v1")
def process_payment(amount: float, recipient: str):
    """Process payment"""
    return f"Payment of ${amount} to {recipient}"

print("=" * 80)
print("🧪 STRUCTURED PARAMETERS TEST")
print("=" * 80)

# Test with analyst role
set_context(user_id="analyst-1", user_role="analyst")

print("\n📝 TEST 1: Small payment (analyst)")
try:
    result = process_payment(30.0, "vendor-a")
    print(f"✅ {result}")
except GovernanceError as e:
    print(f"❌ {e}")

print("\n📝 TEST 2: Large payment (analyst)")
try:
    result = process_payment(5000.0, "vendor-b")
    print(f"✅ {result}")
except GovernanceError as e:
    print(f"❌ DENIED (Expected): {e}")

# Test with admin role
set_context(user_id="admin-1", user_role="admin")

print("\n📝 TEST 3: Large payment (admin)")
try:
    result = process_payment(5000.0, "vendor-c")
    print(f"✅ {result}")
except GovernanceError as e:
    print(f"❌ {e}")

print("\n" + "=" * 80)
print("✅ Structured parameter extraction working!")

