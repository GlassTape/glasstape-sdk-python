#!/usr/bin/env python3
"""
Natural Language Governance Test
=================================

Comprehensive test of LLM extraction + Cerbos policy enforcement
"""

import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from glasstape import configure, govern, set_context, GovernanceError
from dotenv import load_dotenv

# Load .env from examples directory
load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))

# Configure with LLM extraction
configure(
    agent_id="nl-agent",
    policy_dir=os.path.join(os.path.dirname(__file__), '..', 'policies'),
    llm_provider="anthropic",
    llm_api_key=os.getenv("ANTHROPIC_API_KEY"),
    llm_model="claude-3-haiku-20240307",
    debug=True
)

@govern("finance.payments.v1")
def process_payment(amount: float = 0, recipient: str = "", nl_prompt: str = ""):
    """Process payment with NL support"""
    return f"Payment of ${amount} to {recipient} processed"

print("=" * 80)
print("🧪 NATURAL LANGUAGE GOVERNANCE TEST")
print("=" * 80)

# Test 1: Small amount (should allow)
print("\n📝 TEST 1: Small NL amount")
set_context(user_id="analyst-1", user_role="analyst")
try:
    result = process_payment(nl_prompt="Pay $45 to vendor-abc")
    print(f"✅ {result}")
except GovernanceError as e:
    print(f"❌ {e}")

# Test 2: Large amount (should deny for analyst)
print("\n📝 TEST 2: Large NL amount (analyst)")
try:
    result = process_payment(nl_prompt="Send payment of $5000 to contractor-xyz")
    print(f"✅ {result}")
except GovernanceError as e:
    print(f"❌ DENIED (Expected): {e}")

# Test 3: Large amount with admin role (should allow)
print("\n📝 TEST 3: Large amount (admin)")
set_context(user_id="admin-1", user_role="admin")
try:
    result = process_payment(nl_prompt="Process $5000 payment to vendor-123")
    print(f"✅ {result}")
except GovernanceError as e:
    print(f"❌ {e}")

print("\n" + "=" * 80)
print("✅ Natural language governance working!")

