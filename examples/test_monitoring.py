#!/usr/bin/env python3
"""
Monitoring (Non-Blocking) Test
===============================

Test @monitor decorator - logs but never blocks
"""

import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from glasstape import configure, monitor, set_context

configure(
    agent_id="monitor-agent",
    policy_dir=os.path.join(os.path.dirname(__file__), '..', 'policies'),
    debug=True
)

@monitor("analytics.data_access.v1")
def get_user_data(user_id: str):
    """Get user data - monitored but never blocked"""
    return f"User data for {user_id}: [name, email, preferences]"

print("=" * 80)
print("🧪 MONITORING (NON-BLOCKING) TEST")
print("=" * 80)

set_context(user_id="analyst-1", user_role="analyst")

print("\n📝 TEST 1: Access user data (always allowed)")
result = get_user_data("user-123")
print(f"✅ {result}")

print("\n📝 TEST 2: Multiple accesses (all logged, none blocked)")
for i in range(3):
    result = get_user_data(f"user-{i}")
    print(f"✅ Access {i+1}: {result}")

print("\n" + "=" * 80)
print("✅ Monitoring works - all actions logged, none blocked!")

