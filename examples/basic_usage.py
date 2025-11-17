#!/usr/bin/env python3
"""
GlassTape Basic Usage Example
============================

This example demonstrates the core functionality of GlassTape SDK
for AI agent governance.
"""

from glasstape import configure, govern, monitor, set_context, GovernanceError


def main():
    """Basic usage demonstration"""
    
    # 1. Configure GlassTape (optional - has sensible defaults)
    configure(
        agent_id="demo-agent",
        policy_dir="./policies",
        debug=True  # Enable debug output
    )
    
    # 2. Define governed functions
    @govern("finance.payments.v1")
    def process_payment(amount: float, recipient: str):
        """Process a payment - governed by policy"""
        return f"Payment of ${amount} to {recipient} processed successfully"
    
    @monitor("analytics.data_access.v1") 
    def get_user_data(user_id: str):
        """Get user data - monitored but not blocked"""
        return f"User data for {user_id}: [name, email, preferences]"
    
    # 3. Set request context (important for policy decisions)
    set_context(
        user_id="analyst-123",
        user_role="analyst",
        session_id="sess-456"
    )
    
    print("🚀 GlassTape Basic Usage Demo")
    print("=" * 50)
    
    # 4. Test allowed operations
    try:
        print("\n✅ Testing allowed payment (small amount):")
        result = process_payment(25.0, "vendor-abc")
        print(f"   Result: {result}")
    except GovernanceError as e:
        print(f"   ❌ Blocked: {e}")
    
    # 5. Test blocked operations  
    try:
        print("\n❌ Testing blocked payment (large amount):")
        result = process_payment(5000.0, "vendor-xyz")
        print(f"   Result: {result}")
    except GovernanceError as e:
        print(f"   🛡️  Blocked: {e}")
    
    # 6. Test monitoring (never blocks)
    print("\n📊 Testing monitoring (never blocks):")
    result = get_user_data("user-789")
    print(f"   Result: {result}")
    
    # 7. Test with different user role
    print("\n👑 Testing with admin role:")
    set_context(
        user_id="admin-456", 
        user_role="admin",
        session_id="sess-789"
    )
    
    try:
        result = process_payment(5000.0, "vendor-xyz")
        print(f"   ✅ Admin allowed: {result}")
    except GovernanceError as e:
        print(f"   ❌ Even admin blocked: {e}")


if __name__ == "__main__":
    main()