#!/usr/bin/env python3
"""
GlassTape + LangChain Integration Example
========================================

This example shows how to integrate GlassTape governance
with LangChain agents and tools.
"""

from glasstape import configure, govern, set_context, GovernanceError

# Mock LangChain imports (replace with actual imports)
class MockTool:
    """Mock LangChain tool decorator"""
    def __init__(self, func):
        self.func = func
        self.name = func.__name__
        self.description = func.__doc__ or ""
    
    def __call__(self, *args, **kwargs):
        return self.func(*args, **kwargs)

def tool(func):
    """Mock LangChain @tool decorator"""
    return MockTool(func)


# Configure GlassTape once at module level
configure(
    agent_id="langchain-agent",
    policy_dir="./policies",
    debug=True
)

# Define governed LangChain tools at module level
@tool
@govern("finance.payments.v1")
def process_payment(amount: float, recipient: str) -> str:
    """Process a payment through the payment system"""
    return f"Payment of ${amount} sent to {recipient}"

@tool
@govern("data.customer_lookup.v1")
def lookup_customer(customer_id: str) -> str:
    """Look up customer information by ID"""
    return f"Customer {customer_id}: John Doe, Premium Account"

@tool
@govern("external.api_call.v1")
def call_external_api(endpoint: str, data: dict) -> str:
    """Make an external API call"""
    return f"API call to {endpoint} with data: {data}"


def main():
    """LangChain integration demonstration"""

    print("🔗 GlassTape + LangChain Integration Demo")
    print("=" * 50)

    # Simulate different user contexts (tools already configured above)
    contexts = [
        {
            "user_id": "agent-operator",
            "user_role": "operator", 
            "clearance_level": "standard"
        },
        {
            "user_id": "senior-analyst",
            "user_role": "analyst",
            "clearance_level": "elevated"
        },
        {
            "user_id": "system-admin",
            "user_role": "admin",
            "clearance_level": "full"
        }
    ]
    
    tools = [process_payment, lookup_customer, call_external_api]
    
    for context in contexts:
        print(f"\n👤 Testing as {context['user_role']}: {context['user_id']}")
        set_context(**context)
        
        # Test payment tool
        try:
            result = process_payment(150.0, "supplier-xyz")
            print(f"   💰 Payment: ✅ {result}")
        except GovernanceError as e:
            print(f"   💰 Payment: ❌ {e}")
        
        # Test customer lookup
        try:
            result = lookup_customer("cust-12345")
            print(f"   👥 Lookup: ✅ {result}")
        except GovernanceError as e:
            print(f"   👥 Lookup: ❌ {e}")
        
        # Test external API
        try:
            result = call_external_api("https://api.example.com/data", {"query": "test"})
            print(f"   🌐 API: ✅ {result}")
        except GovernanceError as e:
            print(f"   🌐 API: ❌ {e}")
    
    # Demonstrate tool introspection
    print(f"\n🔍 Tool Introspection:")
    for tool_obj in tools:
        print(f"   - {tool_obj.name}: {tool_obj.description}")


class MockLangChainAgent:
    """Mock LangChain agent for demonstration"""
    
    def __init__(self, tools, user_context):
        self.tools = {tool.name: tool for tool in tools}
        self.user_context = user_context
    
    def run(self, query: str) -> str:
        """Simulate agent execution with governance"""
        set_context(**self.user_context)
        
        print(f"\n🤖 Agent Query: '{query}'")
        
        # Simulate agent deciding to use tools based on query
        if "payment" in query.lower():
            try:
                return self.tools["process_payment"](100.0, "vendor-abc")
            except GovernanceError as e:
                return f"Cannot process payment: {e}"
        
        elif "customer" in query.lower():
            try:
                return self.tools["lookup_customer"]("cust-67890")
            except GovernanceError as e:
                return f"Cannot lookup customer: {e}"
        
        else:
            return "I don't understand that request."


def demo_agent_workflow():
    """Demonstrate full agent workflow with governance"""
    
    print("\n" + "=" * 50)
    print("🤖 Agent Workflow Demo")
    print("=" * 50)
    
    tools = [process_payment, lookup_customer, call_external_api]
    
    # Create agents with different permissions
    operator_agent = MockLangChainAgent(tools, {
        "user_id": "operator-001",
        "user_role": "operator",
        "department": "customer_service"
    })
    
    admin_agent = MockLangChainAgent(tools, {
        "user_id": "admin-001", 
        "user_role": "admin",
        "department": "finance"
    })
    
    queries = [
        "Process a payment of $100",
        "Look up customer information",
        "Make an external API call"
    ]
    
    for agent_name, agent in [("Operator", operator_agent), ("Admin", admin_agent)]:
        print(f"\n👤 {agent_name} Agent:")
        for query in queries:
            result = agent.run(query)
            print(f"   Query: {query}")
            print(f"   Result: {result}")


if __name__ == "__main__":
    main()
    demo_agent_workflow()