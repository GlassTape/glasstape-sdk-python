# GlassTape Quick Start Guide

Get started with GlassTape in under 5 minutes!

## Installation

```bash
pip install glasstape
```

That's it! No API keys, no signups, no network dependencies.

## Basic Usage

### Step 1: Create Project Structure

```bash
cd your-project
mkdir policies
```

This creates the `policies/` directory for your policy files.

### Step 2: Configure (Optional)

GlassTape works with zero configuration, but you can customize:

```python
from glasstape import configure

configure(
    agent_id="my-agent",          # Identify your agent
    policy_dir="./policies",      # Where policies are stored
    debug=True                    # Enable debug output
)
```

Or use environment variables:

```bash
export GT_AGENT_ID=my-agent
export GT_POLICY_DIR=./policies
export GT_DEBUG=true
```

### Step 3: Add Governance to Your Tools

```python
from glasstape import govern, set_context

# Add @govern decorator to any function
@govern("finance.payments.v1")
def process_payment(amount: float, recipient: str):
    """Process a payment - now governed by policy!"""
    return f"Payment of ${amount} to {recipient} processed"

# Set request context (who is making the request)
set_context(
    user_id="analyst-123",
    user_role="analyst"
)

# Use the function normally
try:
    result = process_payment(100.0, "vendor-x")
    print(f"✅ {result}")
except GovernanceError as e:
    print(f"❌ Blocked: {e}")
```

### Step 4: Create Your Policy

Create `policies/finance.payments.v1.json`:

```json
{
  "policy_id": "finance.payments.v1",
  "version": "1.0",
  "description": "Payment policy with role-based limits",
  "extraction_bindings": {
    "bindings": [
      {
        "path": "input.resource.attr.amount",
        "sources": [{"type": "arg", "name": "amount"}],
        "required": true
      },
      {
        "path": "input.principal.attr.user_role",
        "sources": [{"type": "context", "name": "user_role"}],
        "required": true
      }
    ]
  },
  "rules": {
    "deny": [
      {
        "id": "deny-large-analyst-payments",
        "condition": "amount > 1000 && user_role == 'analyst'",
        "reason": "Analysts limited to $1000"
      }
    ],
    "allow": [
      {
        "id": "allow-small-payments",
        "condition": "amount <= 1000",
        "reason": "Small payments allowed"
      },
      {
        "id": "allow-admin",
        "condition": "user_role == 'admin'",
        "reason": "Admins can process any amount"
      }
    ]
  }
}
```

## Testing

Run your tests:

```bash
pytest tests/
```

Test with debug mode:

```python
configure(debug=True)  # See policy evaluation details
```

## Integration with AI Frameworks

### LangChain

```python
from langchain.tools import tool
from glasstape import govern

@tool
@govern("my-policy.v1")
def my_tool(query: str) -> str:
    """A governed LangChain tool"""
    return process_query(query)
```

### LangGraph

```python
from langgraph.prebuilt import create_react_agent
from glasstape import configure, govern

configure(agent_id="my-agent")

@govern("weather.access.v1")
def get_weather(city: str) -> str:
    return f"Weather in {city}: Sunny"

agent = create_react_agent(
    model="anthropic:claude-3-5-sonnet-latest",
    tools=[get_weather]
)
```

### Custom Agents

```python
from glasstape import govern, set_context

# Set context for request
set_context(user_id="user123", user_role="analyst")
result = my_governed_function(args)
```

## What's Next?

- **📖 Full Documentation**: [README.md](README.md)
- **🎯 Use Cases**: See [README.md](README.md#-use-cases)
- **🏗️ Architecture**: [ARCHITECTURE.md](ARCHITECTURE.md)
- **🤝 Contributing**: [CONTRIBUTING.md](CONTRIBUTING.md)
- **🔧 Policy Builder**: [agent-policy-builder-mcp](https://github.com/GlassTape/agent-policy-builder-mcp)

## Common Issues

### Policy Not Found

```
Error: Policy file not found: my-policy.v1
```

**Solution**: Make sure your policy file exists in the `policy_dir` (default: `./policies/`)

### Parameters Not Extracted

```
Warning: Required field input.resource.attr.amount not found
```

**Solution**: Check that your extraction bindings match your function parameters:
- Binding `"name": "amount"` should match function parameter `amount`
- Use `"type": "arg"` for function arguments
- Use `"type": "context"` for runtime context (user_role, etc.)

### All Requests Denied

**Solution**: Check your policy rules:
- Make sure you have at least one `allow` rule
- Verify conditions use correct field names
- Enable debug mode: `configure(debug=True)`

## Support

- **GitHub Issues**: [glasstape-sdk-python/issues](https://github.com/glasstape/glasstape-sdk-python/issues)

