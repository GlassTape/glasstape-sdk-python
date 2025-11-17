# GlassTape Policy Files

This directory contains example policy files for GlassTape SDK. This is the canonical location for policies - examples and documentation reference `./policies/`.

## Policy File Format

Policy files can be in JSON or YAML format. Each policy defines:

1. **Policy Metadata**: ID, version, and description
2. **Extraction Bindings**: How to map tool arguments to policy attributes
3. **ICP Schema**: Structure of the policy request
4. **Rules**: Allow and deny rules with conditions

## Example Policies

### finance.payments.v1.json
Payment processing policy with role-based limits:
- Analysts: up to $50
- Admins: unlimited

### analytics.data_access.v1.json
Monitoring policy for data access (always allows, just logs)

## Creating Your Own Policies

You can create policies manually or use the [GlassTape Policy Builder MCP](https://github.com/GlassTape/agent-policy-builder-mcp) to generate them from natural language.

### Manual Policy Example

```json
{
  "policy_id": "my-custom-policy.v1",
  "version": "1.0",
  "description": "My custom policy description",
  "extraction_bindings": {
    "bindings": [
      {
        "source_path": "parameter_name",
        "target_path": "resource.attr.parameter_name"
      }
    ]
  },
  "rules": {
    "deny": [
      {
        "id": "deny-rule-1",
        "condition": "parameter_name > 100",
        "reason": "Value exceeds limit"
      }
    ],
    "allow": [
      {
        "id": "allow-rule-1",
        "condition": "parameter_name <= 100",
        "reason": "Value within limit"
      }
    ]
  }
}
```

## Policy Location

All examples and documentation reference policies in this directory:
- Examples: `policy_dir="./policies"`
- Tests: `policy_dir="./test_policies"`
- Production: Configure your own path

## Using Cerbos Policies

You can also use Cerbos YAML policies. Add a `cerbos_policy_yaml` field to your policy file:

```json
{
  "policy_id": "my-policy.v1",
  "cerbos_policy_yaml": "apiVersion: api.cerbos.dev/v1\nresourcePolicy:\n  version: \"1.0\"\n  ..."
}
```

For Cerbos policy syntax, see: https://docs.cerbos.dev/

