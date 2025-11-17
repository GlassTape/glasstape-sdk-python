# Security Policy

## Security Model

### Fail-Closed Design
- **Policy not found** → DENY
- **Extraction error** → DENY
- **Evaluation failure** → DENY
- **Signature verification failure** → DENY

### Cryptographic Signatures
- **Ed25519**: All decisions cryptographically signed
- **Per-Agent Keys**: Unique identity per agent
- **Non-Repudiation**: Legal admissibility for audit trails

### Key Management

**Critical**: Never commit keys to version control

```bash
# Environment variables (recommended)
export GT_ED25519_PRIVATE_KEY="your-key"

# Production: Use secure key management
# - AWS KMS, HashiCorp Vault, etc.
# - Regular key rotation
# - Environment separation
```

**Auto-generated keys**: Stored in `~/.glasstape/keys/` if not provided

### Local Mode Security
- **Offline**: No network calls, complete data privacy
- **File-based**: Policies and logs stored locally

**Secure deployment**:
```bash
# Restrict permissions
chmod 700 ./policies
chmod 600 ./glasstape.log

# Docker: read-only policies
docker run -v ./policies:/app/policies:ro ...
```

### Input Validation
- **Policy integrity**: Ed25519 signature verification
- **Tool arguments**: Schema validation
- **Parameter types**: Type checking
- **Required fields**: Missing fields → DENY

### Dependencies
**Core** (minimal):
- `pyyaml>=6.0`
- `cryptography>=41.0.0`

**Optional**:
- `openai>=1.0.0` (LLM extraction)
- `anthropic>=0.7.0` (LLM extraction)

## Threat Protection

### Prompt Injection
Policies enforce limits **after** LLM reasoning:
```python
@govern("spending.limit.v1")
def make_purchase(amount: float):
    # Even if LLM is tricked, policy blocks unauthorized amounts
    pass
```

### Parameter Tampering
- Policies evaluate actual function arguments
- Cannot bypass by modifying user input

### Policy Bypass
- Evaluated at function boundary
- Cannot disable decorators at runtime
- Cannot bypass by calling internal functions

## Best Practices

### Development
```python
# Enable debug mode
configure(debug=True)

# Test governance scenarios
def test_payment_limit():
    set_context(user_role="analyst")
    with pytest.raises(GovernanceError):
        process_payment(10000.0)
```

### Production
- **Disable debug**: `configure(debug=False)`
- **Monitor denials**: Track blocked requests
- **Regular audits**: Verify policy behavior
- **Backup**: Policies and keys

### Multi-Tenant
- **Isolate**: Separate agent identities per tenant
- **Segregate**: Separate policy directories and audit logs
- **Rate limit**: Prevent abuse

## Compliance

**HIPAA**: Audit logging, encrypted storage, key rotation  
**SOC 2**: Cryptographic receipts, role-based access, change management  
**GDPR**: Purpose limitation, data minimization, audit trails  
**EU AI Act**: Decision traceability, cryptographic integrity

## Updates & Contact

**Security Updates**: Watch repository for advisories  
**GitHub**: https://github.com/glasstape/glasstape-sdk-python

**Responsible disclosure appreciated** - contributors acknowledged in advisories.

