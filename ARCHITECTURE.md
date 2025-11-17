# GlassTape SDK Architecture

This document explains the technical architecture of GlassTape SDK v1.0.

## Design Philosophy

GlassTape follows these core principles:

1. **Fail-Closed Security**: Default deny on errors or missing policies
2. **Separation of Concerns**: Governance logic separate from application code
3. **Mode Extensibility**: Easy to add new modes (local, platform, web3)
4. **Framework Agnostic**: Works with any AI agent framework
5. **Zero Dependencies**: Local mode works completely offline

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     Application Layer                       │
│  (LangChain, LangGraph, Custom Agents, AWS Strands)         │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│              GlassTape Decorator Layer                      │
│                @govern, @monitor                            │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                   Core Engine                               │
│  ┌─────────────┬──────────────┬──────────────────────────┐  │
│  │   Config    │   Context    │      Router              │  │
│  │  Manager    │   Manager    │   (Mode Dispatch)        │  │
│  └─────────────┴──────────────┴──────────────────────────┘  │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                  Local Engine                               │
│  ┌─────────────┬──────────────┬──────────────────────────┐  │
│  │  Policy     │  Parameter   │  CEL Evaluator           │  │
│  │  Engine     │  Extraction  │  (Built-in)              │  │
│  └─────────────┴──────────────┴──────────────────────────┘  │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│              Security & Audit Layer                         │
│  ┌─────────────┬──────────────┬──────────────────────────┐  │
│  │   Agent     │  Crypto      │   Orchestration          │  │
│  │  Identity   │  Operations  │   & Workflows            │  │
│  └─────────────┴──────────────┴──────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. Decorators (`decorators.py`)

**Purpose**: User-facing API for governance

**Key Functions**:
- `@govern(policy_id)`: Blocking governance with policy enforcement
- `@monitor(policy_id)`: Non-blocking monitoring (logs but doesn't block)

**Features**:
- Async/sync function support
- Automatic positional → keyword argument conversion
- Context injection
- Debug mode support

### 2. Config (`config.py`)

**Purpose**: Configuration management with sensible defaults

**Key Features**:
- Environment variable support (`GT_*` prefix)
- Validation of mode-specific requirements
- Auto-directory creation for local mode
- Smart LLM detection

**Default Values**:
```python
agent_id = "default-agent"
mode = "local"
policy_dir = "./policies"
log_file = "./glasstape.log"
debug = False
```

### 3. Context (`context.py`)

**Purpose**: Thread-safe request context injection

**Key Features**:
- `contextvars` for async-safe storage
- `set_context()`: Set request-scoped context
- `request_context()`: Context manager for automatic cleanup
- `get_context()`: Retrieve current context

**Usage**:
```python
set_context(
    user_id="user123",
    user_role="analyst",
    session_id="sess456"
)
```

### 4. Mode Router (`router.py`)

**Purpose**: Dispatch to appropriate mode engine

**Design Pattern**: Factory pattern

**Current Modes**:
- `local`: File-based policies (v1.0) ✅

### 5. Local Engine (`modes/local.py`)

**Purpose**: Self-contained local governance engine

**Key Responsibilities**:
1. **Policy Loading**: Load policies from local files (JSON/YAML)
2. **Parameter Extraction**: Extract parameters using extraction bindings
3. **Policy Evaluation**: Evaluate using built-in CEL expressions (Cerbos-compatible)
4. **Decision Logging**: Log decisions to local audit file

**Features**:
- Policy caching for performance
- Multiple file format support (JSON, YAML)
- Fallback evaluation when Cerbos unavailable
- Cryptographic audit trails

### 6. Policy Engine (`policy_engine.py`)

**Purpose**: ICP extraction and policy evaluation

**Key Components**:

**ICPExtractor**:
- Converts tool arguments → ICP (Intermediate Canonical Policy) format
- Applies extraction bindings
- Supports transforms (to_number, currency_normalize)
- Optional LLM extraction for natural language

**PolicyBundle**:
- Verifies policy integrity (Ed25519 signatures)
- Evaluates policies using CEL expressions
- Cerbos-compatible policy format
- Generates cryptographic decision receipts

### 7. Cerbos Evaluator (`cerbos_evaluator.py`)

**Purpose**: Built-in CEL-compatible policy evaluation

**Features**:
- **No external dependencies** - fully self-contained
- CEL expression evaluation (AND, OR, comparisons)
- Principal attribute checks (user_role, etc.)
- Arithmetic operations in conditions
- Sub-5ms evaluation time
- Cerbos policy format compatible

## Data Flow

### Request Flow

```
1. Tool Call
   process_payment(100.0, "vendor")
   
2. Decorator Interception
   @govern("finance.payments.v1")
   - Convert args to kwargs
   - Get current context
   
3. Mode Router
   - Select engine (local/platform/web3)
   
4. Policy Loading
   - Load policy from file/API/blockchain
   - Verify integrity
   - Cache for performance
   
5. Parameter Extraction
   - Apply extraction bindings
   - Map tool args → ICP format
   - Include runtime context
   
6. Policy Evaluation
   - Evaluate using CEL expressions
   - Fallback to legacy rules
   - Return decision + reason
   
7. Decision Enforcement
   - If allow: execute tool
   - If deny: raise GovernanceError
   
8. Audit Logging
   - Log decision to audit file
   - Include cryptographic signature
```

### ICP (Intermediate Canonical Policy) Format

ICP is a Cerbos-compatible format that simplifies the evaluation pipeline:

```json
{
  "version": "1.0.0",
  "input": {
    "principal": {
      "id": "analyst-123",
      "roles": ["agent"],
      "attr": {
        "user_role": "analyst"
      }
    },
    "resource": {
      "kind": "payment",
      "id": "resource-123",
      "attr": {
        "amount": 100.0,
        "recipient": "vendor-x"
      }
    },
    "actions": ["execute"],
    "environment": {
      "region": "us",
      "time": "2025-11-17T...",
      "agent_id": "finance-agent",
      "org_id": "acme-corp"
    }
  }
}
```

## Security Model

### Multi-Agent Identity

Each agent has a unique Ed25519 keypair for:
- Signing decision receipts
- Non-repudiation in audit trails
- Agent traceability

### Fail-Closed Design

All error conditions result in denial:
- Policy not found → DENY
- Extraction failure → DENY
- Evaluation error → DENY
- Signature verification failure → DENY

### Decision Receipts

Every decision generates a cryptographic receipt:

```json
{
  "agent_id": "finance-agent",
  "bundle_id": "finance.payments.v1",
  "bundle_hash": "sha256:...",
  "dis_hash": "sha256:...",
  "decision": "Deny",
  "reason": "Amount exceeds limit",
  "ts": "2025-11-17T10:30:00Z",
  "signature": "ed25519:..."
}
```

## Performance

### Caching Strategy

- **Policy Bundles**: Cached in memory after first load
- **Cache Invalidation**: Manual or TTL-based (configurable)
- **Cache Key**: Policy ID

### Evaluation Performance

- **CEL Evaluation**: Sub-5ms evaluation
- **Parameter Extraction**: ~1ms
- **Policy Loading (cached)**: ~0.1ms
- **Total Overhead**: < 10ms per tool call (structured parameters)
- **With LLM Extraction**: ~300ms (Anthropic API call dominates)

## Extension Points

### Adding a New Mode

1. Create new engine in `modes/`:
```python
class CustomEngine:
    async def enforce_policy(self, policy_id, tool_name, tool_args, context):
        # Implementation
        pass
```

2. Register in `router.py`:
```python
elif self.config.mode == "custom":
    from .modes.custom import CustomEngine
    return CustomEngine(self.config)
```

### Custom Transforms

Add new transforms in `ICPExtractor._apply_transform()`:

```python
elif transform_name == "my_transform":
    return my_transformation(value)
```

### Custom CEL Conditions

Extend `CerbosEvaluator._evaluate_simple_condition()` for new condition patterns:

```python
# Add support for new operators or field types
if "my_custom_field" in condition:
    return self._evaluate_custom_field(condition, request)
```

### Adding LLM Providers

Add new LLM provider in `LLMParameterExtractor._init_clients()`:

```python
elif self.config.llm_provider == "my_provider":
    self.my_provider_client = MyProvider(api_key=self.config.llm_api_key)
```

## Testing Strategy

### Unit Tests
- Config validation
- Context management
- Decorator behavior
- Mode routing

### Integration Tests
- End-to-end policy enforcement
- Multi-agent scenarios
- Framework integrations

### Performance Tests
- Evaluation latency
- Cache effectiveness
- Concurrent requests

## Extensibility

The architecture supports future modes and integrations through:
- Pluggable mode system
- Standardized policy interfaces
- Configurable audit backends
- Custom evaluation engines

## References

- **Cerbos Documentation**: https://docs.cerbos.dev/
- **CEL Specification**: https://github.com/google/cel-spec
- **Ed25519 Signatures**: https://ed25519.cr.yp.to/

