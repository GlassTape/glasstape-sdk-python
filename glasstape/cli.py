"""
GlassTape CLI - Command Line Interface
=======================================

Simple CLI for common GlassTape operations.
"""

import sys
import argparse
import json
from pathlib import Path
from typing import Optional

from .config import GlassTapeConfig
from .__init__ import __version__


def main() -> int:
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        prog="glasstape",
        description="GlassTape SDK - Zero-trust runtime governance for AI agents",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version=f"glasstape {__version__}",
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Init command
    init_parser = subparsers.add_parser(
        "init",
        help="Initialize a new GlassTape project"
    )
    init_parser.add_argument(
        "--policy-dir",
        default="./policies",
        help="Directory to create for policies (default: ./policies)"
    )
    
    # Validate command
    validate_parser = subparsers.add_parser(
        "validate",
        help="Validate policy files"
    )
    validate_parser.add_argument(
        "policy_dir",
        nargs="?",
        default="./policies",
        help="Directory containing policy files (default: ./policies)"
    )
    
    # Info command
    info_parser = subparsers.add_parser(
        "info",
        help="Show GlassTape configuration and system info"
    )
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 0
    
    if args.command == "init":
        return cmd_init(args.policy_dir)
    elif args.command == "validate":
        return cmd_validate(args.policy_dir)
    elif args.command == "info":
        return cmd_info()
    
    return 0


def cmd_init(policy_dir: str) -> int:
    """Initialize a new GlassTape project"""
    print(f"🚀 Initializing GlassTape project...")
    
    # Create policy directory
    policy_path = Path(policy_dir)
    policy_path.mkdir(parents=True, exist_ok=True)
    print(f"✓ Created policy directory: {policy_dir}")
    
    # Create example policy
    example_policy = {
        "policy_id": "example.policy.v1",
        "version": "1.0",
        "description": "Example policy - customize for your needs",
        "extraction_bindings": {
            "bindings": [
                {
                    "source_path": "amount",
                    "target_path": "resource.attr.amount"
                }
            ]
        },
        "icp_schema": {
            "resource": {
                "kind": "example",
                "attr": {
                    "amount": {
                        "type": "number",
                        "description": "Amount parameter"
                    }
                }
            }
        },
        "rules": {
            "deny": [],
            "allow": [
                {
                    "id": "allow-all",
                    "condition": "",
                    "reason": "Allow all by default"
                }
            ]
        }
    }
    
    example_path = policy_path / "example.policy.v1.json"
    with open(example_path, 'w') as f:
        json.dump(example_policy, f, indent=2)
    print(f"✓ Created example policy: {example_path}")
    
    # Create .env example
    env_example = """# GlassTape Configuration
# Agent Identity
GT_AGENT_ID=my-agent
GT_ORG_ID=my-org

# Policy Directory
GT_POLICY_DIR=./policies

# Logging
GT_LOG_FILE=./glasstape.log

# Debug Mode
GT_DEBUG=false

# Optional: LLM Integration
# GT_LLM_PROVIDER=openai
# GT_LLM_MODEL=gpt-4o-mini
# OPENAI_API_KEY=your-key-here

# Optional: Cryptography
# GT_ED25519_PRIVATE_KEY=your-private-key
# GT_KEYS_DIR=~/.glasstape/keys
"""
    
    env_path = Path(".env.example")
    with open(env_path, 'w') as f:
        f.write(env_example)
    print(f"✓ Created environment example: {env_path}")
    
    print("\n✅ GlassTape project initialized!")
    print(f"\nNext steps:")
    print(f"  1. Edit policies in {policy_dir}/")
    print(f"  2. Copy .env.example to .env and configure")
    print(f"  3. Add @govern decorators to your agent tools")
    print(f"\nDocs: https://docs.glasstape.dev")
    
    return 0


def cmd_validate(policy_dir: str) -> int:
    """Validate policy files"""
    print(f"🔍 Validating policies in {policy_dir}...")
    
    policy_path = Path(policy_dir)
    if not policy_path.exists():
        print(f"❌ Error: Policy directory not found: {policy_dir}")
        return 1
    
    # Find all policy files
    policy_files = list(policy_path.glob("*.json")) + list(policy_path.glob("*.yaml")) + list(policy_path.glob("*.yml"))
    
    if not policy_files:
        print(f"⚠️  Warning: No policy files found in {policy_dir}")
        return 1
    
    print(f"Found {len(policy_files)} policy file(s)")
    
    errors = 0
    for policy_file in policy_files:
        try:
            if policy_file.suffix == ".json":
                with open(policy_file, 'r') as f:
                    policy = json.load(f)
            else:
                import yaml
                with open(policy_file, 'r') as f:
                    policy = yaml.safe_load(f)
            
            # Basic validation
            required_fields = ["policy_id", "version"]
            missing = [field for field in required_fields if field not in policy]
            
            if missing:
                print(f"❌ {policy_file.name}: Missing required fields: {', '.join(missing)}")
                errors += 1
            else:
                print(f"✓ {policy_file.name}: Valid")
                
        except Exception as e:
            print(f"❌ {policy_file.name}: Parse error: {e}")
            errors += 1
    
    if errors == 0:
        print(f"\n✅ All {len(policy_files)} policy files are valid!")
        return 0
    else:
        print(f"\n❌ Found {errors} error(s) in policy files")
        return 1


def cmd_info() -> int:
    """Show GlassTape configuration and system info"""
    print(f"GlassTape SDK v{__version__}")
    print("=" * 50)
    
    # Try to load config
    try:
        config = GlassTapeConfig.from_env()
        
        print(f"\nConfiguration:")
        print(f"  Agent ID:       {config.agent_id}")
        print(f"  Org ID:         {config.org_id}")
        print(f"  Mode:           {config.mode}")
        print(f"  Policy Dir:     {config.policy_dir}")
        print(f"  Log File:       {config.log_file}")
        print(f"  Debug:          {config.debug}")
        
        # Check optional features
        print(f"\nOptional Features:")
        print(f"  LLM Extraction: {'✓' if config.use_llm_extraction else '✗'}")
        if config.use_llm_extraction:
            print(f"    Provider:     {config.llm_provider}")
            print(f"    Model:        {config.llm_model or 'default'}")
        
        # Check for CEL evaluation
        print(f"  Cerbos CEL:     ", end="")
        try:
            from .cerbos_evaluator import CerbosEvaluator
            evaluator = CerbosEvaluator()
            if evaluator.is_available():
                print("✓ Available (built-in)")
            else:
                print("✗ Not available")
        except Exception as e:
            print(f"✗ Error: {e}")
        
        # Count policies
        policy_path = Path(config.policy_dir)
        if policy_path.exists():
            policy_count = len(list(policy_path.glob("*.json")) + list(policy_path.glob("*.yaml")) + list(policy_path.glob("*.yml")))
            print(f"\nPolicies:")
            print(f"  Directory:      {config.policy_dir}")
            print(f"  Policy Files:   {policy_count}")
        else:
            print(f"\nPolicies:")
            print(f"  Directory:      {config.policy_dir} (not found)")
        
    except Exception as e:
        print(f"\n❌ Error loading configuration: {e}")
        return 1
    
    print(f"\nDocumentation: https://docs.glasstape.dev")
    print(f"GitHub:        https://github.com/glasstape/glasstape-sdk-python")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())

