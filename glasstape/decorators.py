"""
GlassTape Decorators - Mode-Agnostic Governance
===============================================

Elegant decorators that work across local, platform, and web3 modes.
"""

import asyncio
import time
import os
import inspect
from functools import wraps
from typing import Callable, Dict, Any

from .errors import GovernanceError

def govern(policy_id: str, enforcement: str = "blocking", debug=False, **kwargs):
    """Governance decorator for tool boundary control"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def async_wrapper(*args, **func_kwargs):
            return await _execute_with_governance(
                func, args, func_kwargs, policy_id, enforcement, debug
            )
        
        @wraps(func)
        def sync_wrapper(*args, **func_kwargs):
            try:
                loop = asyncio.get_running_loop()
                import concurrent.futures
                
                def run_in_thread():
                    new_loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(new_loop)
                    try:
                        return new_loop.run_until_complete(async_wrapper(*args, **func_kwargs))
                    finally:
                        new_loop.close()
                
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future = executor.submit(run_in_thread)
                    return future.result()
            except RuntimeError:
                return asyncio.run(async_wrapper(*args, **func_kwargs))
        
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator

def monitor(policy_id: str, debug=False, **kwargs):
    """Monitoring decorator for observability without blocking execution"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def async_wrapper(*args, **func_kwargs):
            return await _execute_with_monitoring(
                func, args, func_kwargs, policy_id, debug
            )
        
        @wraps(func)
        def sync_wrapper(*args, **func_kwargs):
            try:
                loop = asyncio.get_running_loop()
                import concurrent.futures
                
                def run_in_thread():
                    new_loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(new_loop)
                    try:
                        return new_loop.run_until_complete(async_wrapper(*args, **func_kwargs))
                    finally:
                        new_loop.close()
                
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future = executor.submit(run_in_thread)
                    return future.result()
            except RuntimeError:
                return asyncio.run(async_wrapper(*args, **func_kwargs))
        
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator

async def _execute_with_governance(
    func: Callable,
    args: tuple,
    func_kwargs: Dict[str, Any],
    policy_id: str,
    enforcement: str,
    debug: bool
) -> Any:
    """Execute function with governance checks"""
    start_time = time.time()
    tool_name = func.__name__
    
    try:
        # Convert positional args to keyword args using function signature
        sig = inspect.signature(func)
        bound_args = sig.bind(*args, **func_kwargs)
        bound_args.apply_defaults()
        all_kwargs = dict(bound_args.arguments)
        
        # Use mode router for policy enforcement
        from .router import ModeRouter
        from .config import get_config
        
        config = get_config()
        router = ModeRouter(config)
        
        # Merge request context with built-in context
        from .context import get_context
        request_ctx = get_context()
        
        context = {
            "agent_id": config.agent_id,
            "org_id": config.org_id,
            "timestamp": time.time(),
            **request_ctx  # Include all runtime context
        }
        
        decision = await router.enforce_policy(
            policy_id=policy_id,
            tool_name=tool_name,
            tool_args=all_kwargs,
            context=context
        )
        
        # DEBUG: Show decision details
        if debug:
            print(f"\n🔍 GOVERN DEBUG - {tool_name}")
            print(f"   Policy ID: {policy_id}")
            print(f"   Decision: {decision.decision}")
            print(f"   Reason: {decision.reason}")
            print(f"   Mode: {config.mode}")
            print("=" * 60)
        
        if decision.decision == "deny":
            if enforcement == "blocking":
                raise GovernanceError(
                    decision.reason or "Tool execution denied by policy"
                )
        
        if asyncio.iscoroutinefunction(func):
            result = await func(*args, **func_kwargs)
        else:
            result = func(*args, **func_kwargs)
        
        return result
        
    except Exception as e:
        raise

async def _execute_with_monitoring(
    func: Callable,
    args: tuple,
    func_kwargs: Dict[str, Any],
    policy_id: str,
    debug: bool
) -> Any:
    """Execute function with monitoring only (non-blocking)"""
    tool_name = func.__name__
    
    try:
        if asyncio.iscoroutinefunction(func):
            result = await func(*args, **func_kwargs)
        else:
            result = func(*args, **func_kwargs)
        
        # Background monitoring
        async def background_monitor():
            try:
                from .router import ModeRouter
                from .config import get_config
                
                config = get_config()
                router = ModeRouter(config)
                
                context = {
                    "agent_id": config.agent_id,
                    "org_id": config.org_id,
                    "timestamp": time.time()
                }
                
                decision = await router.enforce_policy(
                    policy_id=policy_id,
                    tool_name=tool_name,
                    tool_args=func_kwargs,
                    context=context
                )
                
                if debug:
                    print(f"\n📊 MONITOR DEBUG - {tool_name}")
                    print(f"   Policy ID: {policy_id}")
                    print(f"   Decision: {decision.decision}")
                    print(f"   ⚠️  Non-blocking monitoring only")
                    print("=" * 60)
                    
            except Exception as e:
                if debug:
                    print(f"Warning: Monitoring failed for {tool_name}: {e}")
        
        asyncio.create_task(background_monitor())
        return result
        
    except Exception as e:
        raise