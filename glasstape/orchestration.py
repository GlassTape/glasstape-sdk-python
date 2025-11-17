"""
GlassTape Multi-Agent Orchestration with Governance Integration
==============================================================

This module provides multi-agent orchestration patterns with built-in governance integration.
It is NOT a replacement for agent frameworks like Strands, LangChain, or LangGraph.

WHY THIS MODULE EXISTS:
======================

The core challenge in multi-agent governance is AGENT IDENTITY BINDING:

1. **Problem**: When multiple agents work together, tool calls need to be attributed to the correct agent
2. **Challenge**: External frameworks (Strands, LangChain) don't have built-in governance integration
3. **Solution**: This module provides agent-specific tool binding that ensures each tool call uses the correct agent's identity for governance

Example of the problem:
    from strands import Agent, Swarm
    from glasstape import configure, govern
    
    finance_sdk = configure(agent_key="org:finance:agent:v1")
    research_sdk = configure(agent_key="org:research:agent:v1")
    
    @govern("finance.payments.v1", sdk=finance_sdk)
    def process_payment(amount: float):
        return payment_service.charge(amount)
    
    @govern("research.data.v1", sdk=research_sdk)  
    def research_tool(query: str):
        return web_search(query)
    
    # PROBLEM: Which agent's identity is used for tool calls?
    finance_agent = Agent(tools=[process_payment])  # No governance binding
    research_agent = Agent(tools=[research_tool])   # No governance binding
    swarm = Swarm([finance_agent, research_agent])  # Identity confusion!

HOW THIS DIFFERS FROM EXTERNAL FRAMEWORKS:
==========================================

External Frameworks (Strands, LangChain, LangGraph):
- Focus on agent orchestration patterns (swarms, graphs, workflows)
- Provide LLM integration and tool calling
- Handle conversation management and memory
- Do NOT have built-in governance integration

GlassTape Orchestration Module:
- Provides governance-integrated agent patterns
- Ensures each tool call uses the correct agent's identity
- Maintains audit trails and policy enforcement
- Works WITH external frameworks, not instead of them

INTEGRATION PATTERN:
===================

Use GlassTape orchestration for governance, external frameworks for advanced patterns:

    # GlassTape for governance-integrated agents
    from glasstape import Agent, Swarm, govern
    
    # External frameworks for advanced orchestration
    from strands import create_react_agent
    from langgraph import create_workflow
    
    # GlassTape agents with governance
    finance_agent = Agent("finance", tools=[governed_tools], sdk=finance_sdk)
    research_agent = Agent("research", tools=[governed_tools], sdk=research_sdk)
    
    # Use external frameworks for complex orchestration
    team = Swarm([finance_agent, research_agent])
    result = await team("Complex multi-agent task")
"""

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List, Callable, Union
from datetime import datetime, timezone
from functools import wraps

from .agent_identity import set_agent_context, get_agent_context, clear_agent_context
from .errors import ConfigurationError, AuthenticationError

logger = logging.getLogger(__name__)

@dataclass
class AgentMessage:
    """Message between agents with governance context"""
    sender: str
    recipient: str
    content: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    agent_id: Optional[str] = None  # Governance tracking

class GovernedAgent:
    """
    GlassTape GovernedAgent with built-in governance integration.
    
    This is NOT a replacement for Strands/LangChain agents. It provides:
    - Agent-specific tool binding for governance
    - Identity management for audit trails
    - Simple orchestration patterns
    
    For complex agent patterns, use external frameworks with GlassTape governance.
    
    Key Distinction:
    - Strands Agent: Focuses on LLM integration and tool calling
    - GlassTape GovernedAgent: Focuses on governance and identity binding
    """
    
    def __init__(self, name: str, tools: List[Callable] = None, sdk=None, system_prompt: str = None):
        """
        Initialize agent with governance integration.
        
        Args:
            name: Agent identifier
            tools: List of governed tools (must have @govern decorators)
            sdk: GlassTape SDK instance for this agent's identity
            system_prompt: Optional system prompt for LLM integration
        """
        self.name = name
        self.system_prompt = system_prompt
        self.sdk = sdk
        self.tools = tools or []
        
        # Validate that tools are properly governed
        self._validate_governed_tools()
        
        logger.debug(f"Created agent '{name}' with {len(self.tools)} governed tools")
    
    def _validate_governed_tools(self):
        """Validate that all tools have proper governance decorators"""
        for tool in self.tools:
            if not hasattr(tool, '__wrapped__'):
                logger.warning(f"Tool '{tool.__name__}' may not have governance decorators")
    
    async def __call__(self, message: str, **kwargs) -> str:
        """
        Execute agent with proper identity binding.
        
        This method:
        1. Sets the agent's identity context
        2. Executes tools with correct governance
        3. Clears context to prevent contamination
        """
        if not self.sdk:
            raise ConfigurationError(f"Agent '{self.name}' requires SDK for governance")
        
        # Set this agent's identity context
        set_agent_context(self.sdk.config)
        
        try:
            # Execute with agent identity bound
            result = await self._execute_with_identity(message, **kwargs)
            return result
        finally:
            # Clear context to prevent cross-agent contamination
            clear_agent_context()
    
    async def _execute_with_identity(self, message: str, **kwargs) -> str:
        """Execute agent logic with proper identity context"""
        # Simple execution - in practice, this would integrate with LLM
        # For now, just demonstrate governance integration
        
        context = get_agent_context()
        logger.info(f"Agent '{self.name}' (ID: {context.agent_id}) executing: {message}")
        
        # Simulate tool execution with governance
        results = []
        for tool in self.tools:
            try:
                # Tools will use the correct agent identity via decorators
                if asyncio.iscoroutinefunction(tool):
                    result = await tool(message)
                else:
                    result = tool(message)
                results.append(f"Tool {tool.__name__}: {result}")
            except Exception as e:
                logger.error(f"Tool {tool.__name__} failed: {e}")
                results.append(f"Tool {tool.__name__}: Error - {e}")
        
        return f"Agent {self.name} completed task. Results: {'; '.join(results)}"

class GovernedSwarm:
    """
    Collaborative governed agent team with identity separation.
    
    Each agent maintains its own identity and governance context.
    This ensures proper audit trails and policy enforcement.
    """
    
    def __init__(self, agents: List[GovernedAgent]):
        """
        Initialize swarm with governed agents.
        
        Args:
            agents: List of Agent instances with proper SDK binding
        """
        self.agents = agents
        self._validate_agents()
        
        logger.debug(f"Created swarm with {len(self.agents)} agents")
    
    def _validate_agents(self):
        """Validate that all agents have proper SDK binding"""
        for agent in self.agents:
            if not agent.sdk:
                raise ConfigurationError(f"GovernedAgent '{agent.name}' requires SDK for governance")
    
    async def __call__(self, task: str, **kwargs) -> str:
        """
        Execute task with all agents, maintaining proper identity separation.
        
        Each agent executes with its own identity context to ensure
        proper governance and audit trails.
        """
        logger.info(f"Swarm executing task: {task}")
        
        results = []
        for agent in self.agents:
            try:
                # Each agent executes with its own identity
                result = await agent(task, **kwargs)
                results.append(f"{agent.name}: {result}")
            except Exception as e:
                logger.error(f"Agent {agent.name} failed: {e}")
                results.append(f"{agent.name}: Error - {e}")
        
        return f"Swarm completed task. Results: {' | '.join(results)}"

class GovernedGraphBuilder:
    """
    Simple workflow builder for sequential governed agent execution.
    
    This provides basic workflow patterns. For complex workflows,
    use external frameworks like LangGraph with GlassTape governance.
    """
    
    def __init__(self):
        self.nodes = {}
        self.edges = []
        self.entry_point = None
    
    def add_node(self, agent: GovernedAgent, node_id: str):
        """Add governed agent as workflow node"""
        if not agent.sdk:
            raise ConfigurationError(f"GovernedAgent '{agent.name}' requires SDK for governance")
        
        self.nodes[node_id] = agent
        logger.debug(f"Added node '{node_id}' with agent '{agent.name}'")
    
    def add_edge(self, from_node: str, to_node: str, condition: Callable = None):
        """Add conditional edge between nodes"""
        if from_node not in self.nodes or to_node not in self.nodes:
            raise ConfigurationError(f"Invalid edge: {from_node} -> {to_node}")
        
        self.edges.append({
            'from': from_node,
            'to': to_node,
            'condition': condition
        })
        logger.debug(f"Added edge: {from_node} -> {to_node}")
    
    def set_entry_point(self, node_id: str):
        """Set workflow entry point"""
        if node_id not in self.nodes:
            raise ConfigurationError(f"Entry point '{node_id}' not found")
        
        self.entry_point = node_id
        logger.debug(f"Set entry point: {node_id}")
    
    def build(self) -> 'GovernedGraph':
        """Build executable workflow graph"""
        if not self.entry_point:
            raise ConfigurationError("No entry point set")
        
        return GovernedGraph(self.nodes, self.edges, self.entry_point)

class GovernedGraph:
    """Executable workflow graph with governance integration"""
    
    def __init__(self, nodes: Dict[str, GovernedAgent], edges: List[Dict], entry_point: str):
        self.nodes = nodes
        self.edges = edges
        self.entry_point = entry_point
    
    async def __call__(self, input_data: str, **kwargs) -> str:
        """Execute workflow with proper agent identity management"""
        logger.info(f"Executing workflow with input: {input_data}")
        
        current_node = self.entry_point
        results = []
        
        while current_node:
            agent = self.nodes[current_node]
            logger.debug(f"Executing node: {current_node}")
            
            try:
                # Execute agent with proper identity
                result = await agent(input_data, **kwargs)
                results.append(f"{current_node}: {result}")
                
                # Find next node based on edges
                next_node = self._get_next_node(current_node, result)
                current_node = next_node
                
            except Exception as e:
                logger.error(f"Node {current_node} failed: {e}")
                results.append(f"{current_node}: Error - {e}")
                break
        
        return f"Workflow completed. Results: {' | '.join(results)}"
    
    def _get_next_node(self, current_node: str, result: str) -> Optional[str]:
        """Determine next node based on edges and conditions"""
        for edge in self.edges:
            if edge['from'] == current_node:
                if edge['condition'] is None or edge['condition'](result):
                    return edge['to']
        return None

# Convenience functions for common patterns

def create_agent_tool(agent: GovernedAgent, tool_name: str) -> Callable:
    """
    Convert agent into a tool for hierarchical delegation.
    
    This enables the Agents-as-Tools pattern where one agent
    can call another agent as a tool.
    """
    @wraps(agent.__call__)
    async def agent_tool(*args, **kwargs) -> str:
        return await agent(*args, **kwargs)
    
    agent_tool.__name__ = tool_name
    agent_tool.__doc__ = f"Agent tool: {agent.name}"
    
    return agent_tool

def handoff_to_user(message: str) -> str:
    """
    Human-in-the-loop handoff tool.
    
    This allows agents to explicitly transfer control to humans
    when they encounter tasks outside their expertise.
    """
    return f"HANDOFF_TO_USER: {message}"

def create_swarm(agents: List[GovernedAgent]) -> GovernedSwarm:
    """Create governed swarm from list of agents"""
    return GovernedSwarm(agents)

def create_graph_builder() -> GovernedGraphBuilder:
    """Create new governed workflow graph builder"""
    return GovernedGraphBuilder()

# Export main classes
__all__ = [
    'GovernedAgent',
    'GovernedSwarm', 
    'GovernedGraphBuilder',
    'GovernedGraph',
    'AgentMessage',
    'create_agent_tool',
    'handoff_to_user',
    'create_swarm',
    'create_graph_builder'
]
