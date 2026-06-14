"""
MCP Semantic Taint Tracker MVP
==============================

Demonstrates that session-aware provenance tracking can detect
compositional attacks that stateless inspection cannot.
"""

from .schema import Event, Node, Edge, FlowDetection, PolicyViolation, Alert, Severity
from .mcp_interception_layer import MCPInterceptor
from .taint_engine import TaintSourceEngine
from .flow_attribution import FlowAttributionEngine
from .policy_engine import PolicyEngine
from .metrics import MetricsCollector, GLOBAL_METRICS

__version__ = "0.2.0"
__all__ = [
    "Event", "Node", "Edge", "FlowDetection", "PolicyViolation", "Alert", "Severity",
    "MCPInterceptor", "TaintSourceEngine",
    "FlowAttributionEngine", "PolicyEngine",
    "MetricsCollector", "GLOBAL_METRICS",
]
