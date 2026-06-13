"""
Data schemas for the MCP Semantic Taint Tracker.

All structured data flowing through the system is defined here using Pydantic
models to enforce validation and provide serialization.
"""

from enum import Enum
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional


class Severity(str, Enum):
    """Alert severity levels, ordered by urgency."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Event(BaseModel):
    """
    A captured MCP tool invocation event.

    Every MCP request/response pair that flows through the interception layer
    produces one Event. This is the raw input to the provenance graph.
    """
    call_id: str
    session_id: str
    tool_name: str
    server_name: str
    tool_input: Dict[str, Any]
    tool_output: Dict[str, Any]
    timestamp: float

    def input_text(self) -> str:
        """Extract all string values from tool_input as a single text corpus."""
        return _extract_text(self.tool_input)

    def output_text(self) -> str:
        """Extract all string values from tool_output as a single text corpus."""
        return _extract_text(self.tool_output)


class Node(BaseModel):
    """
    A node in the session provenance graph.

    Each node represents a single tool invocation. Taint labels accumulate
    as data flows propagate through the graph.
    """
    call_id: str
    tool_name: str
    server_name: str
    timestamp: float
    taint_labels: List[str] = Field(default_factory=list)
    summary: str


class Edge(BaseModel):
    """
    A directed edge in the session provenance graph.

    Represents an inferred information flow between two tool invocations.
    The edge_type indicates the attribution method that detected the flow.
    """
    source: str
    target: str
    confidence: float
    edge_type: str  # explicit | lexical | semantic | memory
    evidence: str


class FlowDetection(BaseModel):
    """
    Result of checking whether information flowed between two tool invocations.

    Produced by the FlowAttributionEngine for every pair comparison.
    Every detection must be explainable — no black-box verdicts.
    """
    flow_detected: bool
    confidence: float
    evidence: str
    method: str  # explicit | lexical | semantic | none


class PolicyViolation(BaseModel):
    """A policy rule violation detected by the PolicyEngine."""
    severity: Severity
    rule: str
    path: List[str]
    confidence: float
    evidence: str


class Alert(BaseModel):
    """
    A fully explainable security alert.

    Every alert must explain itself: what violation occurred, the full path
    through the provenance graph, the confidence level, and human-readable
    evidence. No black-box security decisions.
    """
    alert_id: str = Field(default_factory=lambda: __import__('uuid').uuid4().hex)
    triage_status: Optional[str] = Field(None, description="'tp' or 'fp'")
    violation: str
    severity: Severity
    rule: str
    source_node: str
    sink_node: str
    path: List[str]
    confidence: float
    evidence: str


def _extract_text(obj: Any) -> str:
    """Recursively extract all string values from nested dicts/lists."""
    texts: List[str] = []

    def _walk(item: Any) -> None:
        if isinstance(item, str):
            texts.append(item)
        elif isinstance(item, dict):
            for v in item.values():
                _walk(v)
        elif isinstance(item, (list, tuple)):
            for elem in item:
                _walk(elem)

    _walk(obj)
    return " ".join(texts)
