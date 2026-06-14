"""
Data schemas for the MCP Semantic Taint Tracker.

All structured data flowing through the system is defined here using Pydantic
models to enforce validation and provide serialization.
"""

from enum import Enum
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional, Callable
import time as time_module


class Severity(str, Enum):
    """Alert severity levels, ordered by urgency."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    DISABLED = "disabled"


class TierAction(str, Enum):
    """Action to take when a tier threshold is exceeded."""
    BLOCK = "block"
    INVESTIGATE = "investigate"
    ENRICH = "enrich"
    LOG = "log"


class TierConfig(BaseModel):
    """
    Dynamic tiering configuration for detection thresholds.
    
    Each tier defines strict criteria that must ALL be met:
    - min_efficacy: Minimum precision for this tier
    - max_fp_budget_minutes: Maximum cumulative analyst time wasted per day
    - min_mitre_coverage: Minimum MITRE ATT&CK sub-techniques mapped
    - action: What to do when triggered
    """
    name: str
    min_efficacy: float = Field(ge=0.0, le=1.0)
    max_fp_budget_minutes: float = Field(ge=0.0)
    min_mitre_coverage: int = Field(ge=0)
    action: TierAction = TierAction.LOG
    pager_duty: bool = False


# Default tier definitions based on SOC best practices
DEFAULT_TIERS: Dict[str, TierConfig] = {
    "P0": TierConfig(
        name="P0 — Block",
        min_efficacy=0.99,
        max_fp_budget_minutes=5.0,
        min_mitre_coverage=3,
        action=TierAction.BLOCK,
        pager_duty=True,
    ),
    "P1": TierConfig(
        name="P1 — Investigate",
        min_efficacy=0.95,
        max_fp_budget_minutes=30.0,
        min_mitre_coverage=2,
        action=TierAction.INVESTIGATE,
        pager_duty=False,
    ),
    "P2": TierConfig(
        name="P2 — Enrich",
        min_efficacy=0.90,
        max_fp_budget_minutes=120.0,
        min_mitre_coverage=1,
        action=TierAction.ENRICH,
        pager_duty=False,
    ),
    "P3": TierConfig(
        name="P3 — Log",
        min_efficacy=0.0,
        max_fp_budget_minutes=float('inf'),
        min_mitre_coverage=0,
        action=TierAction.LOG,
        pager_duty=False,
    ),
}


class FPBudgetTracker:
    """
    Tracks cumulative false positive time budget per rule.
    
    Each FP costs ~5 minutes of analyst time (industry avg).
    Auto-demotes rules that exceed their tier budget.
    """
    
    def __init__(self):
        self.fp_counts: Dict[str, int] = {}
        self.budget_reset_time: float = time_module.time()
        
    def record_fp(self, rule_name: str) -> None:
        """Record a false positive for a rule (costs ~5 min analyst time)."""
        self.fp_counts[rule_name] = self.fp_counts.get(rule_name, 0) + 1
        
    def current_fp_budget_minutes(self, rule_name: str) -> float:
        """Compute cumulative wasted analyst time for this rule (24h window)."""
        return self.fp_counts.get(rule_name, 0) * 5.0  # 5 min per FP
        
    def reset_budgets(self) -> None:
        """Reset all FP counters (e.g., daily rollover)."""
        self.fp_counts.clear()
        self.budget_reset_time = time_module.time()


# Global FP budget tracker instance
FP_BUDGETS = FPBudgetTracker()


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
    source_call_id: str = ""
    sink_call_id: str = ""
    path: List[str]
    confidence: float
    evidence: str
    recommended_tier: str = Field(default="P3", description="Recommended tier based on dynamic evaluation")
    mitre_techniques: List[str] = Field(default_factory=list, description="MITRE ATT&CK technique IDs")
    fp_budget_used_minutes: float = Field(default=0.0, description="Cumulative FP budget used by this rule")
    path_call_ids: List[str] = Field(default_factory=list, description="Call IDs along alert path for graph edge filtering")


def compute_dynamic_severity(
    rule_severity: Severity,
    rule_efficacy_precision: float,
    rule_invocations: int,
    mitre_coverage: int,
    fp_budget_minutes: float,
    environment: str = "production",
) -> Severity:
    """
    Compute the effective severity level based on:
    - Rule's base severity
    - Measured precision (efficacy)
    - MITRE ATT&CK coverage
    - Cumulative FP budget consumption
    - Environment context
    
    Returns the appropriate severity, potentially demoting rules
    with poor efficacy or excessive FP costs.
    """
    # Rules with <10 invocations are still warming up, use base severity
    if rule_invocations < 10:
        return rule_severity
    
    # Determine the highest tier this rule qualifies for
    for tier_name, config in DEFAULT_TIERS.items():
        if rule_efficacy_precision < config.min_efficacy:
            continue
        if fp_budget_minutes > config.max_fp_budget_minutes:
            continue
        if mitre_coverage < config.min_mitre_coverage:
            continue
        # Found the appropriate tier
        break
    else:
        # Falls below P3: disable
        return Severity.DISABLED
    
    # Map tier to base severity
    tier_severity_map = {
        "P0": Severity.CRITICAL,
        "P1": Severity.HIGH,
        "P2": Severity.MEDIUM,
        "P3": Severity.INFO,
    }
    dynamic = tier_severity_map.get(tier_name, Severity.INFO)
    
    # Never elevate above base severity, only demote
    severity_order = {s.value: i for i, s in enumerate(Severity)}
    if severity_order.get(dynamic.value, 0) < severity_order.get(rule_severity.value, 0):
        return dynamic
    
    return rule_severity


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
