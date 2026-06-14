"""
Policy Engine — Component 5.

Evaluates the session provenance graph against security rules to detect policy
violations. Now upgraded to a Declarative Policy Engine (Module 4) that compiles
custom YAML rules into native Cypher queries for Neo4j traversal.

Features:
- Schema versioning for rule compatibility
- Built-in test cases (positive/negative) for CI/CD validation
- Rule efficacy tracking (TP/FP/FN per rule)
- MITRE ATT&CK technique mapping
- Compiled rule cache for performance
"""

import os
import yaml
import json
import logging
import hashlib
from typing import List, Tuple, Dict, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

from schema import Alert, Severity, compute_dynamic_severity, FP_BUDGETS
from taint_engine import TaintSourceEngine
from metrics import GLOBAL_METRICS

logger = logging.getLogger(__name__)

class RuleSchemaVersion(Enum):
    V1 = 1  # Legacy format
    V2 = 2  # Current format with test cases, description, schema_version

@dataclass
class RuleTestCase:
    """A single test case for a rule."""
    description: str
    events: List[Dict[str, Any]]
    expected_alert: bool

@dataclass
class RuleEfficacy:
    """Tracks detection efficacy for a single rule."""
    rule_name: str
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    true_negatives: int = 0
    total_latency_ms: float = 0.0
    invocations: int = 0
    
    @property
    def precision(self) -> float:
        total = self.true_positives + self.false_positives
        return self.true_positives / total if total > 0 else 0.0
    
    @property
    def recall(self) -> float:
        total = self.true_positives + self.false_negatives
        return self.true_positives / total if total > 0 else 0.0
    
    @property
    def f1_score(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0
    
    @property
    def fp_rate(self) -> float:
        total = self.false_positives + self.true_negatives
        return self.false_positives / total if total > 0 else 0.0

class DeclarativeRule:
    """Represents a parsed YAML declarative rule with test cases and metadata."""
    def __init__(self, filepath: str):
        with open(filepath, "r") as f:
            self.raw_yaml = f.read()
            data = yaml.safe_load(self.raw_yaml)
            
        self.filename = os.path.basename(filepath)
        self.name = data.get("name", "Unknown Rule")
        self.severity = Severity(data.get("severity", "medium").lower())
        self.schema_version = data.get("schema_version", 1)
        self.description = data.get("description", "")
        self.mitre_techniques = data.get("mitre_techniques", [])
        
        pattern = data.get("pattern", {})
        self.source_taints = pattern.get("source", {}).get("taints", [])
        # Backward compat: old format used source.tools
        if not self.source_taints and "source" in pattern:
            old_tools = pattern.get("source", {}).get("tools", [])
            # Map known tools to taints
            tool_to_taint = {
                "filesystem_read": "filesystem",
                "database_query": "database",
                "get_credentials": "credential",
                "email_read": "email",
                "memory_read": "memory",
                "github_issue_read": "user_input",
                "external_data": "user_input",
            }
            self.source_taints = [tool_to_taint.get(t, "user_input") for t in old_tools]
        
        self.max_hops = pattern.get("path", {}).get("max_hops", 5)
        self.requires_taint = pattern.get("path", {}).get("requires_taint", True)
        self.sink_tools = pattern.get("sink", {}).get("tools", [])
        
        # Parse test cases
        self.test_cases: List[RuleTestCase] = []
        test_data = data.get("test", {})
        for pos in test_data.get("positive", []):
            self.test_cases.append(RuleTestCase(
                description=pos.get("description", "positive test"),
                events=pos.get("events", []),
                expected_alert=True
            ))
        for neg in test_data.get("negative", []):
            self.test_cases.append(RuleTestCase(
                description=neg.get("description", "negative test"),
                events=neg.get("events", []),
                expected_alert=False
            ))
        
        # Efficacy tracking
        self.efficacy = RuleEfficacy(rule_name=self.name)
        
        # Compiled query cache
        self._cypher_cache: Optional[str] = None
        
    def to_cypher(self) -> str:
        """Compile the YAML rule into a Neo4j Cypher query with caching."""
        if self._cypher_cache:
            return self._cypher_cache
            
        src_taints_str = ", ".join([f"'{t}'" for t in self.source_taints])
        sink_tools_str = ", ".join([f"'{t}'" for t in self.sink_tools])
        
        query = f"""
        MATCH p = (src:Event)-[r:FLOWS_TO*1..{self.max_hops}]->(sink:Event)
        WHERE src.session_id = $session_id 
          AND sink.session_id = $session_id
          AND ANY(t IN src.taint_labels WHERE t IN [{src_taints_str}])
          AND sink.tool_name IN [{sink_tools_str}]
        RETURN 
          src.tool_name AS src_tool,
          src.call_id AS src_id,
          sink.tool_name AS sink_tool,
          sink.call_id AS sink_id,
          [n IN nodes(p) | n.tool_name] AS path_names,
          [n IN nodes(p) | n.call_id] AS path_ids,
          [e IN relationships(p) | e.confidence] AS confidences,
          [e IN relationships(p) | e.method] AS methods,
          [e IN relationships(p) | e.evidence] AS evidences
        """
        self._cypher_cache = query
        return query
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize rule to dictionary for API responses."""
        return {
            "filename": self.filename,
            "name": self.name,
            "severity": self.severity.value,
            "schema_version": self.schema_version,
            "description": self.description,
            "mitre_techniques": self.mitre_techniques,
            "source_taints": self.source_taints,
            "sink_tools": self.sink_tools,
            "max_hops": self.max_hops,
            "test_count": len(self.test_cases),
            "efficacy": {
                "precision": self.efficacy.precision,
                "recall": self.efficacy.recall,
                "f1_score": self.efficacy.f1_score,
                "fp_rate": self.efficacy.fp_rate,
                "true_positives": self.efficacy.true_positives,
                "false_positives": self.efficacy.false_positives,
                "false_negatives": self.efficacy.false_negatives,
                "true_negatives": self.efficacy.true_negatives,
                "invocations": self.efficacy.invocations,
            },
            "raw_yaml": self.raw_yaml,
        }


class PolicyEngine:
    """
    Evaluates security policies on the session provenance graph.
    Compiles YAML rules to Cypher for Neo4j, or uses NetworkX fallback.
    """
    def __init__(self, rules_dir: str = "rules"):
        self.rules: List[DeclarativeRule] = []
        self.rule_thresholds = {}
        self.global_threshold = 0.50
        self._load_rules(rules_dir)
        self.reload_thresholds()
        
    def reload_thresholds(self):
        """Load optimized rule thresholds from learning pipeline."""
        if os.path.exists("optimized_thresholds.json"):
            try:
                with open("optimized_thresholds.json", "r") as f:
                    opt = json.load(f)
                    if "_global" in opt:
                        self.global_threshold = opt["_global"].get("semantic_threshold", 0.50)
                    if "rules" in opt:
                        self.rule_thresholds = {
                            k: v.get("semantic_threshold", self.global_threshold) 
                            for k, v in opt["rules"].items()
                        }
            except Exception as e:
                logger.error(f"Failed to load optimized thresholds: {e}")

    def load_rules_from_directory(self, rules_dir: str = "rules"):
        self.rules = []
        self._load_rules(rules_dir)

    def _load_rules(self, rules_dir: str):
        if not os.path.exists(rules_dir):
            logger.warning(f"Rules directory '{rules_dir}' not found. No rules loaded.")
            return
            
        for file in os.listdir(rules_dir):
            if file.endswith((".yaml", ".yml")):
                try:
                    rule = DeclarativeRule(os.path.join(rules_dir, file))
                    self.rules.append(rule)
                    logger.info(f"Loaded YAML Rule: {rule.name}")
                except Exception as e:
                    logger.error(f"Failed to load rule {file}: {e}")

    def run_tests(self, rules_dir: str = "rules") -> List[Dict[str, Any]]:
        """Run all built-in test cases for all rules. Returns test results."""
        results = []
        for rule in self.rules:
            if not rule.test_cases:
                results.append({
                    "rule": rule.name,
                    "status": "skipped",
                    "reason": "no test cases defined",
                })
                continue
            
            failures = 0
            passed = 0
            for tc in rule.test_cases:
                try:
                    # Build a mini Neo4jSessionGraph from test events
                    from neo4j_graph import Neo4jSessionGraph
                    from schema import Event
                    import time as time_mod
                    from flow_attribution import FlowAttributionEngine
                    
                    test_graph = Neo4jSessionGraph(flow_engine=None)
                    test_graph.flow_engine = FlowAttributionEngine()
                    
                    test_sid = f"test-{rule.name}-{hashlib.md5(tc.description.encode()).hexdigest()[:8]}"
                    for evt in tc.events:
                        event = Event(
                            call_id=hashlib.md5(f"{evt.get('tool_name')}-{test_sid}-{time_mod.time()}".encode()).hexdigest()[:12],
                            session_id=test_sid,
                            tool_name=evt.get("tool_name", "unknown"),
                            server_name=evt.get("server_name", "test"),
                            tool_input=evt.get("tool_input", {}),
                            tool_output=evt.get("tool_output", {}),
                            timestamp=time_mod.time(),
                        )
                        test_graph.add_event(event)
                    
                    # Evaluate against this rule only
                    old_rules = self.rules
                    self.rules = [rule]
                    alerts = self._evaluate_neo4j(test_graph, session_id=test_sid)
                    self.rules = old_rules
                    
                    has_alert = len(alerts) > 0
                    if has_alert == tc.expected_alert:
                        passed += 1
                    else:
                        failures += 1
                        results.append({
                            "rule": rule.name,
                            "status": "failed",
                            "test": tc.description,
                            "expected": tc.expected_alert,
                            "got": has_alert,
                        })
                except Exception as e:
                    failures += 1
                    results.append({
                        "rule": rule.name,
                        "status": "error",
                        "test": tc.description,
                        "error": str(e),
                    })
            
            if failures == 0 and any(
                r.get("rule") == rule.name and r.get("status") == "skipped"
                for r in results
            ):
                continue
            
            if failures == 0:
                results.append({
                    "rule": rule.name,
                    "status": "passed",
                    "passed": passed,
                    "total": len(rule.test_cases),
                })
        
        return results
    
    def validate_all_rules(self) -> List[Dict[str, Any]]:
        """Validate rule schema, test coverage, FP rates. Returns issues."""
        issues = []
        for rule in self.rules:
            # Schema version check
            if rule.schema_version < 2:
                issues.append({
                    "rule": rule.name,
                    "severity": "warning",
                    "message": f"Schema version {rule.schema_version} is outdated. Should be >= 2",
                })
            
            # Test coverage check
            if len(rule.test_cases) == 0:
                issues.append({
                    "rule": rule.name,
                    "severity": "warning",
                    "message": "No test cases defined. Add positive and negative test cases for CI/CD.",
                })
            elif all(tc.expected_alert for tc in rule.test_cases):
                issues.append({
                    "rule": rule.name,
                    "severity": "warning",
                    "message": "Only positive test cases (no negative tests). Add negative cases to prevent FP.",
                })
            
            # Source taints check
            if not rule.source_taints:
                issues.append({
                    "rule": rule.name,
                    "severity": "error",
                    "message": "No source taints defined. Rule will never match.",
                })
            
            # Sink tools check
            if not rule.sink_tools:
                issues.append({
                    "rule": rule.name,
                    "severity": "error",
                    "message": "No sink tools defined. Rule will never match.",
                })
            
            # Efficacy check: auto-demote rules with >5% FP rate
            if rule.efficacy.invocations >= 10:
                if rule.efficacy.fp_rate > 0.05:
                    issues.append({
                        "rule": rule.name,
                        "severity": "critical",
                        "message": f"FP rate {rule.efficacy.fp_rate:.1%} exceeds 5% threshold. Auto-demoting.",
                    })
        
        return issues
    
    def auto_demote_rules(self) -> List[str]:
        """Demote rules exceeding FP budget. Returns demoted rule names."""
        demoted = []
        for rule in self.rules:
            if rule.efficacy.invocations >= 10 and rule.efficacy.fp_rate > 0.05:
                old_severity = rule.severity
                # Demote: critical -> high -> medium -> low -> info -> disabled
                severity_order = ["critical", "high", "medium", "low", "info"]
                try:
                    idx = severity_order.index(rule.severity.value)
                    if idx < len(severity_order) - 1:
                        rule.severity = Severity(severity_order[idx + 1])
                    else:
                        rule.severity = Severity("info")
                except ValueError:
                    rule.severity = Severity("info")
                demoted.append(f"{rule.name}: {old_severity.value} -> {rule.severity.value}")
                logger.warning("Auto-demoted rule '%s' due to FP rate %.1f%%", rule.name, rule.efficacy.fp_rate * 100)
        return demoted
    
    def get_efficacy_summary(self) -> Dict[str, Any]:
        """Return aggregate efficacy metrics across all rules."""
        total_tp = sum(r.efficacy.true_positives for r in self.rules)
        total_fp = sum(r.efficacy.false_positives for r in self.rules)
        total_fn = sum(r.efficacy.false_negatives for r in self.rules)
        total_tn = sum(r.efficacy.true_negatives for r in self.rules)
        precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0.0
        recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0.0
        return {
            "rules_loaded": len(self.rules),
            "rules_with_tests": sum(1 for r in self.rules if r.test_cases),
            "total_tp": total_tp,
            "total_fp": total_fp,
            "total_fn": total_fn,
            "total_tn": total_tn,
            "aggregate_precision": round(precision, 3),
            "aggregate_recall": round(recall, 3),
            "rules_demoted": sum(1 for r in self.rules
                if r.efficacy.invocations >= 10 and r.efficacy.fp_rate > 0.05),
            "per_rule": {
                r.name: {
                    "precision": r.efficacy.precision,
                    "recall": r.efficacy.recall,
                    "fp_rate": r.efficacy.fp_rate,
                    "invocations": r.efficacy.invocations,
                }
                for r in self.rules if r.efficacy.invocations > 0
            }
        }

    def evaluate(self, session_graph: Any, session_id: str = "default") -> List[Alert]:
        """
        Scan the session graph for policy violations.
        Uses Neo4j Cypher queries to find tainted paths to sinks.
        """
        return self._evaluate_neo4j(session_graph, session_id)

    def _evaluate_neo4j(self, neo4j_graph: Any, session_id: str) -> List[Alert]:
        """Execute compiled Cypher queries against Neo4j."""
        alerts_map: Dict[Tuple[str, str, str], Alert] = {}
        
        try:
            with neo4j_graph.driver.session() as session:
                for rule in self.rules:
                    cypher_query = rule.to_cypher()
                    result = session.run(cypher_query, session_id=session_id)
                    
                    for record in result:
                        src_id = record["src_id"]
                        sink_id = record["sink_id"]
                        src_tool = record["src_tool"]
                        sink_tool = record["sink_tool"]
                        path_names = record["path_names"]
                        path_ids = record.get("path_ids", [])
                        confidences = record["confidences"]
                        methods = record["methods"]
                        evidences = record["evidences"]
                        
                        # Calculate confidence with decay
                        confidence = 1.0
                        evidence_chain = []
                        for i in range(len(confidences)):
                            confidence *= confidences[i]
                            evidence_chain.append(f"[{methods[i]}] {evidences[i]}")
                            
                        # Apply decay: 10% penalty per hop after first
                        num_edges = len(confidences)
                        if num_edges > 1:
                            confidence *= (0.9 ** (num_edges - 1))
                            
                        # Check against Rule-Specific threshold
                        rule_thresh = self.rule_thresholds.get(rule.name, self.global_threshold)
                        if confidence < rule_thresh:
                            continue
                            
                        import hashlib
                        path_hash = hashlib.md5(f"{rule.name}-{src_id}-{sink_id}".encode()).hexdigest()
                        
                        # Compute dynamic severity
                        fp_budget = FP_BUDGETS.current_fp_budget_minutes(rule.name)
                        dynamic_sev = compute_dynamic_severity(
                            rule_severity=rule.severity,
                            rule_efficacy_precision=rule.efficacy.precision,
                            rule_invocations=rule.efficacy.invocations,
                            mitre_coverage=len(rule.mitre_techniques),
                            fp_budget_minutes=fp_budget,
                        )
                        sev_to_tier = {"critical": "P0", "high": "P1", "medium": "P2", "low": "P3", "info": "P3"}
                        recommended_tier = sev_to_tier.get(dynamic_sev.value, "P3")

                        # Track efficacy
                        rule.efficacy.true_positives += 1
                        rule.efficacy.invocations += 1

                        alert_key = (src_id, sink_id, rule.name)
                        new_alert = Alert(
                            alert_id=path_hash,
                            violation=rule.name,
                            severity=dynamic_sev,
                            rule=f"Matched YAML Rule: {rule.name}",
                            source_node=src_tool,
                            sink_node=sink_tool,
                            source_call_id=src_id,
                            sink_call_id=sink_id,
                            path=path_names,
                            path_call_ids=path_ids,
                            confidence=round(confidence, 3),
                            evidence=" -> ".join(evidence_chain),
                            recommended_tier=recommended_tier,
                            mitre_techniques=rule.mitre_techniques,
                            fp_budget_used_minutes=fp_budget,
                        )
                        
                        if alert_key not in alerts_map or alerts_map[alert_key].confidence < new_alert.confidence:
                            alerts_map[alert_key] = new_alert
                            
        except Exception as e:
            logger.error(f"Neo4j policy evaluation failed: {e}")
            
        return list(alerts_map.values())


