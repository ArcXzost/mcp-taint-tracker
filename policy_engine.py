"""
Policy Engine — Component 5.

Evaluates the session provenance graph against security rules to detect policy
violations. Now upgraded to a Declarative Policy Engine (Module 4) that compiles
custom YAML rules into native Cypher queries for Neo4j traversal, with a fallback
for in-memory NetworkX graphs.
"""

import os
import yaml
import logging
from typing import List, Tuple, Dict, Any

from schema import Alert, Severity
from session_graph import SessionGraph
from taint_engine import TaintSourceEngine

logger = logging.getLogger(__name__)

class DeclarativeRule:
    """Represents a parsed YAML declarative rule."""
    def __init__(self, filepath: str):
        with open(filepath, "r") as f:
            self.raw_yaml = f.read()
            data = yaml.safe_load(self.raw_yaml)
            
        self.filename = os.path.basename(filepath)
        self.name = data.get("name", "Unknown Rule")
        self.severity = Severity(data.get("severity", "medium").lower())
        
        pattern = data.get("pattern", {})
        self.source_taints = pattern.get("source", {}).get("taints", [])
        self.max_hops = pattern.get("path", {}).get("max_hops", 5)
        self.sink_tools = pattern.get("sink", {}).get("tools", [])
        
    def to_cypher(self) -> str:
        """Compile the YAML rule into a Neo4j Cypher query."""
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
          [e IN relationships(p) | e.confidence] AS confidences,
          [e IN relationships(p) | e.method] AS methods,
          [e IN relationships(p) | e.evidence] AS evidences
        """
        return query


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

    def evaluate(self, session_graph: Any, session_id: str = "default") -> List[Alert]:
        """
        Scan the session graph for policy violations.
        If session_graph is a Neo4jGraph, it executes Cypher.
        Otherwise falls back to NetworkX traversal.
        """
        if hasattr(session_graph, "driver") and session_graph.driver:
            return self._evaluate_neo4j(session_graph, session_id)
        else:
            return self._evaluate_networkx(session_graph)

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
                        
                        alert_key = (src_id, sink_id, rule.name)
                        new_alert = Alert(
                            alert_id=path_hash,
                            violation=rule.name,
                            severity=rule.severity,
                            rule=f"Matched YAML Rule: {rule.name}",
                            source_node=src_tool,
                            sink_node=sink_tool,
                            source_call_id=src_id,
                            sink_call_id=sink_id,
                            path=path_names,
                            confidence=round(confidence, 3),
                            evidence=" -> ".join(evidence_chain)
                        )
                        
                        if alert_key not in alerts_map or alerts_map[alert_key].confidence < new_alert.confidence:
                            alerts_map[alert_key] = new_alert
                            
        except Exception as e:
            logger.error(f"Neo4j policy evaluation failed: {e}")
            
        return list(alerts_map.values())

    def _evaluate_networkx(self, session_graph: SessionGraph) -> List[Alert]:
        """Legacy fallback for NetworkX in-memory graphs."""
        alerts_map: Dict[Tuple[str, str, str], Alert] = {}
        paths = session_graph.get_tainted_paths_to_sinks()

        for source_node, sink_node, path in paths:
            source_labels = source_node.taint_labels
            
            for rule in self.rules:
                # Check if this rule matches source taints and sink tool
                if not any(t in source_labels for t in rule.source_taints):
                    continue
                if sink_node.tool_name not in rule.sink_tools:
                    continue
                    
                # Path length check
                if len(path) - 1 > rule.max_hops:
                    continue

                # Compute confidence
                confidence = 1.0
                evidence_chain = []
                for i in range(len(path) - 1):
                    u = path[i]
                    v = path[i + 1]
                    edge_data = session_graph.graph.get_edge_data(u, v)
                    if edge_data:
                        confidence *= edge_data.get("confidence", 1.0)
                        method = edge_data.get("method", "unknown")  # Updated key
                        evidence = edge_data.get("evidence", "")
                        evidence_chain.append(f"[{method}] {evidence}")

                num_edges = len(path) - 1
                if num_edges > 1:
                    confidence *= (0.9 ** (num_edges - 1))

                rule_thresh = self.rule_thresholds.get(rule.name, self.global_threshold)
                if confidence < rule_thresh:
                    continue

                import hashlib
                path_hash = hashlib.md5(f"{rule.name}-{source_node.call_id}-{sink_node.call_id}".encode()).hexdigest()

                alert_key = (source_node.call_id, sink_node.call_id, rule.name)
                new_alert = Alert(
                    alert_id=path_hash,
                    violation=rule.name,
                    severity=rule.severity,
                    rule=f"Matched YAML Rule: {rule.name}",
                    source_node=source_node.tool_name,
                    sink_node=sink_node.tool_name,
                    source_call_id=source_node.call_id,
                    sink_call_id=sink_node.call_id,
                    path=[session_graph.nodes_data[cid].tool_name for cid in path],
                    confidence=round(confidence, 3),
                    evidence=" -> ".join(evidence_chain),
                )

                if alert_key not in alerts_map or alerts_map[alert_key].confidence < new_alert.confidence:
                    alerts_map[alert_key] = new_alert

        return list(alerts_map.values())
