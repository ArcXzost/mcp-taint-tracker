import json
import logging
from typing import List, Dict, Any, Tuple, Optional
from neo4j import GraphDatabase

from schema import Event, Node, Edge, _extract_text
from taint_engine import TaintSourceEngine
from flow_attribution import FlowAttributionEngine
from metrics import GLOBAL_METRICS

logger = logging.getLogger(__name__)

class Neo4jSessionGraph:
    """
    Neo4j-backed representation of MCP tool execution history and data provenance.
    """

    def __init__(self, uri: str = "bolt://localhost:7687", user: str = "neo4j", password: str = "password", flow_engine: Optional[FlowAttributionEngine] = None):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        self.flow_engine = flow_engine or FlowAttributionEngine()
        # Ensure constraints
        self._setup_db()

    def _setup_db(self):
        try:
            with self.driver.session() as session:
                session.run("CREATE CONSTRAINT event_id IF NOT EXISTS FOR (e:Event) REQUIRE e.call_id IS UNIQUE")
                session.run("CREATE INDEX session_idx IF NOT EXISTS FOR (e:Event) ON (e.session_id)")
        except Exception as e:
            logger.warning(f"Could not connect to Neo4j to setup constraints: {e}")

    def close(self):
        self.driver.close()

    def clear(self):
        """Clear all nodes (for testing)."""
        try:
            with self.driver.session() as session:
                session.run("MATCH (n) DETACH DELETE n")
        except:
            pass

    def add_event(self, event: Event) -> None:
        """
        Incrementally add an event to the session graph in Neo4j.
        Performs flow checking against all existing nodes in the session,
        updates edges, and propagates taint labels.
        """
        session_id = event.session_id
        nodes_before = 0 # Can't trivially get graph size before, mock for metrics
        
        # Get initial taints
        initial_taints = set(TaintSourceEngine.get_sources(event.tool_name))
        inherited_taints = set(initial_taints)

        # ── Secret Scanning ──
        output_text = _extract_text(event.tool_output)
        if TaintSourceEngine.has_secret_patterns(output_text):
            inherited_taints.add("credential")

        import functools
        
        @functools.lru_cache(maxsize=8192)
        def _cached_flow_check(prev_output_json: str, curr_input_json: str):
            prev_output = json.loads(prev_output_json)
            curr_input = json.loads(curr_input_json)
            return self.flow_engine.check_flow(prev_output, curr_input)

        try:
            with self.driver.session() as session:
                # 1. Fetch previous events in this session
                result = session.run(
                    "MATCH (e:Event {session_id: $session_id}) RETURN e.call_id AS call_id, e.tool_output AS tool_output, e.taint_labels AS taint_labels",
                    session_id=session_id
                )
                
                edges_to_create = []
                for record in result:
                    prev_call_id = record["call_id"]
                    prev_output_json = record["tool_output"]
                    try:
                        prev_output = json.loads(prev_output_json)
                    except:
                        prev_output = {}
                    
                    prev_taints = record["taint_labels"] or []

                    # Flow attribution (cached)
                    detection = _cached_flow_check(prev_output_json, json.dumps(event.tool_input))
                    if detection.flow_detected:
                        edges_to_create.append({
                            "source": prev_call_id,
                            "target": event.call_id,
                            "confidence": detection.confidence,
                            "method": detection.method,
                            "evidence": detection.evidence
                        })
                        inherited_taints.update(prev_taints)

                # 2. Insert new event node and create edges in one operation
                params = {
                    "call_id": event.call_id,
                    "session_id": event.session_id,
                    "tool_name": event.tool_name,
                    "server_name": event.server_name,
                    "timestamp": event.timestamp,
                    "tool_input": json.dumps(event.tool_input),
                    "tool_output": json.dumps(event.tool_output),
                    "taint_labels": list(inherited_taints),
                    "edges": edges_to_create,
                }
                session.run(
                    """
                    CREATE (e:Event {
                        call_id: $call_id,
                        session_id: $session_id,
                        tool_name: $tool_name,
                        server_name: $server_name,
                        timestamp: $timestamp,
                        tool_input: $tool_input,
                        tool_output: $tool_output,
                        taint_labels: $taint_labels
                    })
                    WITH e
                    UNWIND $edges AS edge
                    MATCH (src:Event {call_id: edge.source})
                    MATCH (tgt:Event {call_id: edge.target})
                    CREATE (src)-[:FLOWS_TO {
                        confidence: edge.confidence,
                        method: edge.method,
                        evidence: edge.evidence
                    }]->(tgt)
                    """,
                    params
                )
        except Exception as e:
            logger.error(f"Neo4j add_event failed: {e}")
            # Fallback logic could go here

        GLOBAL_METRICS.record_graph_growth(1)

    def get_sink_paths(self, session_id: str, sink_tools: List[str]) -> List[Tuple[Node, Node, List[str]]]:
        """
        Cypher query to find paths from tainted nodes to sink tools.
        Returns: [(Source Node, Sink Node, path_call_ids)]
        """
        if not sink_tools:
            return []

        paths = []
        try:
            with self.driver.session() as session:
                result = session.run(
                    """
                    MATCH p = (src:Event)-[:FLOWS_TO*]->(sink:Event)
                    WHERE src.session_id = $session_id 
                      AND sink.session_id = $session_id
                      AND size(src.taint_labels) > 0
                      AND sink.tool_name IN $sink_tools
                    RETURN src, sink, [n IN nodes(p) | n.call_id] AS path_ids
                    """,
                    session_id=session_id,
                    sink_tools=sink_tools
                )
                
                for record in result:
                    src_dict = dict(record["src"])
                    sink_dict = dict(record["sink"])
                    
                    src_node = Node(
                        call_id=src_dict["call_id"],
                        tool_name=src_dict["tool_name"],
                        server_name=src_dict["server_name"],
                        timestamp=src_dict["timestamp"],
                        taint_labels=src_dict["taint_labels"]
                    )
                    
                    sink_node = Node(
                        call_id=sink_dict["call_id"],
                        tool_name=sink_dict["tool_name"],
                        server_name=sink_dict["server_name"],
                        timestamp=sink_dict["timestamp"],
                        taint_labels=sink_dict["taint_labels"]
                    )
                    
                    paths.append((src_node, sink_node, record["path_ids"]))
        except Exception as e:
            logger.error(f"Neo4j get_sink_paths failed: {e}")
            
        return paths

    def get_graph_response(self, session_id: str):
        """Build GraphResponse for the API."""
        from taint_engine import TaintSourceEngine
        
        nodes = []
        edges = []
        try:
            with self.driver.session() as session:
                res_nodes = session.run("MATCH (n:Event {session_id: $session_id}) RETURN n", session_id=session_id)
                for record in res_nodes:
                    n = dict(record["n"])
                    tool_name = n.get("tool_name", "unknown")
                    nodes.append({
                        "id": n.get("call_id", ""),
                        "label": tool_name,
                        "tool_name": tool_name,
                        "server_name": n.get("server_name", "local"),
                        "taint_labels": list(n.get("taint_labels", [])),
                        "is_source": len(TaintSourceEngine.get_sources(tool_name)) > 0,
                        "is_sink": len(TaintSourceEngine.get_sinks(tool_name)) > 0,
                        "is_neutral": TaintSourceEngine.is_neutral(tool_name),
                    })
                    
                res_edges = session.run("MATCH (src:Event {session_id: $session_id})-[r:FLOWS_TO]->(tgt:Event) RETURN src.call_id AS src, tgt.call_id AS tgt, r", session_id=session_id)
                for record in res_edges:
                    r = dict(record["r"])
                    edges.append({
                        "from": record["src"],
                        "to": record["tgt"],
                        "confidence": r.get("confidence", 1.0),
                        "method": r.get("method", "explicit"),
                        "edge_type": r.get("method", "explicit"),
                        "evidence": r.get("evidence", "")
                    })
        except Exception as e:
            logger.error(f"Error fetching Neo4j graph: {e}")
            
        return {"session_id": session_id, "nodes": nodes, "edges": edges}

    def get_serializable_graph(self, session_id: str) -> Dict[str, Any]:
        """Convert Neo4j graph back to the format vis.js expects."""
        nodes = []
        edges = []
        try:
            with self.driver.session() as session:
                res_nodes = session.run("MATCH (n:Event {session_id: $session_id}) RETURN n", session_id=session_id)
                for record in res_nodes:
                    n = dict(record["n"])
                    nodes.append({
                        "id": n["call_id"],
                        "label": n["tool_name"],
                        "title": f"Taints: {', '.join(n['taint_labels']) if n['taint_labels'] else 'None'}",
                        "color": "#ef4444" if n["taint_labels"] else "#3b82f6"
                    })
                    
                res_edges = session.run("MATCH (src:Event {session_id: $session_id})-[r:FLOWS_TO]->(tgt:Event) RETURN src.call_id AS src, tgt.call_id AS tgt, r.method AS method", session_id=session_id)
                for record in res_edges:
                    edges.append({
                        "from": record["src"],
                        "to": record["tgt"],
                        "confidence": r.get("confidence", 1.0),
                        "method": r.get("method", "unknown"),
                        "evidence": r.get("evidence", "")
                    })
        except:
            pass
            
        return {"nodes": nodes, "edges": edges}
