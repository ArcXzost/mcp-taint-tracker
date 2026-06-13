"""
Session Provenance Graph — Component 2.

Constructs and maintains a session-scoped execution graph where nodes represent
tool invocations and directed edges represent inferred information flows.
Propagates taint labels along path edges as flows are detected.
"""

import time
import logging
from typing import List, Dict, Any, Tuple, Optional

import networkx as nx

from schema import Event, Node, Edge
from taint_engine import TaintSourceEngine
from flow_attribution import FlowAttributionEngine
from metrics import GLOBAL_METRICS

logger = logging.getLogger(__name__)


class SessionGraph:
    """
    Graph representation of MCP tool execution history and data provenance.
    Supports real-time incremental building and batch construction.
    """

    def __init__(self, flow_engine: Optional[FlowAttributionEngine] = None):
        self.graph = nx.DiGraph()
        self.flow_engine = flow_engine or FlowAttributionEngine()
        self.nodes_data: Dict[str, Node] = {}
        self.events_data: Dict[str, Event] = {}

    def add_event(self, event: Event) -> None:
        """
        Incrementally add an event to the session graph.
        Performs flow checking against all existing nodes, updates edges,
        and propagates taint labels.
        """
        nodes_before = len(self.graph.nodes)
        edges_before = len(self.graph.edges)

        # Store the event data for future flow checks
        self.events_data[event.call_id] = event

        # Get initial taints if this tool is a primary taint source
        initial_taints = set(TaintSourceEngine.get_sources(event.tool_name))
        inherited_taints = set(initial_taints)

        # Create the temporary node
        node = Node(
            call_id=event.call_id,
            tool_name=event.tool_name,
            server_name=event.server_name,
            timestamp=event.timestamp,
            taint_labels=list(inherited_taints),
            summary=f"{event.tool_name} on {event.server_name}",
        )

        # Add node to graph first so flow checks can link to it
        self.graph.add_node(event.call_id, **node.model_dump())
        self.nodes_data[event.call_id] = node

        # Check flows from all pre-existing nodes
        for prev_call_id, prev_node in list(self.nodes_data.items()):
            if prev_call_id == event.call_id:
                continue

            prev_event = self.events_data[prev_call_id]
            detection = self.flow_engine.check_flow(
                prev_event.tool_output, event.tool_input
            )

            if detection.flow_detected:
                # Flow exists! Create a directed edge in the graph
                edge = Edge(
                    source=prev_call_id,
                    target=event.call_id,
                    confidence=detection.confidence,
                    edge_type=detection.method,
                    evidence=detection.evidence,
                )
                self.graph.add_edge(
                    prev_call_id, event.call_id, **edge.model_dump()
                )

                # Propagate all taints from the source node to this node
                if prev_node.taint_labels:
                    inherited_taints.update(prev_node.taint_labels)

        # Update the node's taint labels with all inherited taints
        node.taint_labels = list(inherited_taints)
        self.graph.nodes[event.call_id]["taint_labels"] = node.taint_labels
        self.nodes_data[event.call_id] = node

        # Track graph growth rate
        nodes_added = len(self.graph.nodes) - nodes_before
        GLOBAL_METRICS.record_graph_growth(nodes_added)

        logger.debug(
            "Added node %s. Taints: %s. Added %d nodes, %d edges.",
            event.tool_name,
            node.taint_labels,
            nodes_added,
            len(self.graph.edges) - edges_before,
        )

    def build_from_events(self, events: List[Event]) -> None:
        """Batch construct the graph from a chronological list of events."""
        # Ensure events are sorted by timestamp
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        for event in sorted_events:
            self.add_event(event)

    def get_tainted_paths_to_sinks(self) -> List[Tuple[Node, Node, List[str]]]:
        """
        Traverse the graph and identify all paths from tainted sources to sinks.
        Returns a list of tuples: (source_node, sink_node, call_id_path_list).
        """
        start_time = time.time()
        alerts = []

        # Find all nodes that carry taint labels
        source_nodes = [
            n for n in self.nodes_data.values() if len(n.taint_labels) > 0
        ]
        # Find all nodes that are dangerous sinks
        sink_nodes = [
            n
            for n in self.nodes_data.values()
            if len(TaintSourceEngine.get_sinks(n.tool_name)) > 0
        ]

        longest_chain = 0
        traversal_start = time.time()

        for source in source_nodes:
            for sink in sink_nodes:
                if source.call_id == sink.call_id:
                    continue

                try:
                    # Traversal check: find all simple paths
                    paths = list(
                        nx.all_simple_paths(
                            self.graph, source.call_id, sink.call_id
                        )
                    )
                    for path in paths:
                        alerts.append((source, sink, path))
                        if len(path) > longest_chain:
                            longest_chain = len(path)
                except nx.NetworkXNoPath:
                    pass
                except nx.NodeNotFound:
                    pass

        traversal_time = time.time() - traversal_start
        GLOBAL_METRICS.graph_traversal_times.append(traversal_time)
        GLOBAL_METRICS.path_discovery_times.append(time.time() - start_time)

        # Record session summary
        GLOBAL_METRICS.record_session(
            len(self.graph.nodes), len(self.graph.edges), longest_chain
        )

        return alerts

    def get_graph_stats(self) -> Dict[str, Any]:
        """Return high-level structure stats for the graph."""
        return {
            "num_nodes": len(self.graph.nodes),
            "num_edges": len(self.graph.edges),
            "is_directed_acyclic": nx.is_directed_acyclic_graph(self.graph),
        }
