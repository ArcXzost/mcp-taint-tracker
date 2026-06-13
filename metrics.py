"""
Metrics Collector — Component 7.

Gathers, computes, and outputs detection accuracy, graph provenance,
attribution method breakdown, and runtime performance overhead.
"""

import json
import time
import tracemalloc
from typing import List, Dict, Any, Optional
import numpy as np


class MetricsCollector:
    """
    Collects, aggregates, and exports runtime performance and security metrics.
    """

    def __init__(self):
        self.reset()
        self._tracemalloc_started = False

    def reset(self) -> None:
        """Reset all metric counters and trackers to their initial states."""
        # Detection metrics (confusion matrix)
        self.tp: int = 0
        self.fp: int = 0
        self.tn: int = 0
        self.fn: int = 0

        # Provenance metrics
        self.nodes_per_session: List[int] = []
        self.edges_per_session: List[int] = []
        self.longest_taint_chains: List[int] = []
        self.graph_traversal_times: List[float] = []
        self.path_discovery_times: List[float] = []

        # Attribution metrics
        self.explicit_detections: int = 0
        self.lexical_detections: int = 0
        self.semantic_detections: int = 0
        self.confidence_distribution: List[float] = []
        self.attribution_latencies: List[float] = []

        # Runtime metrics
        self.total_latencies: List[float] = []
        self.peak_memory_bytes: float = 0.0
        self.graph_growth_rates: List[float] = []  # nodes added per event in session

    def start_memory_tracking(self) -> None:
        """Start tracking memory allocations using tracemalloc."""
        if not self._tracemalloc_started:
            tracemalloc.start()
            self._tracemalloc_started = True

    def update_peak_memory(self) -> float:
        """Snapshot current peak memory allocation and return it in bytes."""
        if self._tracemalloc_started:
            _, peak = tracemalloc.get_traced_memory()
            if peak > self.peak_memory_bytes:
                self.peak_memory_bytes = float(peak)
        return self.peak_memory_bytes

    def record_test_case(self, detected: bool, expected: bool) -> None:
        """Record a benchmark test outcome to the confusion matrix."""
        if expected and detected:
            self.tp += 1
        elif not expected and not detected:
            self.tn += 1
        elif expected and not detected:
            self.fn += 1
        elif not expected and detected:
            self.fp += 1

    def record_session(self, nodes: int, edges: int, longest_chain: int) -> None:
        """Record provenance graph size and structure statistics."""
        self.nodes_per_session.append(nodes)
        self.edges_per_session.append(edges)
        self.longest_taint_chains.append(longest_chain)

    def record_attribution(self, method: str, confidence: float, latency: float) -> None:
        """Record information flow attribution details."""
        if method == "explicit":
            self.explicit_detections += 1
        elif method == "lexical":
            self.lexical_detections += 1
        elif method == "semantic":
            self.semantic_detections += 1

        if method != "none":
            self.confidence_distribution.append(confidence)

        self.attribution_latencies.append(latency)

    def record_graph_growth(self, nodes_added: int) -> None:
        """Record the growth rate (e.g., number of nodes added)."""
        self.graph_growth_rates.append(float(nodes_added))

    @property
    def precision(self) -> float:
        """Compute precision: TP / (TP + FP)"""
        total_positives = self.tp + self.fp
        return float(self.tp / total_positives) if total_positives > 0 else 0.0

    @property
    def recall(self) -> float:
        """Compute recall: TP / (TP + FN)"""
        total_actual_positives = self.tp + self.fn
        return float(self.tp / total_actual_positives) if total_actual_positives > 0 else 0.0

    @property
    def f1_score(self) -> float:
        """Compute F1 score: 2 * (P * R) / (P + R)"""
        p, r = self.precision, self.recall
        return float(2 * p * r / (p + r)) if (p + r) > 0 else 0.0

    @property
    def fpr(self) -> float:
        """Compute False Positive Rate: FP / (FP + TN)"""
        total_negatives = self.fp + self.tn
        return float(self.fp / total_negatives) if total_negatives > 0 else 0.0

    @property
    def fnr(self) -> float:
        """Compute False Negative Rate: FN / (FN + TP)"""
        total_actual_positives = self.fn + self.tp
        return float(self.fn / total_actual_positives) if total_actual_positives > 0 else 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert collector state into a serializable metrics dictionary."""
        self.update_peak_memory()

        # Helper to safely compute mean of list
        def _mean(lst: List[Any]) -> float:
            return float(np.mean(lst)) if lst else 0.0

        # Helper to safely compute percentiles
        def _percentile(lst: List[Any], p: float) -> float:
            return float(np.percentile(lst, p)) if lst else 0.0

        return {
            "detection": {
                "tp": self.tp,
                "fp": self.fp,
                "tn": self.tn,
                "fn": self.fn,
                "precision": self.precision,
                "recall": self.recall,
                "f1_score": self.f1_score,
                "false_positive_rate": self.fpr,
                "false_negative_rate": self.fnr,
            },
            "provenance": {
                "avg_nodes_per_session": _mean(self.nodes_per_session),
                "avg_edges_per_session": _mean(self.edges_per_session),
                "longest_taint_chain": int(max(self.longest_taint_chains)) if self.longest_taint_chains else 0,
                "avg_path_discovery_time_ms": _mean(self.path_discovery_times) * 1000.0,
                "avg_graph_traversal_time_ms": _mean(self.graph_traversal_times) * 1000.0,
            },
            "attribution": {
                "explicit_detections": self.explicit_detections,
                "lexical_detections": self.lexical_detections,
                "semantic_detections": self.semantic_detections,
                "avg_confidence": _mean(self.confidence_distribution),
                "avg_attribution_latency_ms": _mean(self.attribution_latencies) * 1000.0,
            },
            "runtime": {
                "p50_latency_ms": _percentile(self.total_latencies, 50) * 1000.0,
                "p95_latency_ms": _percentile(self.total_latencies, 95) * 1000.0,
                "p99_latency_ms": _percentile(self.total_latencies, 99) * 1000.0,
                "peak_memory_mb": self.peak_memory_bytes / (1024 * 1024),
                "avg_graph_growth_rate": _mean(self.graph_growth_rates),
                "attribution_overhead_pct": (sum(self.attribution_latencies) / sum(self.total_latencies) * 100.0)
                if self.total_latencies and sum(self.total_latencies) > 0 else 0.0,
            }
        }

    def print_metrics(self) -> None:
        """Print formatted metrics summary to stdout."""
        data = self.to_dict()

        print("\n" + "=" * 40)
        print("         MCPSecBench-MVP Metrics")
        print("=" * 40)

        det = data["detection"]
        print("\n--- DETECTION ACCURACY ---")
        print(f"Precision: {det['precision']:.2f}")
        print(f"Recall:    {det['recall']:.2f}")
        print(f"F1 Score:  {det['f1_score']:.2f}")
        print(f"FPR:       {det['false_positive_rate']:.2f}")
        print(f"FNR:       {det['false_negative_rate']:.2f}")
        print(f"Counts:    TP={det['tp']}, FP={det['fp']}, TN={det['tn']}, FN={det['fn']}")

        prov = data["provenance"]
        print("\n--- PROVENANCE GRAPH ---")
        print(f"Avg Nodes/Session:   {prov['avg_nodes_per_session']:.2f}")
        print(f"Avg Edges/Session:   {prov['avg_edges_per_session']:.2f}")
        print(f"Longest Taint Chain: {prov['longest_taint_chain']}")
        print(f"Avg Traversal Time:  {prov['avg_graph_traversal_time_ms']:.2f} ms")
        print(f"Avg Path Discovery:  {prov['avg_path_discovery_time_ms']:.2f} ms")

        attr = data["attribution"]
        print("\n--- FLOW ATTRIBUTION ---")
        print(f"Explicit Flows:      {attr['explicit_detections']}")
        print(f"Lexical Flows:       {attr['lexical_detections']}")
        print(f"Semantic Flows:      {attr['semantic_detections']}")
        print(f"Avg Flow Confidence: {attr['avg_confidence']:.2f}")
        print(f"Avg Attr Latency:    {attr['avg_attribution_latency_ms']:.2f} ms")

        run = data["runtime"]
        print("\n--- RUNTIME OVERHEAD ---")
        print(f"P50 Latency:         {run['p50_latency_ms']:.2f} ms")
        print(f"P95 Latency:         {run['p95_latency_ms']:.2f} ms")
        print(f"P99 Latency:         {run['p99_latency_ms']:.2f} ms")
        print(f"Peak Memory:         {run['peak_memory_mb']:.2f} MB")
        print(f"Graph Growth Rate:   {run['avg_graph_growth_rate']:.2f} nodes/event")
        print(f"Attribution Cost:    {run['attribution_overhead_pct']:.2f}% of total latency")
        print("=" * 40 + "\n")

    def export_json(self, filepath: str) -> None:
        """Export session metrics to a JSON file."""
        with open(filepath, "w") as f:
            json.dump(self.to_dict(), f, indent=4)


# Single global metrics collector instance.
GLOBAL_METRICS = MetricsCollector()
GLOBAL_METRICS.start_memory_tracking()
