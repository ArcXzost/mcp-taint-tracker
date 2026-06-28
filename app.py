"""
MCP Semantic Taint Tracker — FastAPI Application Server.

Exposes REST API endpoints for streaming tool execution events,
querying session provenance graphs, retrieving security alerts,
and serving the interactive web dashboard.

Launch with:
    uvicorn app:app --reload --port 8000
"""

import hashlib
import json
import logging
import os
import re
import threading
import time
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from mcp_gateway import initialize_backends, register_mcp_routes, _backends
from mcp_interception_layer import MCPInterceptor
from schema import Event, Alert, Severity
import logging

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

from flow_attribution import FlowAttributionEngine
from kafka_utils import streaming_client
from metrics import GLOBAL_METRICS
from neo4j_graph import Neo4jSessionGraph
from policy_engine import PolicyEngine
from taint_engine import TaintSourceEngine

os.environ["HF_HUB_DISABLE_SYMLINKS_WARNING"] = "1"

# ═══════════════════════════════════════════════════════════════════════
#  Global State — Session registry & shared engine
# ═══════════════════════════════════════════════════════════════════════

flow_engine: Optional[FlowAttributionEngine] = None
policy_engine = PolicyEngine()

# Per-session stores
session_interceptors: Dict[str, MCPInterceptor] = {}
session_graphs: Dict[str, Neo4jSessionGraph] = {}
session_alerts: Dict[str, List[Alert]] = {}


async def lifespan(app: FastAPI):
    """Pre-load the sentence transformer model at startup and connect Kafka."""
    global flow_engine
    logger.info("Loading FlowAttributionEngine on startup...")
    flow_engine = FlowAttributionEngine()
    GLOBAL_METRICS.start_memory_tracking()

    logger.info("Connecting to Kafka...")
    if not await streaming_client.connect_producer():
        raise RuntimeError("Failed to connect to Kafka Producer. Kafka is required.")
    await streaming_client.start_consumer(process_kafka_message)

    logger.info("Engine ready.")
    yield
    logger.info("Shutting down.")
    await streaming_client.stop_consumer()
    await streaming_client.disconnect_producer()


app = FastAPI(
    title="MCP Semantic Taint Tracker",
    description="Session-aware semantic provenance tracking for MCP tool ecosystems.",
    version="0.2.0",
    lifespan=lifespan,
)

# Serve the static dashboard files
static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.isdir(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

# Register MCP Streamable HTTP gateway for n8n integration
register_mcp_routes(app)


# ═══════════════════════════════════════════════════════════════════════
#  Request / Response Schemas
# ═══════════════════════════════════════════════════════════════════════


class EventRequest(BaseModel):
    """Payload for posting a new MCP tool call event."""

    tool_name: str
    server_name: str = "local"
    tool_input: Dict[str, Any] = Field(default_factory=dict)
    tool_output: Dict[str, Any] = Field(default_factory=dict)


class EventResponse(BaseModel):
    """Response after processing an event — includes any triggered alerts."""

    call_id: str
    session_id: str
    alerts_triggered: int
    alerts: List[Alert]


class GraphNode(BaseModel):
    """Node representation for the dashboard graph renderer."""

    id: str
    label: str
    tool_name: str
    server_name: str
    taint_labels: List[str]
    is_source: bool
    is_sink: bool
    is_neutral: bool


class GraphEdge(BaseModel):
    """Edge representation for the dashboard graph renderer."""

    from_: str = Field(alias="from")
    to: str
    confidence: float
    method: str = "unknown"
    evidence: str = ""
    edge_type: str = "unknown"
    in_alert_path: bool = False

    model_config = {"populate_by_name": True}


class GraphResponse(BaseModel):
    """Full graph structure for rendering."""

    session_id: str
    nodes: List[GraphNode]
    edges: List[GraphEdge]


class SessionSummary(BaseModel):
    """Summary of a session for the session list."""

    session_id: str
    event_count: int
    alert_count: int
    node_count: int
    edge_count: int


# ═══════════════════════════════════════════════════════════════════════
#  Helper Functions
# ═══════════════════════════════════════════════════════════════════════


def _ensure_session(session_id: str) -> None:
    """Initialize session stores if the session doesn't exist yet."""
    if session_id not in session_graphs:
        session_graphs[session_id] = Neo4jSessionGraph(flow_engine=flow_engine)
        session_interceptors[session_id] = MCPInterceptor(session_id=session_id)
        session_alerts[session_id] = []


# ═══════════════════════════════════════════════════════════════════════
#  Routes — Dashboard
# ═══════════════════════════════════════════════════════════════════════


@app.get("/", include_in_schema=False)
async def serve_dashboard():
    """Serve the main dashboard HTML page."""
    index_path = os.path.join(static_dir, "index.html")
    if os.path.isfile(index_path):
        return FileResponse(index_path)
    return {"message": "Dashboard not found. Place index.html in static/ directory."}


# ═══════════════════════════════════════════════════════════════════════
#  Routes — Sessions
# ═══════════════════════════════════════════════════════════════════════


@app.get("/api/sessions", response_model=List[SessionSummary])
async def list_sessions():
    """List all active tracking sessions."""
    summaries = []
    for sid in session_interceptors:
        interceptor = session_interceptors[sid]
        graph = session_graphs[sid]
        alerts = session_alerts.get(sid, [])
        resp = graph.get_graph_response(sid)
        summaries.append(
            SessionSummary(
                session_id=sid,
                event_count=len(interceptor.events),
                alert_count=len(alerts),
                node_count=len(resp.get("nodes", [])),
                edge_count=len(resp.get("edges", [])),
            )
        )
    return summaries


# ═══════════════════════════════════════════════════════════════════════
#  Routes — Events
# ═══════════════════════════════════════════════════════════════════════


async def process_kafka_message(msg: Dict[str, Any]):
    """Background worker that processes events off the Kafka topic."""
    session_id = msg.get("session_id")
    if not session_id:
        return

    _ensure_session(session_id)

    interceptor = session_interceptors[session_id]
    graph = session_graphs[session_id]

    start_time = time.time()

    # 1. Intercept and build standard Event
    event = interceptor.intercept(
        tool_name=msg.get("tool_name"),
        server_name=msg.get("server_name", "local"),
        tool_input=msg.get("tool_input", {}),
        tool_output=msg.get("tool_output", {}),
    )

    # 2. Add to Graph (Neo4j or Memory)
    graph.add_event(event)

    # 3. Evaluate Policies
    all_alerts = policy_engine.evaluate(graph, session_id=session_id)

    # Preserve existing triage status across re-evaluations
    if session_id in session_alerts:
        existing_alerts = {
            a.alert_id: a.triage_status for a in session_alerts[session_id]
        }
        for new_alert in all_alerts:
            if new_alert.alert_id in existing_alerts:
                new_alert.triage_status = existing_alerts[new_alert.alert_id]

    print(f"KAFKA PROCESSOR ALERTS FOR {session_id}: {all_alerts}")
    session_alerts[session_id] = all_alerts

    # Record telemetry
    GLOBAL_METRICS.total_latencies.append(time.time() - start_time)
    GLOBAL_METRICS.update_peak_memory()


@app.post("/api/sessions/{session_id}/events", response_model=EventResponse)
async def ingest_event(session_id: str, req: EventRequest):
    """
    Ingest a new MCP tool call event into a session via Kafka.
    """
    _ensure_session(session_id)

    msg = {
        "session_id": session_id,
        "tool_name": req.tool_name,
        "server_name": req.server_name,
        "tool_input": req.tool_input,
        "tool_output": req.tool_output,
    }

    await streaming_client.produce_event(session_id, msg)
    logger.debug("Event queued to Kafka for session %s", session_id)

    alerts = session_alerts.get(session_id, [])
    return EventResponse(
        call_id="async-queued",
        session_id=session_id,
        alerts_triggered=len(alerts),
        alerts=alerts,
    )


# ═══════════════════════════════════════════════════════════════════════
#  Routes — Graph
# ═══════════════════════════════════════════════════════════════════════


@app.get("/api/sessions/{session_id}/graph", response_model=GraphResponse)
async def get_session_graph(session_id: str):
    """Return the session provenance graph as nodes and edges for rendering."""
    if session_id not in session_graphs:
        raise HTTPException(
            status_code=404, detail=f"Session '{session_id}' not found."
        )

    graph = session_graphs[session_id]

    # Collect edges that are part of alert paths (call_id pairs)
    alert_edge_pairs = set()
    if session_id in session_alerts:
        for alert in session_alerts[session_id]:
            call_ids = alert.path_call_ids
            for i in range(len(call_ids) - 1):
                alert_edge_pairs.add((call_ids[i], call_ids[i + 1]))

    if hasattr(graph, "get_graph_response"):
        # Neo4j graph - get response (returns dict) and highlight alert paths
        resp = graph.get_graph_response(session_id)
        if alert_edge_pairs:
            resp["edges"] = [
                e
                for e in resp.get("edges", [])
                if (e.get("from", e.get("from_")), e.get("to")) in alert_edge_pairs
            ]
            for e in resp["edges"]:
                e["in_alert_path"] = True
        return resp

    return GraphResponse(session_id=session_id, nodes=[], edges=[])


# ═══════════════════════════════════════════════════════════════════════
#  Routes — Alerts
# ═══════════════════════════════════════════════════════════════════════


@app.get("/api/sessions/{session_id}/alerts", response_model=List[Alert])
async def get_session_alerts(session_id: str):
    """Retrieve all alerts for a session."""
    if session_id not in session_alerts:
        return []
    return session_alerts[session_id]


@app.get("/api/sessions/{session_id}/schema-mutations")
async def get_schema_mutations(session_id: str):
    """Retrieve schema mutation detections for a session (rug pull attacks)."""
    if session_id not in session_graphs:
        raise HTTPException(
            status_code=404, detail=f"Session '{session_id}' not found."
        )
    graph = session_graphs[session_id]
    if hasattr(graph, "schema_mutations"):
        return {"session_id": session_id, "mutations": graph.schema_mutations}
    return {"session_id": session_id, "mutations": []}


class TriageRequest(BaseModel):
    label: str  # 'tp' or 'fp'


import csv

from schema import FP_BUDGETS
from learning_pipeline import MIN_GLOBAL_SAMPLES

_truth_matrix_lock = threading.Lock()


@app.post("/api/alerts/{session_id}/{alert_id}/triage")
async def triage_alert(session_id: str, alert_id: str, req: TriageRequest):
    """Mark an alert as True Positive or False Positive to update precision metrics."""
    if session_id not in session_alerts:
        raise HTTPException(status_code=404, detail="Session not found")

    for alert in session_alerts[session_id]:
        if getattr(alert, "alert_id", None) == alert_id:
            if alert.triage_status == req.label:
                return {"status": "ok", "message": "Already triaged"}

            # If changing label, revert previous
            if alert.triage_status == "tp":
                GLOBAL_METRICS.tp -= 1
                _update_rule_efficacy(alert.rule, "tp", revert=True)
            elif alert.triage_status == "fp":
                GLOBAL_METRICS.fp -= 1
                _update_rule_efficacy(alert.rule, "fp", revert=True)

            alert.triage_status = req.label

            if req.label == "tp":
                GLOBAL_METRICS.tp += 1
                _update_rule_efficacy(alert.rule, "tp")
            else:
                GLOBAL_METRICS.fp += 1
                _update_rule_efficacy(alert.rule, "fp")
                FP_BUDGETS.record_fp(alert.rule)

            # --- LEARNING PIPELINE: Save to Truth Matrix ---
            csv_path = "truth_matrix.csv"
            file_exists = os.path.isfile(csv_path)

            # Determine method based on evidence string
            method = "explicit"
            if "[semantic]" in alert.evidence:
                method = "semantic"
            elif "[lexical]" in alert.evidence:
                method = "lexical"

            with _truth_matrix_lock:
                with open(csv_path, mode="a", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    if not file_exists:
                        writer.writerow(
                            [
                                "timestamp",
                                "alert_id",
                                "rule",
                                "method",
                                "confidence",
                                "evidence",
                                "label",
                            ]
                        )
                    writer.writerow(
                        [
                            time.time(),
                            alert_id,
                            alert.rule,
                            method,
                            alert.confidence,
                            alert.evidence,
                            1 if req.label == "tp" else 0,
                        ]
                    )

            # Auto-demote rule if FP budget exceeded
            demoted = policy_engine.auto_demote_rules()

            return {"status": "ok", "auto_demoted": demoted}

            raise HTTPException(status_code=404, detail="Alert not found")


def _update_rule_efficacy(rule_name: str, label: str, revert: bool = False):
    """Update rule-level efficacy tracking counts."""
    for rule in policy_engine.rules:
        if f"Matched YAML Rule: {rule.name}" == rule_name or rule.name in rule_name:
            delta = -1 if revert else 1
            if label == "tp":
                rule.efficacy.true_positives += delta
            elif label == "fp":
                rule.efficacy.false_positives += delta
            rule.efficacy.invocations += delta
            break


@app.post("/api/learn")
async def run_learning_pipeline(shadow: bool = False):
    """Execute the learning pipeline to optimize attribution thresholds."""
    import json
    import os

    try:
        # Direct import avoids subprocess overhead, preserves shared state
        from learning_pipeline import main as run_learn

        with _truth_matrix_lock:
            result = run_learn(shadow_mode=shadow)

        if result is None:
            # Check how many samples are available for a useful message
            sem = lex = 0
            if os.path.isfile("truth_matrix.csv"):
                with open("truth_matrix.csv", encoding="utf-8") as f:
                    for row in csv.DictReader(f):
                        if row["method"] == "semantic":
                            sem += 1
                        elif row["method"] == "lexical":
                            lex += 1
            return {
                "status": "ok",
                "message": f"Insufficient tunable data ({sem} semantic, {lex} lexical — need 100 total). Triage more alerts to enable tuning.",
                "thresholds": {},
                "rules_optimized": 0,
                "total_samples": sem + lex,
                "explanations": [],
            }

        if not shadow:
            policy_engine.reload_thresholds()

        meta = result.get("metadata", {})
        return {
            "status": "ok",
            "message": f"Optimized thresholds deployed (global semantic={result['_global']['semantic_threshold']:.2f}, lexical={result['_global']['lexical_threshold']:.2f})." if not shadow else "Shadow run complete — thresholds computed but not deployed.",
            "shadow_mode": shadow,
            "thresholds": result.get("_global", {}),
            "rules_optimized": len(result.get("rules", {})),
            "total_samples": meta.get("total_samples", 0),
            "explanations": meta.get("explanations", []),
        }
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Learning pipeline failed: {e}"
        )


@app.get("/api/learn/status")
async def learning_status():
    """Return the current learning pipeline status and threshold history."""
    history_file = "threshold_history.json"
    thresh_file = "optimized_thresholds.json"

    status = {
        "data_available": os.path.exists("truth_matrix.csv"),
        "thresholds_deployed": os.path.exists(thresh_file),
        "history_available": os.path.exists(history_file),
        "truth_matrix_count": 0,
        "semantic_samples": 0,
        "lexical_samples": 0,
        "explicit_samples": 0,
        "tunable_samples": 0,
        "tunable_ready": False,
        "latest_run": None,
        "history_summary": [],
    }

    if status["data_available"]:
        with open("truth_matrix.csv", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            total = 0
            for row in reader:
                total += 1
                method = row.get("method", "")
                if method == "semantic":
                    status["semantic_samples"] += 1
                elif method == "lexical":
                    status["lexical_samples"] += 1
                else:
                    status["explicit_samples"] += 1
            status["truth_matrix_count"] = total
            status["tunable_samples"] = status["semantic_samples"] + status["lexical_samples"]
            status["tunable_ready"] = status["tunable_samples"] >= MIN_GLOBAL_SAMPLES

    if status["thresholds_deployed"]:
        with open(thresh_file) as f:
            status["latest_run"] = json.load(f)

    if status["history_available"]:
        with open(history_file) as f:
            history = json.load(f)
            status["history_summary"] = [
                {"timestamp": h["timestamp"], "datetime": h.get("datetime", "unknown")}
                for h in history.get("history", [])
            ]

    return status


# ═══════════════════════════════════════════════════════════════════════
#  Routes — Metrics
# ═══════════════════════════════════════════════════════════════════════


class ConfigRequest(BaseModel):
    explicit: bool
    lexical: bool
    semantic: bool


@app.get("/api/rules")
async def get_rules():
    """Return all currently loaded YAML rules with efficacy data."""
    rules = [rule.to_dict() for rule in policy_engine.rules]
    return {"rules": rules, "efficacy_summary": policy_engine.get_efficacy_summary()}


@app.get("/api/rules/validate")
async def validate_rules():
    """Run schema validation on all loaded rules."""
    issues = policy_engine.validate_all_rules()
    return {"status": "ok", "issues": issues, "count": len(issues)}


@app.post("/api/rules/test")
async def test_rules():
    """Run all built-in test cases for all rules and pipe results into sessions/alerts/graph."""
    results = policy_engine.run_tests()
    passed = sum(1 for r in results if r.get("status") == "passed")
    failed = sum(1 for r in results if r.get("status") == "failed")

    # Pipe each test case through the real pipeline so sessions/alerts/graph get populated
    for rule in policy_engine.rules:
        if not rule.test_cases:
            continue
        for idx, tc in enumerate(rule.test_cases):
            safe_name = re.sub(r"[^a-zA-Z0-9]", "_", rule.name.lower())
            session_id = f"test-{safe_name}-{idx}"
            _ensure_session(session_id)
            for evt in tc.events:
                msg = {
                    "session_id": session_id,
                    "tool_name": evt.get("tool_name", "unknown"),
                    "server_name": evt.get("server_name", "test"),
                    "tool_input": evt.get("tool_input", {}),
                    "tool_output": evt.get("tool_output", {}),
                }
                await process_kafka_message(msg)

    return {"status": "ok", "results": results, "passed": passed, "failed": failed}


@app.get("/api/rules/test/stream")
async def test_rules_stream(request: Request):
    """SSE endpoint: runs YAML tests incrementally, populating sessions/alerts/graph in real-time."""

    async def event_stream():
        total = sum(len(r.test_cases) for r in policy_engine.rules)
        yield f"event: test_start\ndata: {json.dumps({'total': total})}\n\n"

        passed = 0
        failed = 0

        for rule in policy_engine.rules:
            if not rule.test_cases:
                continue
            for idx, tc in enumerate(rule.test_cases):
                if await request.is_disconnected():
                    yield f"event: test_aborted\ndata: {json.dumps({'passed': passed, 'failed': failed})}\n\n"
                    return

                safe_name = re.sub(r"[^a-zA-Z0-9]", "_", rule.name.lower())
                test_sid = f"test-{safe_name}-{idx}-{hashlib.md5(tc.description.encode()).hexdigest()[:8]}"

                # Step 1: Run YAML pattern test against this single rule
                pattern_status = "passed"
                try:
                    test_graph = Neo4jSessionGraph(flow_engine=None)
                    test_graph.flow_engine = FlowAttributionEngine()
                    for evt in tc.events:
                        event = Event(
                            call_id=hashlib.md5(
                                f"{evt.get('tool_name')}-{test_sid}-{time.time()}".encode()
                            ).hexdigest()[:12],
                            session_id=test_sid,
                            tool_name=evt.get("tool_name", "unknown"),
                            server_name=evt.get("server_name", "test"),
                            tool_input=evt.get("tool_input", {}),
                            tool_output=evt.get("tool_output", {}),
                            timestamp=time.time(),
                        )
                        test_graph.add_event(event)
                    old_rules = policy_engine.rules[:]
                    policy_engine.rules = [rule]
                    alerts = policy_engine._evaluate_neo4j(
                        test_graph, session_id=test_sid
                    )
                    policy_engine.rules = old_rules
                    has_alert = len(alerts) > 0
                    if has_alert != tc.expected_alert:
                        pattern_status = "failed"
                        failed += 1
                    else:
                        pattern_status = "passed"
                        passed += 1
                except Exception:
                    pattern_status = "error"
                    failed += 1

                # Step 2: Pipe through real pipeline to populate sessions/alerts/graph
                session_id = f"test-{safe_name}-{idx}"
                _ensure_session(session_id)
                for evt in tc.events:
                    msg = {
                        "session_id": session_id,
                        "tool_name": evt.get("tool_name", "unknown"),
                        "server_name": evt.get("server_name", "test"),
                        "tool_input": evt.get("tool_input", {}),
                        "tool_output": evt.get("tool_output", {}),
                    }
                    await process_kafka_message(msg)

                alert_count = len(session_alerts.get(session_id, []))

                yield f"event: test_progress\ndata: {json.dumps({'rule': rule.name, 'test': tc.description, 'pattern_status': pattern_status, 'expected_alert': tc.expected_alert, 'alert_count': alert_count, 'session_id': session_id})}\n\n"

        yield f"event: test_done\ndata: {json.dumps({'passed': passed, 'failed': failed})}\n\n"

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@app.post("/api/rules/auto-demote")
async def auto_demote_rules():
    """Demote rules exceeding FP budget."""
    demoted = policy_engine.auto_demote_rules()
    return {"status": "ok", "demoted": demoted, "count": len(demoted)}


@app.get("/api/rules/efficacy")
async def rule_efficacy():
    """Return aggregate and per-rule efficacy metrics."""
    return policy_engine.get_efficacy_summary()


class RuleUpdate(BaseModel):
    yaml_content: str


@app.put("/api/rules/{filename}")
async def update_rule(filename: str, rule_update: RuleUpdate):
    """Update or create a YAML rule file and reload the engine."""
    # Basic path traversal protection
    filename = os.path.basename(filename)
    if not filename.endswith((".yaml", ".yml")):
        filename += ".yaml"

    filepath = os.path.join("rules", filename)
    with open(filepath, "w") as f:
        f.write(rule_update.yaml_content)

    # Reload engine
    policy_engine.load_rules_from_directory("rules")
    return {"status": "Rule saved and engine reloaded", "filename": filename}


@app.post("/api/rules")
async def reload_rules():
    """Reload all rules from the rules directory."""
    policy_engine.load_rules_from_directory("rules")
    return {"status": "Rules reloaded", "count": len(policy_engine.rules)}


@app.get("/api/config")
async def get_config():
    """Get the active tiers configuration with full tier system info."""
    from flow_attribution import FlowAttributionEngine
    from schema import DEFAULT_TIERS, FP_BUDGETS

    flow_tiers = {"explicit": True, "lexical": True, "semantic": True}
    if session_graphs:
        first_graph = next(iter(session_graphs.values()))
        flow_tiers = first_graph.flow_engine.active_tiers

    def _to_json_safe(v):
        if v == float("inf"):
            return None
        return v

    return {
        "flow_engine_tiers": flow_tiers,
        "detection_tiers": {
            name: {
                "label": config.name,
                "min_efficacy": config.min_efficacy,
                "max_fp_budget_minutes": _to_json_safe(config.max_fp_budget_minutes),
                "min_mitre_coverage": config.min_mitre_coverage,
                "action": config.action.value,
                "pager_duty": config.pager_duty,
            }
            for name, config in DEFAULT_TIERS.items()
        },
        "fp_budget": {
            "per_rule": {
                rule: round(FP_BUDGETS.current_fp_budget_minutes(rule), 1)
                for rule in FP_BUDGETS.fp_counts
            },
            "analyst_cost_per_fp_minutes": 5,
        },
    }


class TierToggleRequest(BaseModel):
    tier: str
    enabled: bool


@app.post("/api/config")
async def set_config(req: TierToggleRequest):
    """Set the active tiers configuration."""
    for graph in session_graphs.values():
        if req.tier in graph.flow_engine.active_tiers:
            graph.flow_engine.active_tiers[req.tier] = req.enabled
    return {"status": "ok"}


@app.get("/api/metrics")
async def get_metrics():
    """Return global system metrics as JSON."""
    GLOBAL_METRICS.update_peak_memory()
    return GLOBAL_METRICS.to_dict()


# ═══════════════════════════════════════════════════════════════════════
#  Routes — Admin
# ═══════════════════════════════════════════════════════════════════════


@app.post("/api/reset")
async def reset_all():
    """Clear all sessions, graphs, alerts and reset metrics."""
    for graph in session_graphs.values():
        if hasattr(graph, "clear"):
            graph.clear()
    session_interceptors.clear()
    session_graphs.clear()
    session_alerts.clear()
    GLOBAL_METRICS.reset()
    GLOBAL_METRICS.start_memory_tracking()
    return {"status": "reset", "message": "All sessions and metrics cleared."}


# ═══════════════════════════════════════════════════════════════════════
#  Routes — MCP Server Registration
# ═══════════════════════════════════════════════════════════════════════


class MCPServerConfig(BaseModel):
    """Configuration for an external MCP server to monitor."""

    name: str
    url: str
    transport: str = "stdio"  # stdio | sse | streamable-http
    token: Optional[str] = None


# In-memory registry of connected MCP server configurations
mcp_server_registry: List[Dict[str, Any]] = []


@app.get("/api/mcp-servers")
async def list_mcp_servers():
    """List all registered MCP server configurations."""
    # Strip tokens from response for security
    return [{k: v for k, v in s.items() if k != "token"} for s in mcp_server_registry]


@app.post("/api/mcp-servers")
async def register_mcp_server(config: MCPServerConfig):
    """
    Register an external MCP server for monitoring.
    In the MVP, this stores the configuration for dashboard display.
    A production version would establish a proxy connection to intercept
    tool calls from this server in real-time.
    """
    # Check for duplicate names
    for existing in mcp_server_registry:
        if existing["name"] == config.name:
            raise HTTPException(
                status_code=409, detail=f"Server '{config.name}' is already registered."
            )

    entry = {
        "name": config.name,
        "url": config.url,
        "transport": config.transport,
        "token": config.token,
        "status": "connected",
    }
    mcp_server_registry.append(entry)
    logger.info(
        "Registered MCP server: %s at %s (%s)",
        config.name,
        config.url,
        config.transport,
    )
    return {
        "status": "connected",
        "message": f"Server '{config.name}' registered for monitoring.",
        "server": {k: v for k, v in entry.items() if k != "token"},
    }


@app.delete("/api/mcp-servers/{server_name}")
async def unregister_mcp_server(server_name: str):
    """Remove an MCP server from the monitoring registry."""
    for i, s in enumerate(mcp_server_registry):
        if s["name"] == server_name:
            mcp_server_registry.pop(i)
            logger.info("Unregistered MCP server: %s", server_name)
            return {
                "status": "disconnected",
                "message": f"Server '{server_name}' removed.",
            }
    raise HTTPException(status_code=404, detail=f"Server '{server_name}' not found.")


# ═══════════════════════════════════════════════════════════════════════
#  Routes — Systems (System-level monitoring onboarding)
# ═══════════════════════════════════════════════════════════════════════


class MCPServerEntry(BaseModel):
    name: str
    url: str
    transport: str = "stdio"
    token: Optional[str] = None


class SystemRegistration(BaseModel):
    name: str
    description: str = ""
    environment: str = "development"  # development | staging | production
    ip_domain: str = ""
    servers: List[MCPServerEntry] = []


# In-memory systems registry
systems_registry: Dict[str, Dict[str, Any]] = {}


@app.get("/api/systems")
async def list_systems():
    """List all registered systems with their MCP servers."""
    result = []
    for name, system in systems_registry.items():
        result.append(
            {
                "name": system["name"],
                "description": system["description"],
                "environment": system["environment"],
                "ip_domain": system["ip_domain"],
                "server_count": len(system.get("servers", [])),
                "servers": [
                    {
                        **{k: v for k, v in s.items() if k != "token"},
                        "connected": s.get("name") in _backends,
                    }
                    for s in system.get("servers", [])
                ],
            }
        )
    return result


@app.post("/api/systems")
async def register_system(config: SystemRegistration):
    """Register a system with one or more MCP servers for monitoring."""
    if config.name in systems_registry:
        raise HTTPException(
            status_code=409, detail=f"System '{config.name}' is already registered."
        )

    entry = {
        "name": config.name,
        "description": config.description,
        "environment": config.environment,
        "ip_domain": config.ip_domain,
        "servers": [s.model_dump() for s in config.servers],
    }
    systems_registry[config.name] = entry
    logger.info(
        "Registered system: %s (%s, %d servers)",
        config.name,
        config.environment,
        len(config.servers),
    )

    # Connect gateway to all MCP servers for this system
    server_configs = [s.model_dump() for s in config.servers]
    gateway_results = []
    try:
        await initialize_backends(server_configs)
        for srv in server_configs:
            sname = srv.get("name")
            gateway_results.append({
                "name": sname,
                "connected": sname in _backends,
                "url": srv.get("url"),
                "transport": srv.get("transport"),
            })
        logger.info("Gateway connected to %d/%d servers for system '%s'",
                     sum(1 for r in gateway_results if r["connected"]),
                     len(gateway_results), config.name)
    except Exception as e:
        logger.warning("Gateway backend connection failed for '%s': %s", config.name, e)

    return {
        "status": "registered",
        "message": f"System '{config.name}' registered with {len(config.servers)} MCP server(s).",
        "system": {k: v for k, v in entry.items() if k != "servers" or True},
        "gateway_connections": gateway_results,
    }


@app.get("/api/systems/{system_name}")
async def get_system(system_name: str):
    """Get details for a specific registered system."""
    if system_name not in systems_registry:
        raise HTTPException(
            status_code=404, detail=f"System '{system_name}' not found."
        )
    system = systems_registry[system_name]
    return {
        "name": system["name"],
        "description": system["description"],
        "environment": system["environment"],
        "ip_domain": system["ip_domain"],
        "servers": [
            {
                **{k: v for k, v in s.items() if k != "token"},
                "connected": s.get("name") in _backends,
            }
            for s in system.get("servers", [])
        ],
    }


@app.put("/api/systems/{system_name}")
async def update_system(system_name: str, config: SystemRegistration):
    """Update a registered system's configuration."""
    if system_name not in systems_registry:
        raise HTTPException(
            status_code=404, detail=f"System '{system_name}' not found."
        )

    entry = {
        "name": config.name,
        "description": config.description,
        "environment": config.environment,
        "ip_domain": config.ip_domain,
        "servers": [s.model_dump() for s in config.servers],
    }
    systems_registry[system_name] = entry
    logger.info(
        "Updated system: %s (%s, %d servers)",
        config.name, config.environment, len(config.servers),
    )

    server_configs = [s.model_dump() for s in config.servers]
    gateway_results = []
    try:
        await initialize_backends(server_configs)
        for srv in server_configs:
            sname = srv.get("name")
            gateway_results.append({
                "name": sname,
                "connected": sname in _backends,
                "url": srv.get("url"),
                "transport": srv.get("transport"),
            })
    except Exception as e:
        logger.warning("Gateway reconnection failed for '%s': %s", system_name, e)

    return {
        "status": "updated",
        "message": f"System '{system_name}' updated with {len(config.servers)} MCP server(s).",
        "system": {k: v for k, v in entry.items() if k != "servers" or True},
        "gateway_connections": gateway_results,
    }


@app.delete("/api/systems/{system_name}")
async def unregister_system(system_name: str):
    """Remove a registered system and all its MCP servers."""
    if system_name not in systems_registry:
        raise HTTPException(
            status_code=404, detail=f"System '{system_name}' not found."
        )
    del systems_registry[system_name]
    logger.info("Unregistered system: %s", system_name)
    return {"status": "removed", "message": f"System '{system_name}' unregistered."}


# ═══════════════════════════════════════════════════════════════════════
#  Main Entry
# ═══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
