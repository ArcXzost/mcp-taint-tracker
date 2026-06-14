"""
MCP Semantic Taint Tracker — FastAPI Application Server.

Exposes REST API endpoints for streaming tool execution events,
querying session provenance graphs, retrieving security alerts,
and serving the interactive web dashboard.

Launch with:
    uvicorn app:app --reload --port 8000
"""

import os
import time
import logging
from typing import Dict, Any, List, Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from schema import Event, Alert, Severity
from mcp_interception_layer import MCPInterceptor
from session_graph import SessionGraph
import logging

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

try:
    from neo4j_graph import Neo4jSessionGraph
    # Test connection to see if docker is running
    _test = Neo4jSessionGraph()
    _test._setup_db()
    # If _setup_db succeeded without error, or we can ping...
    # Actually _setup_db catches exceptions. Let's do a direct ping.
    _test.driver.verify_connectivity()
    _test.close()
    NEO4J_AVAILABLE = True
except Exception as e:
    logger.warning(f"Neo4j is not available (Docker not running?): {e}. Falling back to NetworkX.")
    NEO4J_AVAILABLE = False
from flow_attribution import FlowAttributionEngine
from policy_engine import PolicyEngine
from taint_engine import TaintSourceEngine
from metrics import GLOBAL_METRICS
from kafka_utils import streaming_client

os.environ["HF_HUB_DISABLE_SYMLINKS_WARNING"] = "1"

# ═══════════════════════════════════════════════════════════════════════
#  Global State — Session registry & shared engine
# ═══════════════════════════════════════════════════════════════════════

flow_engine: Optional[FlowAttributionEngine] = None
policy_engine = PolicyEngine()

# Per-session stores
session_interceptors: Dict[str, MCPInterceptor] = {}
session_graphs: Dict[str, SessionGraph] = {}
session_alerts: Dict[str, List[Alert]] = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Pre-load the sentence transformer model at startup and connect Kafka."""
    global flow_engine
    logger.info("Loading FlowAttributionEngine on startup...")
    flow_engine = FlowAttributionEngine()
    GLOBAL_METRICS.start_memory_tracking()
    
    logger.info("Connecting to Kafka...")
    await streaming_client.connect_producer()
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
    edge_type: str
    evidence: str

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
        # Create graphs first to ensure they don't fail, then add interceptor
        if NEO4J_AVAILABLE:
            session_graphs[session_id] = Neo4jSessionGraph(flow_engine=flow_engine)
        else:
            session_graphs[session_id] = SessionGraph(flow_engine=flow_engine)
        
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
        summaries.append(SessionSummary(
            session_id=sid,
            event_count=len(interceptor.events),
            alert_count=len(alerts),
            node_count=len(graph.graph.nodes) if hasattr(graph, 'graph') else len(interceptor.events),
            edge_count=len(graph.graph.edges) if hasattr(graph, 'graph') else 0,
        ))
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
        existing_alerts = {a.alert_id: a.triage_status for a in session_alerts[session_id]}
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
    Ingest a new MCP tool call event into a session.
    If Kafka is connected, publishes to 'mcp-events' for async processing.
    Otherwise, processes inline.
    """
    _ensure_session(session_id)

    msg = {
        "session_id": session_id,
        "tool_name": req.tool_name,
        "server_name": req.server_name,
        "tool_input": req.tool_input,
        "tool_output": req.tool_output,
    }

    if streaming_client.is_connected:
        await streaming_client.produce_event(session_id, msg)
        return EventResponse(
            call_id="async-queued",
            session_id=session_id,
            alerts_triggered=0,
            alerts=[]
        )
    else:
        # Fallback to synchronous inline processing
        await process_kafka_message(msg)
        
        alerts = session_alerts.get(session_id, [])
        return EventResponse(
            call_id="sync-processed",
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
        raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found.")

    graph = session_graphs[session_id]
    
    if hasattr(graph, 'get_graph_response'):
        return graph.get_graph_response(session_id)
    
    # Fallback for old SessionGraph
    nodes = []
    for node_id, data in getattr(graph, 'graph', nx.DiGraph()).nodes(data=True):
        tool_name = data.get("tool_name", "unknown")
        nodes.append(GraphNode(
            id=node_id,
            label=tool_name,
            tool_name=tool_name,
            server_name=data.get("server_name", "local"),
            taint_labels=data.get("taint_labels", []),
            is_source=len(TaintSourceEngine.get_sources(tool_name)) > 0,
            is_sink=len(TaintSourceEngine.get_sinks(tool_name)) > 0,
            is_neutral=TaintSourceEngine.is_neutral(tool_name),
        ))

    edges = []
    for u, v, data in getattr(graph, 'graph', nx.DiGraph()).edges(data=True):
        edges.append(GraphEdge(
            **{"from": u, "to": v},
            confidence=data.get("confidence", 0.0),
            edge_type=data.get("edge_type", "unknown"),
            evidence=data.get("evidence", ""),
        ))

    return GraphResponse(session_id=session_id, nodes=nodes, edges=edges)


# ═══════════════════════════════════════════════════════════════════════
#  Routes — Alerts
# ═══════════════════════════════════════════════════════════════════════

@app.get("/api/sessions/{session_id}/alerts", response_model=List[Alert])
async def get_session_alerts(session_id: str):
    """Retrieve all alerts for a session."""
    if session_id not in session_alerts:
        raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found.")
    return session_alerts[session_id]


class TriageRequest(BaseModel):
    label: str  # 'tp' or 'fp'

import csv

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
            elif alert.triage_status == "fp":
                GLOBAL_METRICS.fp -= 1
                
            alert.triage_status = req.label
            
            if req.label == "tp":
                GLOBAL_METRICS.tp += 1
            else:
                GLOBAL_METRICS.fp += 1
                
            # --- LEARNING PIPELINE: Save to Truth Matrix ---
            csv_path = "truth_matrix.csv"
            file_exists = os.path.isfile(csv_path)
            
            # Determine method based on evidence string (hacky but works without refactoring graph)
            method = "explicit"
            if "[semantic]" in alert.evidence: method = "semantic"
            elif "[lexical]" in alert.evidence: method = "lexical"
                
            with open(csv_path, mode="a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                if not file_exists:
                    writer.writerow(["timestamp", "alert_id", "rule", "method", "confidence", "evidence", "label"])
                writer.writerow([
                    time.time(),
                    alert_id,
                    alert.rule,
                    method,
                    alert.confidence,
                    alert.evidence,
                    1 if req.label == "tp" else 0
                ])

            return {"status": "ok"}
            
            raise HTTPException(status_code=404, detail="Alert not found")


@app.post("/api/learn")
async def run_learning_pipeline():
    """Execute the offline learning pipeline to optimize attribution thresholds."""
    import subprocess
    import json
    import os
    
    try:
        # Run the pipeline script
        subprocess.run(["python", "learning_pipeline.py"], check=True, capture_output=True, text=True)
        
        # Read the new thresholds
        thresh_file = "optimized_thresholds.json"
        if os.path.exists(thresh_file):
            with open(thresh_file, "r") as f:
                opt = json.load(f)
                
            # Hot-reload into the policy engine!
            policy_engine.reload_thresholds()
            
            return {"status": "ok", "message": "Learning pipeline executed successfully", "thresholds": opt}
        return {"status": "ok", "message": "Learning pipeline ran but no thresholds generated (insufficient data)."}
    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=f"Learning pipeline failed: {e.stderr}")



# ═══════════════════════════════════════════════════════════════════════
#  Routes — Metrics
# ═══════════════════════════════════════════════════════════════════════

class ConfigRequest(BaseModel):
    explicit: bool
    lexical: bool
    semantic: bool

@app.get("/api/rules")
async def get_rules():
    """Return all currently loaded YAML rules."""
    rules = []
    for rule in policy_engine.rules:
        rules.append({
            "filename": getattr(rule, "filename", "unknown.yaml"),
            "name": rule.name,
            "severity": rule.severity,
            "raw_yaml": getattr(rule, "raw_yaml", "")
        })
    return {"rules": rules}

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
    """Get the active tiers configuration."""
    from flow_attribution import FlowAttributionEngine
    # The flow engine is stored in the graph, but all graphs share the same defaults in our setup, 
    # so we'll just check the current graph's engine
    if not session_graphs:
        return {"explicit": True, "lexical": True, "semantic": True}
    
    first_graph = next(iter(session_graphs.values()))
    return first_graph.flow_engine.active_tiers

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
        if hasattr(graph, 'clear'):
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
    return [
        {k: v for k, v in s.items() if k != "token"}
        for s in mcp_server_registry
    ]


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
                status_code=409,
                detail=f"Server '{config.name}' is already registered."
            )

    entry = {
        "name": config.name,
        "url": config.url,
        "transport": config.transport,
        "token": config.token,
        "status": "connected",
    }
    mcp_server_registry.append(entry)
    logger.info("Registered MCP server: %s at %s (%s)", config.name, config.url, config.transport)
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
            return {"status": "disconnected", "message": f"Server '{server_name}' removed."}
    raise HTTPException(status_code=404, detail=f"Server '{server_name}' not found.")


# ═══════════════════════════════════════════════════════════════════════
#  Main Entry
# ═══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
