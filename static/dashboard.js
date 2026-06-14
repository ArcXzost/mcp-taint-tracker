let currentSessionId = null;
let pollingInterval = null;
const API_BASE = "http://127.0.0.1:8000";

window.GRAPH_DATA = { nodes: new vis.DataSet(), edges: new vis.DataSet(), events: {} };
let network = null;

document.addEventListener("DOMContentLoaded", async () => {
    await initSimulations();
    await loadConfig();
    startPolling();

    const container = document.getElementById("graph-panel");
    const data = { nodes: window.GRAPH_DATA.nodes, edges: window.GRAPH_DATA.edges };
    const options = getGraphOptions();
    network = new vis.Network(container, data, options);

    network.on("doubleClick", function (params) {
        if (params.nodes.length > 0) {
            const nodeId = params.nodes[0];
            const event = window.GRAPH_DATA.events[nodeId];
            if (event) console.log("Node details:", event);
        }
    });
});

function startPolling() {
    if (pollingInterval) clearInterval(pollingInterval);
    pollingInterval = setInterval(() => {
        refreshSystems();
        refreshSessions();
        refreshMetrics();
        if (currentSessionId) {
            refreshGraph(currentSessionId);
            refreshAlerts(currentSessionId);
        }
    }, 3000);
    refreshSystems();
    refreshSessions();
    refreshMetrics();
}

// ═══════════════════════════════════════════════════════════════════════
//  Systems
// ═══════════════════════════════════════════════════════════════════════

async function refreshSystems() {
    try {
        const res = await fetch(`${API_BASE}/api/systems`);
        const systems = await res.json();
        renderSystemsList(systems);
    } catch (e) {
        console.error("Systems fetch error:", e);
    }
}

function renderSystemsList(systems) {
    const container = document.getElementById("systems-list");
    if (!systems || systems.length === 0) {
        container.innerHTML = '<div class="text-xs font-mono text-outline-variant py-2 text-center">No systems registered</div>';
        return;
    }
    container.innerHTML = systems.map(s => {
        const envColors = { development: "bg-amber-100 text-amber-800 border-amber-300", staging: "bg-blue-100 text-blue-800 border-blue-300", production: "bg-green-100 text-green-800 border-green-300" };
        const envColor = envColors[s.environment] || "bg-gray-100 text-gray-800 border-gray-300";
        return `
            <div class="p-2 bg-surface border-[1.5px] border-outline rounded-lg">
                <div class="flex items-center justify-between mb-1">
                    <span class="font-bold text-xs truncate">${s.name}</span>
                    <span class="px-1.5 py-0.5 text-[9px] font-mono border rounded-full ${envColor}">${s.environment}</span>
                </div>
                <div class="flex items-center gap-2 text-[10px] font-mono text-muted">
                    <span>${s.server_count} server${s.server_count !== 1 ? 's' : ''}</span>
                    ${s.ip_domain ? `<span>• ${s.ip_domain}</span>` : ''}
                </div>
            </div>
        `;
    }).join("");
}

let systemModalInstance = null;

function openSystemModal() {
    const modalEl = document.getElementById('system-modal');
    if (!systemModalInstance) {
        systemModalInstance = new Modal(modalEl);
        document.querySelector('#system-modal [data-modal-hide="system-modal"]').addEventListener('click', () => systemModalInstance.hide());
    }
    systemModalInstance.show();
}

function addServerField() {
    const container = document.getElementById('servers-list');
    const entry = document.createElement('div');
    entry.className = 'server-entry p-3 bg-surface-dim border-[1.5px] border-outline-variant rounded-lg';
    entry.innerHTML = `
        <div class="grid grid-cols-2 gap-2">
            <input type="text" class="srv-name text-xs bg-surface border-[1.5px] border-outline rounded p-1.5 font-mono" placeholder="name" />
            <input type="text" class="srv-url text-xs bg-surface border-[1.5px] border-outline rounded p-1.5 font-mono" placeholder="url" />
        </div>
        <div class="grid grid-cols-2 gap-2 mt-2">
            <select class="srv-transport text-xs bg-surface border-[1.5px] border-outline rounded p-1.5 font-mono">
                <option value="stdio">stdio</option>
                <option value="sse">sse</option>
                <option value="streamable-http">streamable-http</option>
            </select>
            <button type="button" onclick="this.closest('.server-entry').remove()" class="text-xs py-1 border-[1.5px] border-error text-error rounded-full hover:bg-error-container transition-all">Remove</button>
        </div>
    `;
    container.appendChild(entry);
}

async function registerSystem() {
    const name = document.getElementById("sys-name").value.trim();
    if (!name) {
        showToast("System name is required.", "error");
        return;
    }
    const servers = [];
    document.querySelectorAll('.server-entry').forEach(entry => {
        const sname = entry.querySelector('.srv-name').value.trim();
        const url = entry.querySelector('.srv-url').value.trim();
        const transport = entry.querySelector('.srv-transport').value;
        if (sname && url) {
            servers.push({ name: sname, url: url, transport: transport });
        }
    });
    if (servers.length === 0) {
        showToast("At least one MCP server is required.", "error");
        return;
    }
    try {
        const res = await fetch(`${API_BASE}/api/systems`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                name: name,
                description: document.getElementById("sys-description").value.trim(),
                environment: document.getElementById("sys-environment").value,
                ip_domain: document.getElementById("sys-ip-domain").value.trim(),
                servers: servers
            })
        });
        if (res.ok) {
            showToast(`System "${name}" registered!`, "success");
            if (systemModalInstance) systemModalInstance.hide();
            await refreshSystems();
        } else {
            const err = await res.json();
            showToast(err.detail || "Failed to register system.", "error");
        }
    } catch (e) {
        showToast("Error registering system.", "error");
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Sessions
// ═══════════════════════════════════════════════════════════════════════

async function refreshSessions() {
    try {
        const res = await fetch(`${API_BASE}/api/sessions`);
        const sessions = await res.json();
        renderSessionList(sessions);
    } catch (e) {
        setStatus("Disconnected", false);
    }
}

function renderSessionList(sessions) {
    setStatus("Connected", true);
    const container = document.getElementById("session-list");

    if (!sessions || sessions.length === 0) {
        container.innerHTML = `
            <div class="flex flex-col items-center justify-center py-6 text-outline-variant">
                <span class="mt-2 text-xs font-mono">No active sessions</span>
            </div>`;
        return;
    }

    container.innerHTML = sessions.map(s => {
        const isActive = s.session_id === currentSessionId;
        const shortId = s.session_id.startsWith("sim-") ? s.session_id.substring(4, 12) : s.session_id.substring(0, 8);
        const alertLabel = s.alert_count > 0 ? `${s.alert_count} Alert${s.alert_count > 1 ? 's' : ''}` : "Clean";
        const badgeColor = s.alert_count > 0 ? "bg-error text-error-on border-error" : "bg-green-100 text-green-800 border-green-300";
        const activeClass = isActive ? "shadow-stack bg-surface-dim" : "shadow-none hover:bg-surface-dim";
        
        return `
            <div class="p-2 bg-surface border-[1.5px] border-outline rounded-lg cursor-pointer transition-all ${activeClass}" 
                 onclick="selectSession('${s.session_id}')">
                <div class="flex justify-between items-center mb-1">
                    <span class="font-mono text-xs font-bold truncate pr-2">${shortId}</span>
                    <span class="px-1.5 py-0.5 text-[9px] font-mono border ${badgeColor} rounded-full whitespace-nowrap">${alertLabel}</span>
                </div>
                <div class="flex justify-between items-center text-[10px] text-outline-variant font-mono">
                    <span>${s.node_count} nodes / ${s.edge_count} edges</span>
                </div>
            </div>
        `;
    }).join("");
}

function selectSession(sessionId) {
    if (currentSessionId !== sessionId) {
        hasCenteredInitially = false;
        window.GRAPH_DATA.nodes.clear();
        window.GRAPH_DATA.edges.clear();
        window.GRAPH_DATA.events = {};
    }
    currentSessionId = sessionId;
    refreshGraph(sessionId);
    refreshAlerts(sessionId);
    refreshSessions();
}

// ═══════════════════════════════════════════════════════════════════════
//  Graph
// ═══════════════════════════════════════════════════════════════════════

let isAutoLayout = true;

function toggleLayout() {
    isAutoLayout = !isAutoLayout;
    const btn = document.getElementById("btn-layout");
    if (isAutoLayout) {
        btn.textContent = "Auto Layout: ON";
        network.setOptions({ physics: { enabled: true } });
    } else {
        btn.textContent = "Auto Layout: OFF";
        network.setOptions({ physics: { enabled: false } });
    }
}

function centerGraph() {
    if (network) {
        network.fit({ animation: { duration: 500, easingFunction: "easeInOutQuad" } });
    }
}

function getGraphOptions() {
    return {
        nodes: {
            shape: 'box',
            borderWidth: 1.5,
            borderWidthSelected: 2,
            color: {
                border: '#000000',
                background: '#ffffff',
                highlight: { border: '#df9367', background: '#fff8ef' }
            },
            font: { color: '#000000', face: '"JetBrains Mono", monospace', size: 12 },
            margin: { top: 8, right: 12, bottom: 8, left: 12 },
            shapeProperties: { borderRadius: 4 }
        },
        edges: {
            width: 1.5,
            color: { color: '#000000', highlight: '#df9367' },
            arrows: { to: { enabled: true, scaleFactor: 0.8, type: 'arrow' } },
            smooth: { type: 'cubicBezier', forceDirection: 'horizontal', roundness: 0.4 },
            font: { color: '#4a4a4a', size: 10, face: '"JetBrains Mono", monospace', align: 'horizontal' }
        },
        layout: {
            randomSeed: 2
        },
        physics: { enabled: false },
        interaction: { hover: true, tooltipDelay: 200 }
    };
}

async function refreshGraph(sessionId) {
    try {
        const res = await fetch(`${API_BASE}/api/sessions/${sessionId}/graph`);
        if (!res.ok) return;
        const graphData = await res.json();
        renderGraph(graphData);
    } catch (e) {
        console.error("Failed to fetch graph:", e);
    }
}

let hasCenteredInitially = false;

function renderGraph(graphData) {
    if (!graphData || !graphData.nodes) return;

    const newNodes = [];
    graphData.nodes.forEach(n => {
        window.GRAPH_DATA.events[n.id] = n.event;
        const hasTaints = n.taint_labels && n.taint_labels.length > 0;
        
        let label = `${n.tool_name}\n`;
        label += `[${n.server_name}]`;
        
        let title = `ID: ${n.id}\nServer: ${n.server_name}\nTime: ${new Date(n.timestamp * 1000).toLocaleTimeString()}`;
        if (hasTaints) {
            title += `\nTaints: ${n.taint_labels.join(', ')}`;
        }
        
        newNodes.push({
            id: n.id,
            label: label,
            title: title,
            color: {
                border: hasTaints ? '#d32f2f' : '#000000',
                background: hasTaints ? '#ffebee' : '#ffffff'
            }
        });
    });

    const newEdges = [];
    const methodColors = { explicit: '#a3a3a3', lexical: '#f59e0b', semantic: '#ef4444', memory: '#8b5cf6' };
    graphData.edges.forEach(e => {
        const color = methodColors[e.method] || '#a3a3a3';
        newEdges.push({
            id: `${e.from}-${e.to}`,
            from: e.from,
            to: e.to,
            label: `${(e.confidence * 100).toFixed(0)}% [${e.method}]`,
            title: `Method: ${e.method}\nConfidence: ${(e.confidence * 100).toFixed(0)}%\nEvidence: ${e.evidence}`,
            color: { color: color },
            dashes: e.in_alert_path ? false : true,
            width: e.in_alert_path ? 2.5 : 0.8
        });
    });

    window.GRAPH_DATA.nodes.update(newNodes);
    window.GRAPH_DATA.edges.update(newEdges);

    if (!hasCenteredInitially && newNodes.length > 0) {
        centerGraph();
        hasCenteredInitially = true;
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Alerts
// ═══════════════════════════════════════════════════════════════════════

async function refreshAlerts(sessionId) {
    try {
        const res = await fetch(`${API_BASE}/api/sessions/${sessionId}/alerts`);
        if (!res.ok) return;
        const alerts = await res.json();
        renderAlerts(alerts);
    } catch (e) {
        console.error("Failed to fetch alerts:", e);
    }
}

function renderAlerts(alerts) {
    const container = document.getElementById("alert-feed");

    if (!alerts || alerts.length === 0) {
        container.innerHTML = '<div class="text-sm font-mono text-outline-variant">No alerts</div>';
        return;
    }

    container.innerHTML = alerts.map(a => {
        const isTP = a.triage_status === "tp";
        const isFP = a.triage_status === "fp";
        const tpClass = isTP ? "bg-primary text-primary-on" : "bg-surface hover:bg-surface-dim";
        const fpClass = isFP ? "bg-error text-error-on" : "bg-surface hover:bg-surface-dim";
        const borderClass = isTP ? "border-primary" : (isFP ? "border-error" : "border-outline-variant");

        return `
            <div class="p-4 bg-surface border-[1.5px] ${borderClass} rounded-xl shadow-card transition-all">
                <div class="flex items-center justify-between mb-2">
                    <span class="flex items-center gap-1">
                        <span class="px-2 py-0.5 text-[10px] font-mono rounded-full bg-error-container text-error-onContainer border border-error uppercase">${a.severity}</span>
                        <span class="px-2 py-0.5 text-[10px] font-mono rounded-full bg-amber-100 text-amber-800 border border-amber-300">${a.recommended_tier}</span>
                    </span>
                    <span class="text-xs font-mono text-outline-variant">${(a.confidence * 100).toFixed(0)}%</span>
                </div>
                <h4 class="font-bold text-sm mb-1">${a.rule}</h4>
                <div class="text-xs font-mono text-outline-variant mb-2">${a.violation}</div>
                <div class="text-xs font-mono text-outline-variant mb-3">${a.source_node} → ${a.sink_node}</div>
                
                ${a.mitre_techniques.length > 0 ? `<div class="text-[10px] font-mono text-outline-variant mb-2">MITRE: ${a.mitre_techniques.join(', ')}</div>` : ''}
                
                <div class="flex gap-2 w-full">
                    <button onclick="triageAlert('${a.alert_id}', 'tp')" class="flex-1 text-xs py-1.5 border-[1.5px] border-outline rounded-full font-semibold transition-colors ${tpClass}">TP</button>
                    <button onclick="triageAlert('${a.alert_id}', 'fp')" class="flex-1 text-xs py-1.5 border-[1.5px] border-outline rounded-full font-semibold transition-colors ${fpClass}">FP</button>
                    <button onclick="openAlertDetails('${a.alert_id}')" class="flex-1 text-xs py-1.5 border-[1.5px] border-outline rounded-full font-semibold bg-surface hover:bg-surface-dim transition-colors">Details</button>
                </div>
            </div>
        `;
    }).join("");
}

async function triageAlert(alertId, label) {
    if (!currentSessionId) return;
    try {
        const res = await fetch(`${API_BASE}/api/alerts/${currentSessionId}/${alertId}/triage`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ label })
        });
        if (res.ok) {
            showToast(`Alert marked as ${label.toUpperCase()}`, "success");
            await refreshAlerts(currentSessionId);
            await refreshMetrics();
        } else {
            showToast(`Failed to triage alert`, "error");
        }
    } catch (e) {
        console.error("Triage error:", e);
    }
}

let alertDetailsModalInstance = null;

async function openAlertDetails(alertId) {
    try {
        const res = await fetch(`${API_BASE}/api/sessions/${currentSessionId}/alerts`);
        const alerts = await res.json();
        const alert = alerts.find(a => a.alert_id === alertId);
        if (!alert) return;

        const srcEvent = window.GRAPH_DATA.events[alert.source_call_id] || { tool_input: "Not loaded", tool_output: "Not loaded" };
        const sinkEvent = window.GRAPH_DATA.events[alert.sink_call_id] || { tool_input: "Not loaded", tool_output: "Not loaded" };

        const content = document.getElementById('alert-details-content');
        content.innerHTML = `
            <div class="grid grid-cols-3 gap-4 mb-4">
                <div class="p-3 bg-surface-dim border-[1.5px] border-outline-variant rounded-xl">
                    <div class="text-[10px] font-mono tracking-widest uppercase text-outline-variant mb-1">Violation</div>
                    <div class="font-bold text-sm">${alert.violation}</div>
                </div>
                <div class="p-3 bg-surface-dim border-[1.5px] border-outline-variant rounded-xl">
                    <div class="text-[10px] font-mono tracking-widest uppercase text-outline-variant mb-1">Matched Rule</div>
                    <div class="font-bold text-sm">${alert.rule}</div>
                </div>
                <div class="p-3 bg-surface-dim border-[1.5px] border-outline-variant rounded-xl">
                    <div class="text-[10px] font-mono tracking-widest uppercase text-outline-variant mb-1">Recommended Tier</div>
                    <div class="font-bold text-sm">${alert.recommended_tier}</div>
                </div>
            </div>
            
            ${alert.mitre_techniques.length > 0 ? `
            <div class="p-3 bg-surface-dim border-[1.5px] border-outline-variant rounded-xl mb-4">
                <div class="text-[10px] font-mono tracking-widest uppercase text-outline-variant mb-2">MITRE ATT&CK</div>
                <div class="font-mono text-sm">${alert.mitre_techniques.join(', ')}</div>
            </div>` : ''}
            
            <div class="p-3 bg-surface-dim border-[1.5px] border-outline-variant rounded-xl mb-4">
                <div class="text-[10px] font-mono tracking-widest uppercase text-outline-variant mb-2">Execution Path</div>
                <div class="font-mono text-sm">${alert.path.join(' ➔ ')}</div>
            </div>

            <div class="p-3 bg-surface-dim border-[1.5px] border-outline-variant rounded-xl mb-4">
                <div class="text-[10px] font-mono tracking-widest uppercase text-outline-variant mb-2">Flow Evidence</div>
                <div class="font-mono text-sm whitespace-pre-wrap">${alert.evidence}</div>
            </div>

            <div class="grid grid-cols-2 gap-4">
                <div class="flex flex-col gap-2">
                    <div class="font-bold text-sm flex items-center gap-2">
                        <span class="w-2 h-2 rounded-full bg-error"></span> Source: ${alert.source_node}
                    </div>
                    <div class="bg-primary text-primary-on p-3 rounded-xl border border-outline font-mono text-xs overflow-x-auto">
                        <div class="text-outline-variant mb-1">// Input</div>
                        <pre>${JSON.stringify(srcEvent.tool_input, null, 2)}</pre>
                        <div class="text-outline-variant mt-2 mb-1">// Output</div>
                        <pre>${JSON.stringify(srcEvent.tool_output, null, 2)}</pre>
                    </div>
                </div>
                <div class="flex flex-col gap-2">
                    <div class="font-bold text-sm flex items-center gap-2">
                        <span class="w-2 h-2 rounded-full bg-error"></span> Sink: ${alert.sink_node}
                    </div>
                    <div class="bg-primary text-primary-on p-3 rounded-xl border border-outline font-mono text-xs overflow-x-auto">
                        <div class="text-outline-variant mb-1">// Input</div>
                        <pre>${JSON.stringify(sinkEvent.tool_input, null, 2)}</pre>
                        <div class="text-outline-variant mt-2 mb-1">// Output</div>
                        <pre>${JSON.stringify(sinkEvent.tool_output, null, 2)}</pre>
                    </div>
                </div>
            </div>
        `;

        const modalEl = document.getElementById('alert-details-modal');
        if (!alertDetailsModalInstance) {
            alertDetailsModalInstance = new Modal(modalEl);
            document.querySelector('#alert-details-modal [data-modal-hide="alert-details-modal"]').addEventListener('click', () => alertDetailsModalInstance.hide());
        }
        alertDetailsModalInstance.show();
    } catch (e) {
        console.error("Error opening details:", e);
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Metrics
// ═══════════════════════════════════════════════════════════════════════

async function refreshMetrics() {
    try {
        const res = await fetch(`${API_BASE}/api/metrics`);
        if (!res.ok) return;
        const m = await res.json();
        renderMetrics(m);
    } catch (e) { /* silent */ }
}

function renderMetrics(m) {
    document.getElementById("m-precision").textContent = (m.detection.precision * 100).toFixed(0) + '%';
    document.getElementById("m-recall").textContent = (m.detection.recall * 100).toFixed(0) + '%';
    document.getElementById("m-f1").textContent = (m.detection.f1_score * 100).toFixed(0) + '%';
    document.getElementById("m-fpr").textContent = (m.detection.false_positive_rate * 100).toFixed(0) + '%';

    if(document.getElementById("m-p50")) {
        document.getElementById("m-p50").textContent = m.runtime.p50_latency_ms.toFixed(1) + 'ms';
        document.getElementById("m-p95").textContent = m.runtime.p95_latency_ms.toFixed(1) + 'ms';
        document.getElementById("m-memory").textContent = m.runtime.peak_memory_mb.toFixed(0) + 'MB';
        document.getElementById("m-attr-cost").textContent = m.runtime.attribution_overhead_pct.toFixed(1) + '%';
        
        document.getElementById("m-explicit").textContent = m.attribution.explicit_detections;
        document.getElementById("m-lexical").textContent = m.attribution.lexical_detections;
        document.getElementById("m-semantic").textContent = m.attribution.semantic_detections;
        document.getElementById("m-confidence").textContent = (m.attribution.avg_confidence * 100).toFixed(0) + '%';
    }
}

function setStatus(text, isGreen) {
    document.getElementById("status-text").textContent = text;
    const dot = document.getElementById("status-dot");
    dot.className = `w-2.5 h-2.5 rounded-full animate-pulse ${isGreen ? 'bg-secondary' : 'bg-outline-variant'}`;
}

// ═══════════════════════════════════════════════════════════════════════
//  Config & Detection Tiers
// ═══════════════════════════════════════════════════════════════════════

async function loadConfig() {
    try {
        const res = await fetch(`${API_BASE}/api/config`);
        const conf = await res.json();
        
        // Flow engine tiers
        const f = conf.flow_engine_tiers || conf;
        if (document.getElementById("tier-explicit")) {
            document.getElementById("tier-explicit").checked = f.explicit !== false;
            document.getElementById("tier-lexical").checked = f.lexical !== false;
            document.getElementById("tier-semantic").checked = f.semantic !== false;
        }
        
        // Detection tiers (P0-P3)
        renderDetectionTiers(conf.detection_tiers, conf.fp_budget);
    } catch (e) {
        console.error("Config load error:", e);
    }
}

function renderDetectionTiers(tiers, fpBudget) {
    const container = document.getElementById("detection-tiers-list");
    if (!tiers) {
        container.innerHTML = '<div class="text-xs text-muted">Loading...</div>';
        return;
    }
    container.innerHTML = Object.entries(tiers).map(([key, tier]) => `
        <div class="flex items-center justify-between py-1 border-b border-outline-variant last:border-0">
            <span class="font-bold text-xs">${key}</span>
            <span class="text-[10px]">${(tier.min_efficacy * 100).toFixed(0)}% eff • ${tier.max_fp_budget_minutes === Infinity ? '∞' : tier.max_fp_budget_minutes + 'm'} FP</span>
        </div>
    `).join("");
}

async function toggleTier(tier, enabled) {
    try {
        await fetch(`${API_BASE}/api/config`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ tier: tier, enabled: enabled })
        });
    } catch (e) {
        console.error("Tier toggle error:", e);
    }
}

async function runLearningPipeline() {
    const btn = document.getElementById("btn-learn");
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = `<svg class="animate-spin" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2v20"/><path d="M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"/></svg> Tuning...`;
    }
    try {
        const res = await fetch(`${API_BASE}/api/learn`, { method: "POST" });
        const data = await res.json();
        if (!res.ok) {
            showToast("Learning pipeline failed.", "error");
        } else {
            showToast("Successfully optimized AI thresholds.", "success");
        }
    } catch (e) {
        showToast("Error executing learning pipeline.", "error");
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2v20"/><path d="M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"/></svg> Tune`;
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Simulations
// ═══════════════════════════════════════════════════════════════════════

let simulationsData = [];

async function initSimulations() {
    try {
        const res = await fetch('/static/simulations.json');
        simulationsData = await res.json();
        const dropdown = document.getElementById("sim-dropdown");
        dropdown.innerHTML = '<option value="" disabled selected>Select a simulation...</option>';
        simulationsData.forEach((sim, index) => {
            const opt = document.createElement("option");
            opt.value = index;
            opt.textContent = sim.name;
            dropdown.appendChild(opt);
        });
    } catch (e) {
        console.error("Failed to load simulations:", e);
    }
}

async function resetDashboard() {
    if (!confirm("Are you sure you want to clear all graph data, alerts, and sessions?")) return;
    try {
        await fetch(`${API_BASE}/api/reset`, { method: "POST" });
        showToast("Dashboard data cleared successfully.", "success");
        currentSessionId = null;
        if (network) {
            window.GRAPH_DATA.nodes.clear();
            window.GRAPH_DATA.edges.clear();
            window.GRAPH_DATA.events = {};
        }
        await refreshSessions();
        await refreshMetrics();
    } catch (e) {
        showToast("Failed to reset dashboard.", "error");
    }
}

async function runSimulation() {
    const dropdown = document.getElementById("sim-dropdown");
    const selectedIndex = dropdown.value;
    if (selectedIndex === "") {
        showToast("Please select a simulation first.", "error");
        return;
    }

    const sim = simulationsData[selectedIndex];
    const btn = document.getElementById("btn-simulate");
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = `Running...`;
    }

    const simTimestamp = Date.now().toString(36);
    const sessionId = "sim-" + simTimestamp;
    showToast(`Starting: ${sim.name}`, "info");

    for (let i = 0; i < sim.events.length; i++) {
        try {
            await fetch(`${API_BASE}/api/sessions/${sessionId}/events`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(sim.events[i]),
            });
        } catch (e) {
            console.error("Event injection error:", e);
        }
        await new Promise(r => setTimeout(r, 600));
    }

    showToast("Simulation complete.", "success");
    if (btn) {
        btn.disabled = false;
        btn.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><polygon points="6,3 20,12 6,21"/></svg> Run`;
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Toasts
// ═══════════════════════════════════════════════════════════════════════

function showToast(message, type = "info") {
    const container = document.getElementById("toast-container");
    const toast = document.createElement("div");
    
    let icon = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>`;
    let colorClass = "bg-primary text-primary-on border-[1.5px] border-outline shadow-card";
    
    if (type === "success") {
        icon = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>`;
        colorClass = "bg-green-100 text-green-800 border-[1.5px] border-green-300 shadow-card";
    } else if (type === "error") {
        icon = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`;
        colorClass = "bg-error text-error-on border-[1.5px] border-error shadow-card";
    }

    toast.className = `flex items-center gap-3 w-full max-w-xs p-4 rounded-xl ${colorClass} font-mono text-sm opacity-0 transition-opacity duration-300`;
    toast.innerHTML = `${icon} <div class="font-medium">${message}</div>`;
    
    container.appendChild(toast);
    
    requestAnimationFrame(() => {
        toast.classList.remove("opacity-0");
        toast.classList.add("opacity-100");
    });

    setTimeout(() => {
        toast.classList.remove("opacity-100");
        toast.classList.add("opacity-0");
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

// ═══════════════════════════════════════════════════════════════════════
//  YAML Rules Editor
// ═══════════════════════════════════════════════════════════════════════

let currentRules = [];
let activeRuleFilename = null;

let rulesModalInstance = null;

async function openRulesModal() {
    await fetchRules();
    const modalEl = document.getElementById('rules-modal');
    if (!rulesModalInstance) {
        rulesModalInstance = new Modal(modalEl);
        document.querySelector('#rules-modal [data-modal-hide="rules-modal"]').addEventListener('click', () => rulesModalInstance.hide());
    }
    rulesModalInstance.show();
}

async function fetchRules() {
    try {
        const res = await fetch(`${API_BASE}/api/rules`);
        if (!res.ok) throw new Error("Failed to fetch rules");
        const data = await res.json();
        currentRules = data.rules || [];
        renderRulesList();
        
        // Show efficacy summary
        if (data.efficacy_summary) {
            document.getElementById('rule-filename-display').textContent = 
                `${data.efficacy_summary.rules_loaded} rules • ${data.efficacy_summary.rules_with_tests} with tests`;
        }
    } catch (e) {
        showToast("Error loading rules", "error");
    }
}

function renderRulesList() {
    const list = document.getElementById('rules-list');
    list.innerHTML = currentRules.map(r => `
        <div onclick="selectRule('${r.filename}')" class="p-3 bg-surface border-[1.5px] border-outline-variant rounded-xl cursor-pointer hover:bg-surface-dim transition-all ${activeRuleFilename === r.filename ? 'shadow-stack bg-surface-dim' : ''}">
            <div class="flex items-center justify-between mb-1">
                <span class="font-bold text-sm truncate">${r.name}</span>
                <span class="px-2 py-0.5 text-[9px] font-mono rounded-full border border-error bg-error-container text-error-onContainer uppercase">${r.severity}</span>
            </div>
            <div class="text-[10px] font-mono text-outline-variant truncate mb-1">${r.filename}</div>
            <div class="flex items-center gap-2 text-[9px] font-mono text-muted">
                ${r.schema_version ? `<span class="px-1 py-0.5 bg-surface border border-outline-variant rounded">v${r.schema_version}</span>` : ''}
                ${r.mitre_techniques && r.mitre_techniques.length > 0 ? `<span>${r.mitre_techniques.join(', ')}</span>` : ''}
                ${r.test_count !== undefined ? `<span>${r.test_count} tests</span>` : ''}
            </div>
            ${r.description ? `<div class="text-[10px] font-mono text-muted mt-1 truncate">${r.description}</div>` : ''}
        </div>
    `).join("");
}

function selectRule(filename) {
    activeRuleFilename = filename;
    const rule = currentRules.find(r => r.filename === filename);
    if (rule) {
        document.getElementById('rule-filename-display').textContent = filename;
        document.getElementById('rule-editor').value = rule.raw_yaml;
        document.getElementById('btn-save-rule').classList.remove('hidden');
        document.getElementById('btn-save-rule').classList.add('flex');
        
        // Show metadata
        const metaContainer = document.getElementById('rule-metadata-display');
        metaContainer.innerHTML = `
            ${rule.schema_version ? `<span class="px-1.5 py-0.5 bg-surface border border-outline rounded">v${rule.schema_version}</span>` : ''}
            ${rule.mitre_techniques && rule.mitre_techniques.length > 0 ? `<span>${rule.mitre_techniques.join(', ')}</span>` : ''}
            ${rule.test_count !== undefined ? `<span>${rule.test_count} tests</span>` : ''}
        `;
    }
    renderRulesList();
}

function createNewRule() {
    activeRuleFilename = `custom_rule_${Date.now()}.yaml`;
    document.getElementById('rule-filename-display').textContent = activeRuleFilename;
    document.getElementById('rule-editor').value = `schema_version: 2
name: "New Custom Rule"
severity: "MEDIUM"
description: ""
mitre_techniques: []
pattern:
  source:
    taints: []
  path:
    max_hops: 3
    requires_taint: true
  sink:
    tools: []
test:
  positive: []
  negative: []
`;
    document.getElementById('btn-save-rule').classList.remove('hidden');
    document.getElementById('btn-save-rule').classList.add('flex');
    document.getElementById('rule-metadata-display').innerHTML = '<span class="px-1.5 py-0.5 bg-surface border border-outline rounded">v2</span><span>0 tests</span>';
    renderRulesList();
}

async function saveCurrentRule() {
    const yamlContent = document.getElementById('rule-editor').value;
    if (!activeRuleFilename) return;

    try {
        const res = await fetch(`${API_BASE}/api/rules/${activeRuleFilename}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ yaml_content: yamlContent })
        });
        
        if (res.ok) {
            showToast("Rule saved & compiled!", "success");
            await fetchRules();
        } else {
            showToast("Failed to save rule.", "error");
        }
    } catch (e) {
        showToast("Error saving rule.", "error");
    }
}

async function testAllRules() {
    const toast = showToast("Connecting test stream...", "info");
    const btn = document.getElementById("btn-run-tests");
    if (btn) btn.disabled = true;

    let processed = 0;
    let total = 0;
    let passed = 0;
    let failed = 0;

    const es = new EventSource(`${API_BASE}/api/rules/test/stream`);

    es.addEventListener('test_start', (e) => {
        const data = JSON.parse(e.data);
        total = data.total;
        showToast(`Running YAML tests (0/${total})...`, "info");
    });

    es.addEventListener('test_progress', (e) => {
        const data = JSON.parse(e.data);
        processed++;
        if (data.pattern_status === "passed") {
            showToast(`[${processed}/${total}] PASS: ${data.rule} - ${data.test}`, "success");
        } else {
            showToast(`[${processed}/${total}] FAIL: ${data.rule} - ${data.test}`, "error");
        }
        // Refresh session list so new test session appears
        refreshSessions();
    });

    es.addEventListener('test_done', (e) => {
        const data = JSON.parse(e.data);
        es.close();
        if (btn) btn.disabled = false;
        showToast(`Tests complete: ${data.passed} passed, ${data.failed} failed`, data.failed > 0 ? "error" : "success");
        // Auto-select first test session
        fetch(`${API_BASE}/api/sessions`).then(r => r.json()).then(sessions => {
            renderSessionList(sessions);
            const ts = sessions.find(s => s.session_id.startsWith("test-"));
            if (ts) selectSession(ts.session_id);
        });
    });

    es.addEventListener('test_aborted', (e) => {
        es.close();
        if (btn) btn.disabled = false;
        showToast("Test stream aborted.", "error");
    });

    es.onerror = () => {
        es.close();
        if (btn) btn.disabled = false;
        showToast("Test stream connection lost.", "error");
    };
}
