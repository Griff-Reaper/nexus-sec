"""
Nexus-Sec API Server
FastAPI wrapper around the multi-agent orchestrator.
Exposes REST endpoints + WebSocket for the React dashboard.
"""

import asyncio
import json
import re
import random
from datetime import datetime
from typing import Optional
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# --- Import your existing orchestrator ---
# Adjust this import path if needed based on where server.py lives
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from nexus_sec.orchestrator import Orchestrator

app = FastAPI(title="Nexus-Sec API", version="2.0.0")

# Allow React dev server to talk to this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global orchestrator instance
orchestrator: Optional[Orchestrator] = None

# Active WebSocket connections
active_connections: list[WebSocket] = []

# In-memory threat event log (last 100 events)
threat_log: list[dict] = []


# ─────────────────────────────────────────────
# MODELS
# ─────────────────────────────────────────────

class QueryRequest(BaseModel):
    query: str


class ThreatEvent(BaseModel):
    indicator: str
    indicator_type: str
    threat_level: str
    score: int
    details: str
    timestamp: str

class HoneypotIngest(BaseModel):
    source: str
    session_id: str
    threat_score: int
    threat_level: str
    techniques: list[str] = []
    mitre_tags: list[str] = []
    sophistication: str = "unknown"
    objectives: list[str] = []
    summary: str = ""
    honeytokens: list[dict] = []
    correlation: dict = {}
    message_count: int = 0
    conversation: list[dict] = []

class RedTeamIngest(BaseModel):
    source: str = "red-team"
    session_id: str
    technique_id: str
    technique_name: str
    severity: str
    target: str
    attack_prompt: str
    response: str
    impact_score: int
    success: bool
    timestamp: str

class FirewallIngest(BaseModel):
    source: str = "prompt-firewall"
    session_id: str
    original_prompt: str
    action: str
    threat_score: float
    threat_level: str
    sanitized_prompt: Optional[str] = None
    timestamp: str


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def extract_threat_score(response_text: str) -> int:
    """
    Parse a numerical threat score (0-100) from agent response text.
    Looks for patterns like 'risk score: 85' or 'score: 72/100'.
    Falls back to keyword-based heuristic if no number found.
    """
    # Try to find explicit score in response
    patterns = [
        r'risk score[:\s]+(\d+)',
        r'threat score[:\s]+(\d+)',
        r'score[:\s]+(\d+)\s*/\s*100',
        r'severity[:\s]+(\d+)',
        r'\b(\d{1,3})%\s*confidence',
    ]
    for pattern in patterns:
        match = re.search(pattern, response_text.lower())
        if match:
            val = int(match.group(1))
            return min(val, 100)

    # Heuristic keyword fallback
    text_lower = response_text.lower()
    if any(w in text_lower for w in ["critical", "ransomware", "apt", "c2", "command and control"]):
        return random.randint(80, 95)
    if any(w in text_lower for w in ["malicious", "phishing", "tor", "botnet"]):
        return random.randint(60, 80)
    if any(w in text_lower for w in ["suspicious", "anomalous", "unusual"]):
        return random.randint(35, 60)
    if any(w in text_lower for w in ["benign", "safe", "clean", "legitimate"]):
        return random.randint(0, 15)
    return random.randint(20, 45)


def score_to_threat_level(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 35:
        return "MEDIUM"
    if score >= 15:
        return "LOW"
    return "CLEAN"


async def broadcast(event: dict):
    """Send an event to all connected WebSocket clients."""
    dead = []
    for ws in active_connections:
        try:
            await ws.send_text(json.dumps(event))
        except Exception:
            dead.append(ws)
    for ws in dead:
        active_connections.remove(ws)


# ─────────────────────────────────────────────
# STARTUP
# ─────────────────────────────────────────────

@app.on_event("startup")
async def startup():
    global orchestrator
    try:
        orchestrator = Orchestrator(verbose=False)
        print("✓ Nexus-Sec Orchestrator initialized")
    except Exception as e:
        print(f"✗ Failed to initialize orchestrator: {e}")


# ─────────────────────────────────────────────
# REST ENDPOINTS
# ─────────────────────────────────────────────

@app.get("/health")
async def health():
    return {
        "status": "online",
        "orchestrator": orchestrator is not None,
        "timestamp": datetime.utcnow().isoformat()
    }


@app.get("/agents")
async def list_agents():
    if not orchestrator:
        return {"agents": []}
    agents = []
    for name, agent in orchestrator.agents.items():
        agents.append({"name": agent.name, "role": agent.role})
    return {"agents": agents}


@app.get("/threats/log")
async def get_threat_log(limit: int = 50):
    return {"events": threat_log[-limit:]}


@app.post("/query")
async def query(request: QueryRequest):
    if not orchestrator:
        return {"error": "Orchestrator not initialized", "success": False}

    result = orchestrator.process_request(request.query)
    score = extract_threat_score(result.get("response", ""))
    level = score_to_threat_level(score)

    event = {
        "type": "threat_event",
        "indicator": request.query,
        "threat_level": level,
        "score": score,
        "agent": result.get("agent", "Unknown"),
        "response": result.get("response", ""),
        "timestamp": datetime.utcnow().isoformat()
    }

    # Store in log
    threat_log.append(event)
    if len(threat_log) > 100:
        threat_log.pop(0)

    # Push to all dashboard clients
    await broadcast(event)

    return event


# ─────────────────────────────────────────────
# INGEST ENDPOINTS
# ─────────────────────────────────────────────

@app.post("/honeypot/ingest")
async def ingest_honeypot(payload: HoneypotIngest):
    query = (
        f"Analyze ARIA honeypot session. Threat score: {payload.threat_score} "
        f"({payload.threat_level}). Techniques: {', '.join(payload.techniques) or 'none'}. "
        f"MITRE: {', '.join(payload.mitre_tags) or 'none'}. "
        f"Sophistication: {payload.sophistication}. Summary: {payload.summary}"
    )
    result = orchestrator.process_request(query) if orchestrator else {"response": "Orchestrator offline"}

    event = {
        "type": "honeypot_ingest",
        "source": payload.source,
        "session_id": payload.session_id,
        "threat_score": payload.threat_score,
        "threat_level": payload.threat_level,
        "techniques": payload.techniques,
        "mitre_tags": payload.mitre_tags,
        "nexus_analysis": result.get("response", ""),
        "timestamp": datetime.utcnow().isoformat()
    }
    threat_log.append(event)
    if len(threat_log) > 100:
        threat_log.pop(0)
    await broadcast(event)
    return {"status": "ingested", "session_id": payload.session_id, "nexus_analysis": result.get("response", "")}


@app.post("/redteam/ingest")
async def ingest_redteam(payload: RedTeamIngest):
    query = (
        f"Red team result: {payload.technique_id} ({payload.technique_name}), "
        f"severity {payload.severity}, impact {payload.impact_score}/100. "
        f"{'Succeeded' if payload.success else 'Blocked'}. Target: {payload.target}. "
        f"Prompt: {payload.attack_prompt[:200]}"
    )
    result = orchestrator.process_request(query) if orchestrator else {"response": "Orchestrator offline"}

    event = {
        "type": "redteam_ingest",
        "source": payload.source,
        "session_id": payload.session_id,
        "technique_id": payload.technique_id,
        "severity": payload.severity,
        "impact_score": payload.impact_score,
        "success": payload.success,
        "nexus_analysis": result.get("response", ""),
        "timestamp": datetime.utcnow().isoformat()
    }
    threat_log.append(event)
    if len(threat_log) > 100:
        threat_log.pop(0)
    await broadcast(event)
    return {"status": "ingested", "session_id": payload.session_id}


@app.post("/firewall/ingest")
async def ingest_firewall(payload: FirewallIngest):
    query = (
        f"Prompt firewall event: action={payload.action}, "
        f"threat_score={payload.threat_score}, level={payload.threat_level}. "
        f"Prompt: {payload.original_prompt[:200]}"
    )
    result = orchestrator.process_request(query) if orchestrator else {"response": "Orchestrator offline"}

    event = {
        "type": "firewall_ingest",
        "source": payload.source,
        "session_id": payload.session_id,
        "action": payload.action,
        "threat_score": payload.threat_score,
        "threat_level": payload.threat_level,
        "nexus_analysis": result.get("response", ""),
        "timestamp": datetime.utcnow().isoformat()
    }
    threat_log.append(event)
    if len(threat_log) > 100:
        threat_log.pop(0)
    await broadcast(event)
    return {"status": "ingested", "session_id": payload.session_id}


# ─────────────────────────────────────────────
# WEBSOCKET — Live Threat Feed
# ─────────────────────────────────────────────

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_connections.append(websocket)

    # Send last 10 events on connect so dashboard isn't empty
    await websocket.send_text(json.dumps({
        "type": "history",
        "events": threat_log[-10:]
    }))

    try:
        while True:
            # Keep connection alive — client can also send queries via WS
            data = await websocket.receive_text()
            msg = json.loads(data)

            if msg.get("type") == "query" and orchestrator:
                result = orchestrator.process_request(msg["query"])
                score = extract_threat_score(result.get("response", ""))
                level = score_to_threat_level(score)

                event = {
                    "type": "threat_event",
                    "indicator": msg["query"],
                    "threat_level": level,
                    "score": score,
                    "agent": result.get("agent", "Unknown"),
                    "response": result.get("response", ""),
                    "timestamp": datetime.utcnow().isoformat()
                }

                threat_log.append(event)
                await broadcast(event)

            elif msg.get("type") == "ping":
                await websocket.send_text(json.dumps({"type": "pong"}))

    except WebSocketDisconnect:
        active_connections.remove(websocket)


# ─────────────────────────────────────────────
# RUN
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True)