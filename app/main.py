"""SIEM EDR Detection Engine - FastAPI 入口"""

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel
from typing import Optional, Dict, List
import os

from . import init_db, list_rules, load_rule, is_suppressed
from .detection_engine import ingest_event, list_detections, detection_stats

app = FastAPI(title="SIEM EDR Detection Engine", version="1.0.0")


@app.on_event("startup")
def _startup():
    init_db()


class EventIn(BaseModel):
    source: str              # sysmon / edr / cloud / dns
    host: str
    user: Optional[str] = None
    event_type: str          # process.create / auth.signin / network.connect / file.create / dns.query
    severity: str            # low / medium / high / critical
    raw_data: Dict           # event payload


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "siem-edr-detection",
        "rules_loaded": len(list_rules()),
    }


@app.post("/api/events")
async def ingest(event: EventIn):
    """接收事件 → 匹配 → 触发 detection"""
    result = ingest_event(
        source=event.source,
        host=event.host,
        user=event.user or "unknown",
        event_type=event.event_type,
        severity=event.severity,
        raw_data=event.raw_data,
    )
    return result


@app.get("/api/detections")
async def detections(limit: int = Query(50, ge=1, le=500)):
    return list_detections(limit=limit)


@app.get("/api/detections/stats")
async def stats():
    return detection_stats()


@app.get("/api/rules")
async def rules():
    """列所有规则"""
    return [{"rule_id": rid, "rule": load_rule(rid)} for rid in list_rules()]


@app.post("/api/suppressions")
async def add_suppression(rule_id: str, host_pattern: str = None,
                         user_pattern: str = None, reason: str = "",
                         ttl_days: Optional[int] = None):
    """加白名单"""
    from datetime import datetime, timedelta
    expires_at = None
    if ttl_days:
        expires_at = (datetime.now() + timedelta(days=ttl_days)).isoformat()

    conn = init_db()
    conn.execute("""
        INSERT INTO suppressions (rule_id, host_pattern, user_pattern, reason, created_at, expires_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (rule_id, host_pattern, user_pattern, reason,
          datetime.now().isoformat(), expires_at))
    conn.commit()
    conn.close()
    return {"rule_id": rule_id, "host_pattern": host_pattern,
            "user_pattern": user_pattern, "expires_at": expires_at}


def run():
    import uvicorn
    port = int(os.environ.get("WEB_PORT", "5020"))
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")


if __name__ == "__main__":
    run()