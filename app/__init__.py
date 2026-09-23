"""SIEM EDR Detection Engineering - core"""

import os
import re
import sqlite3
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, List, Dict

import requests

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
DATA_DIR.mkdir(exist_ok=True)
DB_PATH = DATA_DIR / "detections.db"
RULES_DIR = ROOT / "rules"

LLM_API_KEY = os.environ.get("LLM_API_KEY", "")
LLM_BASE_URL = os.environ.get("LLM_BASE_URL", "https://api.MiniMax.chat/v1")
LLM_MODEL = os.environ.get("LLM_MODEL", "MiniMax-M3")
LLM_TEMPERATURE = float(os.environ.get("LLM_TEMPERATURE", "0.3"))


def init_db() -> sqlite3.Connection:
    """初始化 SQLite（events / detections / suppressions）"""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source TEXT,           -- sysmon / edr / cloud / dns
            host TEXT,
            user TEXT,
            event_type TEXT,        -- process / network / file / registry / auth
            severity TEXT,          -- low / medium / high / critical
            raw_data TEXT           -- JSON / 原始 log
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp DESC)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_host ON events(host)")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS detections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            rule_name TEXT,
            mitre_technique TEXT,   -- e.g. T1003.001
            severity TEXT,
            host TEXT,
            user TEXT,
            raw_event_id INTEGER,
            details TEXT,
            FOREIGN KEY (raw_event_id) REFERENCES events(id)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_detections_ts ON detections(timestamp DESC)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_detections_rule ON detections(rule_id)")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS suppressions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_id TEXT NOT NULL,
            host_pattern TEXT,
            user_pattern TEXT,
            reason TEXT,             -- 白名单原因（known admin / scheduled task / etc）
            created_at TEXT NOT NULL,
            expires_at TEXT          -- NULL 表示永久
        )
    """)
    conn.commit()
    return conn


def strip_thinking(content: str) -> str:
    """Strip LLM thinking blocks"""
    content = re.sub(r"<think>.*?</think>\s*", "", content, flags=re.DOTALL)
    content = re.sub(r"<think>.*$", "", content, flags=re.DOTALL)
    for m in [r"^OK final structure:.*$", r"^OK let me (write|think).*$",
              r"^Actually[, ].*$", r"^Wait[, ].*$"]:
        if match := re.search(m, content, flags=re.MULTILINE):
            content = content[:match.start()].rstrip() + "\n"
            break
    return content.strip() + "\n"


def call_llm(system_prompt: str, user_prompt: str,
             api_key: str = None, base_url: str = None, model: str = None,
             temperature: float = None, max_tokens: int = 4000) -> str:
    """OpenAI-compatible chat completion API"""
    api_key = api_key or LLM_API_KEY
    if not api_key:
        raise ValueError("LLM_API_KEY 未配置")
    base_url = base_url or LLM_BASE_URL
    model = model or LLM_MODEL
    temperature = temperature if temperature is not None else LLM_TEMPERATURE

    url = f"{base_url.rstrip('/')}/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": model,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
    }

    resp = requests.post(url, headers=headers, json=payload, timeout=300)
    if resp.status_code != 200:
        raise RuntimeError(f"LLM 调用失败 ({resp.status_code}):\n{resp.text[:1000]}")
    return strip_thinking(resp.json()["choices"][0]["message"]["content"])


def is_suppressed(rule_id: str, host: str = None, user: str = None) -> bool:
    """检查 detection 是否被白名单抑制"""
    from datetime import datetime
    conn = init_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT host_pattern, user_pattern, expires_at FROM suppressions
        WHERE rule_id = ?
    """, (rule_id,))
    for hp, up, exp in cur.fetchall():
        # 检查 host pattern
        if hp and host:
            import fnmatch
            if not fnmatch.fnmatch(host, hp):
                continue
        if up and user:
            import fnmatch
            if not fnmatch.fnmatch(user, up):
                continue
        # 检查 expiry
        if exp and datetime.fromisoformat(exp) < datetime.now():
            continue
        conn.close()
        return True
    conn.close()
    return False


def load_rule(rule_id: str) -> Optional[Dict]:
    """加载 YAML 规则"""
    path = RULES_DIR / f"{rule_id}.yaml"
    if not path.exists():
        return None
    try:
        import yaml
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def list_rules() -> List[str]:
    """列所有规则 ID"""
    if not RULES_DIR.exists():
        return []
    return [p.stem for p in RULES_DIR.glob("*.yaml")]