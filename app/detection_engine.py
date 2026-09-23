"""检测引擎 — 加载 Sigma/ATT&CK 规则 + 应用到 events"""

import json
import re
from datetime import datetime
from typing import Dict, List

from . import init_db, is_suppressed, load_rule


# 简单关键字匹配器（不引外部 Sigma parser — 文档规范是简化版）
def match_condition(condition: Dict, event: Dict) -> bool:
    """检查单个 condition 是否匹配 event"""
    field = condition["field"]
    op = condition["operator"]
    expected = condition.get("values") or condition.get("value") or condition.get("pattern")

    # 从 event 取实际值（支持嵌套字段，用 . 分隔）
    actual = event
    for part in field.split("."):
        if isinstance(actual, dict):
            actual = actual.get(part)
        else:
            return False
        if actual is None:
            return False

    if op == "equals":
        # 支持单值或列表（数组）
        if isinstance(expected, list):
            return actual in expected
        return actual == expected
    if op == "in":
        return actual in expected
    if op == "not_in":
        return actual not in expected
    if op == "contains":
        return expected in str(actual)
    if op == "contains_any":
        return any(e in str(actual) for e in expected)
    if op == "matches_regex":
        return bool(re.search(expected, str(actual), re.IGNORECASE))
    if op == "gt":
        try:
            return float(actual) > float(expected)
        except (ValueError, TypeError):
            return False

    return False


def evaluate_rule(rule: Dict, event: Dict) -> bool:
    """评估整个规则（AND 逻辑：所有 conditions 都满足）"""
    conditions = rule["detection"]["conditions"]
    return all(match_condition(c, event) for c in conditions)


def ingest_event(source: str, host: str, user: str,
                 event_type: str, severity: str, raw_data: Dict) -> int:
    """接收事件 + 入库 + 实时跑规则 + 写 detection"""
    from . import init_db
    conn = init_db()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO events (timestamp, source, host, user, event_type, severity, raw_data)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (datetime.now().isoformat(), source, host, user,
          event_type, severity, json.dumps(raw_data)))
    event_id = cur.lastrowid
    conn.commit()
    conn.close()

    # 实时跑所有规则
    from . import list_rules, load_rule, is_suppressed
    detections_made = []
    for rule_id in list_rules():
        rule = load_rule(rule_id)
        if not rule:
            continue
        # 检查抑制
        if is_suppressed(rule_id, host=host, user=user):
            continue
        # 评估规则
        if evaluate_rule(rule, raw_data):
            # 写 detection
            from . import init_db
            conn = init_db()
            conn.execute("""
                INSERT INTO detections
                    (timestamp, rule_id, rule_name, mitre_technique, severity, host, user, raw_event_id, details)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (datetime.now().isoformat(), rule_id, rule.get("name"),
                  rule.get("mitre_technique"), rule.get("severity"),
                  host, user, event_id, json.dumps({
                      "event_type": event_type,
                      "matched_conditions": [c["field"] for c in rule["detection"]["conditions"]],
                      "response": rule.get("response", {}),
                  })))
            conn.commit()
            conn.close()
            detections_made.append({
                "rule_id": rule_id,
                "rule_name": rule.get("name"),
                "severity": rule.get("severity"),
                "mitre_technique": rule.get("mitre_technique"),
            })

    return {
        "event_id": event_id,
        "detections": detections_made,
    }


def list_detections(limit: int = 50) -> List[Dict]:
    """列所有 detection"""
    conn = init_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, timestamp, rule_id, rule_name, mitre_technique, severity, host, user, details
        FROM detections ORDER BY timestamp DESC LIMIT ?
    """, (limit,))
    cols = [d[0] for d in cur.description]
    rows = [dict(zip(cols, r)) for r in cur.fetchall()]
    conn.close()
    return rows


def detection_stats() -> Dict:
    """检测统计"""
    conn = init_db()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM detections")
    total = cur.fetchone()[0]

    cur.execute("""
        SELECT severity, COUNT(*) FROM detections GROUP BY severity
    """)
    by_sev = {row[0]: row[1] for row in cur.fetchall()}

    cur.execute("""
        SELECT rule_id, COUNT(*) as cnt FROM detections
        GROUP BY rule_id ORDER BY cnt DESC LIMIT 5
    """)
    top_rules = [{"rule_id": r[0], "count": r[1]} for r in cur.fetchall()]

    conn.close()
    return {
        "total_detections": total,
        "by_severity": by_sev,
        "top_rules": top_rules,
    }