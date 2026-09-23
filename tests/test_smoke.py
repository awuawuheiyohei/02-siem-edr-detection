"""smoke test"""

import sys
sys.path.insert(0, ".")

import pytest
from app import init_db, load_rule, list_rules, is_suppressed, call_llm
from app.detection_engine import match_condition, evaluate_rule


def test_rules_loaded():
    """10 个规则全部加载"""
    rules = list_rules()
    assert len(rules) == 10, f"期望 10 个规则，实际 {len(rules)}"
    expected_ids = [
        "T1003.001", "T1059.001", "T1053.005", "T1078.004", "T1070.001",
        "T1021.002", "T1490", "T1071.004", "T1562.001", "T1105",
    ]
    for rid in expected_ids:
        assert rid in rules, f"缺失规则: {rid}"


def test_rule_yaml_format():
    """每个规则 YAML 字段完整"""
    for rid in list_rules():
        rule = load_rule(rid)
        assert rule is not None, f"加载失败: {rid}"
        for field in ["id", "name", "mitre_technique", "severity", "detection"]:
            assert field in rule, f"{rid} 缺字段: {field}"
        assert rule["severity"] in ["low", "medium", "high", "critical"], \
            f"{rid} severity 非法: {rule['severity']}"


def test_match_condition_equals():
    cond = {"field": "process.name", "operator": "equals", "values": ["mimikatz.exe"]}
    assert match_condition(cond, {"process": {"name": "mimikatz.exe"}}) == True
    assert match_condition(cond, {"process": {"name": "notepad.exe"}}) == False


def test_match_condition_contains_any():
    cond = {"field": "process.command_line", "operator": "contains_any",
            "values": ["sekurlsa", "logonpasswords"]}
    event = {"process": {"command_line": "mimikatz.exe sekurlsa::logonpasswords"}}
    assert match_condition(cond, event) == True


def test_match_condition_regex():
    cond = {"field": "process.command_line", "operator": "matches_regex",
            "pattern": "(?i)wevtutil.*(cl|clear)"}
    event = {"process": {"command_line": "wevtutil cl Security"}}
    assert match_condition(cond, event) == True


def test_evaluate_rule_lsass():
    """完整规则评估（mimikatz）"""
    rule = load_rule("T1003.001")
    event = {
        "process": {"name": "mimikatz.exe",
                   "command_line": "mimikatz.exe sekurlsa::logonpasswords"}
    }
    assert evaluate_rule(rule, event) == True


def test_evaluate_rule_no_match():
    """合法 PowerShell 不应触发"""
    rule = load_rule("T1003.001")
    event = {"process": {"name": "powershell.exe", "command_line": "Get-Service"}}
    assert evaluate_rule(rule, event) == False


def test_suppression_logic():
    """白名单抑制"""
    from datetime import datetime
    from app import init_db
    conn = init_db()

    # 加白名单
    conn.execute("""
        INSERT INTO suppressions (rule_id, host_pattern, user_pattern, reason, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, ("T1003.001", "WS-IT-*", "admin@*", "known admin host", datetime.now().isoformat()))
    conn.commit()
    conn.close()

    # 检查 — 应被抑制
    assert is_suppressed("T1003.001", host="WS-IT-0099", user="admin@knorr-bremse.com") == True

    # 不同 host — 不应被抑制
    assert is_suppressed("T1003.001", host="WS-FINANCE-0142", user="zhang.wei@knorr-bremse.com") == False