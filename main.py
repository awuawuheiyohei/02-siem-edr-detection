"""CLI: serve / simulate / rules / suppress"""

import argparse
import os
import sys


def cmd_serve(args):
    from app.main import run
    run()


def cmd_simulate(args):
    """模拟原子攻击样本，验证规则触发"""
    import requests
    port = os.environ.get("WEB_PORT", "5020")
    sys.path.insert(0, ".")
    from simulate_attacks import (
        attack_lsass_dump, attack_psexec_lateral, attack_shadow_delete,
        attack_log_clear, attack_defender_disable, attack_certutil,
        attack_dns_tunnel, attack_powershell_download,
    )

    attack_map = {
        "lsass": attack_lsass_dump,
        "psexec": attack_psexec_lateral,
        "shadow": attack_shadow_delete,
        "logclear": attack_log_clear,
        "defender": attack_defender_disable,
        "certutil": attack_certutil,
        "dns": attack_dns_tunnel,
        "powershell": attack_powershell_download,
    }

    attack = args.attack
    if attack not in attack_map:
        print(f"❌ Unknown attack: {attack}")
        print(f"   可选: {list(attack_map.keys())}")
        sys.exit(1)

    event = attack_map[attack]()
    print(f"🎯 模拟攻击: {attack}")
    print(f"   Host: {event['host']}")
    print(f"   User: {event['user']}")
    print(f"   Event type: {event['event_type']}")
    print(f"   Raw: {event['raw_data']}")
    print()

    try:
        resp = requests.post(f"http://localhost:{port}/api/events", json=event, timeout=30)
        resp.raise_for_status()
        result = resp.json()
        print(f"✅ Event ID: {result['event_id']}")
        print(f"   触发规则数: {len(result['detections'])}")
        for d in result["detections"]:
            sev = d["severity"].upper()
            mitre = d.get("mitre_technique", "?")
            print(f"   - [{sev}] {d['rule_id']} ({mitre}) {d['rule_name']}")
    except requests.exceptions.ConnectionError:
        print(f"❌ FastAPI 未启动。先跑: python main.py serve (端口 {port})")
        sys.exit(1)


def cmd_rules(args):
    """列所有规则"""
    from app import list_rules, load_rule
    for rid in list_rules():
        rule = load_rule(rid)
        if rule:
            print(f"### {rid}: {rule['name']} [{rule['severity'].upper()}]")
            print(f"   {rule.get('mitre_technique', '?')} | {rule.get('mitre_tactic', '?')}")


def cmd_stats(args):
    """统计"""
    import requests
    port = os.environ.get("WEB_PORT", "5020")
    try:
        resp = requests.get(f"http://localhost:{port}/api/detections/stats", timeout=10)
        resp.raise_for_status()
        import json
        print(json.dumps(resp.json(), indent=2, ensure_ascii=False))
    except requests.exceptions.ConnectionError:
        print("❌ FastAPI 未启动")


def cmd_detections(args):
    """列所有 detection"""
    import requests
    port = os.environ.get("WEB_PORT", "5020")
    try:
        resp = requests.get(f"http://localhost:{port}/api/detections?limit={args.limit}", timeout=10)
        resp.raise_for_status()
        detections = resp.json()
        if not detections:
            print("暂无 detection")
            return
        print(f"# 最近 {len(detections)} 条 Detection\n")
        for d in detections:
            sev = d['severity'].upper()
            print(f"- **[{sev}]** `{d['rule_id']}` {d['rule_name']}")
            print(f"  - Host: {d['host']} | User: {d['user']}")
            print(f"  - MITRE: {d.get('mitre_technique', '?')}")
            print(f"  - 时间: {d['timestamp']}")
            print()
    except requests.exceptions.ConnectionError:
        print("❌ FastAPI 未启动")


def main():
    parser = argparse.ArgumentParser(description="SIEM EDR Detection CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("serve", help="启动 FastAPI")

    p = sub.add_parser("simulate", help="模拟原子攻击")
    p.add_argument("attack", choices=["lsass", "psexec", "shadow", "logclear",
                                     "defender", "certutil", "dns", "powershell"])

    p = sub.add_parser("rules", help="列所有规则")
    p = sub.add_parser("stats", help="detection 统计")
    p = sub.add_parser("detections", help="列 detection")
    p.add_argument("--limit", type=int, default=20)

    args = parser.parse_args()
    dispatch = {
        "serve": cmd_serve,
        "simulate": cmd_simulate,
        "rules": cmd_rules,
        "stats": cmd_stats,
        "detections": cmd_detections,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()