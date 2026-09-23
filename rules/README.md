# Sigma / ATT&CK Detection Rules

10 个核心检测规则，覆盖 MITRE ATT&CK 战术：
- 凭据访问 (TA0006)
- 执行 (TA0002)
- 持久化 (TA0003)
- 初始访问 (TA0001)
- 防御逃逸 (TA0005)
- 横向移动 (TA0008)
- 影响 (TA0040)
- C&C (TA0011)

## 规则清单

| Rule ID | Technique | Name | Severity |
|---|---|---|---|
| T1003.001 | TA0006 | LSASS 内存转储窃取凭据 | critical |
| T1059.001 | TA0002 | PowerShell 远程恶意脚本混淆下载 | high |
| T1053.005 | TA0003 | 恶意持久化计划任务创建 | high |
| T1078.004 | TA0001 | 云身份凭据异常地理位置或非工作时间访问 | high |
| T1070.001 | TA0005 | Windows 安全审计日志被刻意清除 | critical |
| T1021.002 | TA0008 | SMB / PsExec 横向移动远程服务执行 | critical |
| T1490 | TA0040 | 系统阴影副本删除与勒索阻断恢复 | critical |
| T1071.004 | TA0011 | 可疑 DNS 隧道与数据隐蔽外传 | high |
| T1562.001 | TA0005 | 终端防御被禁用与 Defender 服务关闭 | critical |
| T1105 | TA0011 | 原生工具 Certutil 异常远程下载 | high |

## YAML 字段规范

每个规则文件包含：
- `id`: MITRE technique ID
- `name`: 人类可读名称
- `mitre_technique`: 完整 MITRE ID
- `mitre_tactic`: 战术分类
- `severity`: critical / high / medium / low
- `description`: 检测目的说明
- `detection`: 检测条件（conditions 列表）
- `false_positives`: 已知误报场景
- `suppression_hint`: 白名单抑制指引
- `severity_rationale`: 为什么这个 severity
- `response`: 触发后的响应动作

## 加载机制

检测引擎通过 `app.load_rule(rule_id)` 加载 YAML：
```python
from app import load_rule
rule = load_rule("T1003.001")
# rule['severity'] == 'critical'
# rule['detection']['conditions'] 是条件列表
```