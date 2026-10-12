# 02 SIEM EDR Detection Engineering

> **一句话**：Mac 本地 Sigma/ATT&CK 检测引擎——10+ 条核心规则 + MITRE 技术映射 + 降噪白名单 + 模拟攻击样本验证。
> 对齐 **Senior Cyber Security Analyst** 岗位核心能力（Threat Hunting / Detection Engineering）。

---

## ✨ 核心特性

- **10 个核心 Sigma/ATT&CK 规则**（覆盖 Credential Access / Execution / Persistence / Initial Access / Defense Evasion / Lateral Movement / Impact / C&C）
- **简化版 Sigma 匹配器**（关键字 / 正则 / in 列表 — 不依赖完整 Sigma 解析器）
- **MITRE 技术自动映射**（T1003.001 等）
- **降噪白名单**（host_pattern / user_pattern / TTL）
- **原子攻击样本**（8 种攻击模拟 + 1 种 benign 场景，验证规则）
- **响应动作自动建议**（每个规则带 response.immediate_actions）

---

## 🏗 架构

```
[攻击样本 / 真实 EDR]
        ↓ event JSON
[FastAPI /api/events]
        ↓
[Detection Engine]
   ├─ 加载 10 个 YAML 规则
   ├─ 对每个事件: AND 评估 conditions
   ├─ 抑制检查: 白名单命中跳过
   └─ 写 detection + raw_event 关联
        ↓
[SQLite]
   ├─ events（原始事件）
   ├─ detections（命中规则）
   └─ suppressions（白名单）
        ↓
[REST API]
   ├─ /api/events       → POST 接收事件
   ├─ /api/detections   → 列命中
   ├─ /api/detections/stats
   ├─ /api/rules        → 列出所有规则
   └─ /api/suppressions → 加白名单
```

---

## 🚀 快速开始

```bash
cd /Users/jiangwenrui/Downloads/mass/02-siem-edr-detection
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

cp .env.example .env  # 编辑填 LLM key（可选）
```

### 启动 FastAPI（端口 5020）

```bash
WEB_PORT=5020 python main.py serve
# 浏览器: http://localhost:5020/docs
```

### 跑 8 种原子攻击模拟

```bash
# 1. LSASS 内存转储（T1003.001 - critical）
WEB_PORT=5020 python main.py simulate lsass

# 2. PsExec 横向移动（T1021.002 - critical）
WEB_PORT=5020 python main.py simulate psexec

# 3. 阴影副本删除（T1490 - critical）
WEB_PORT=5020 python main.py simulate shadow

# 4. 日志清除（T1070.001 - critical）
WEB_PORT=5020 python main.py simulate logclear

# 5. Defender 关闭（T1562.001 - critical）
WEB_PORT=5020 python main.py simulate defender

# 6. Certutil LOLBIN（T1105 - high）
WEB_PORT=5020 python main.py simulate certutil

# 7. DNS 隧道（T1071.004 - high）
WEB_PORT=5020 python main.py simulate dns

# 8. PowerShell 远程下载（T1059.001 - high）
WEB_PORT=5020 python main.py simulate powershell

# 9. Benign（不应触发任何规则 — false positive 验证）
WEB_PORT=5020 python main.py simulate benign
```

### 查 Detection + 统计

```bash
WEB_PORT=5020 python main.py detections --limit 20
WEB_PORT=5020 python main.py stats
WEB_PORT=5020 python main.py rules
```

---

## 📁 项目结构

```
02-siem-edr-detection/
├── README.md
├── pyproject.toml
├── .env.example
├── .gitignore
├── main.py                       # CLI 入口
├── simulate_attacks.py           # 8+1 种攻击模拟
├── app/
│   ├── __init__.py               # init_db + call_llm + strip_thinking + is_suppressed + load_rule
│   ├── detection_engine.py       # 规则匹配 + 抑制
│   └── main.py                   # FastAPI
├── rules/
│   ├── README.md
│   ├── T1003.001.yaml            # LSASS 内存转储
│   ├── T1059.001.yaml            # PowerShell 远程下载
│   ├── T1053.005.yaml            # 计划任务持久化
│   ├── T1078.004.yaml            # 云身份异常登录
│   ├── T1070.001.yaml            # 日志清除
│   ├── T1021.002.yaml            # PsExec 横向移动
│   ├── T1490.yaml                # 阴影副本删除
│   ├── T1071.004.yaml            # DNS 隧道
│   ├── T1562.001.yaml            # Defender 关闭
│   └── T1105.yaml                # Certutil LOLBIN
└── tests/
    └── test_smoke.py
```

---

## 📊 10 个 Sigma/ATT&CK 规则

| Rule | Tactic | Name | Severity |
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

---

## 🚫 反模式（不要做的）

- ❌ **不要在生产环境关闭抑制**（即使 false positive 多）：永远保留白名单
- ❌ **不要改 critical → low** 来"减少告警疲劳"：改 false positive 检测逻辑，不改 severity
- ❌ **不要用正则过宽**：`(?i)powershell` 会触发所有 PowerShell 调用
- ❌ **不要 skip 5 Whys**：每个新规则上线前必须问 5 次"为什么"防止误报
- ❌ **不要 hardcode 凭证**：用环境变量 / Vault

---

## 🎯 v1.0 验收

- [x] 10 个 YAML 规则完整（MITRE 映射 + 严重程度 + 响应动作）
- [x] 简化版 Sigma 匹配器（keyword / regex / in）
- [x] 抑制引擎（host / user pattern + TTL）
- [x] FastAPI 4 端点
- [x] 8+1 种原子攻击模拟
- [ ] **真实跑 1 周无 bug**

---

## 📝 来源

本项目基于 `/Users/jiangwenrui/Downloads/mass/25-Interview/Security_and_GRC_14_Projects_Plan/02_SIEM_EDR_Detection_Engineering.md` 完整规划落地。

---

## 📄 License

MIT — 自由使用、修改、二次分发。