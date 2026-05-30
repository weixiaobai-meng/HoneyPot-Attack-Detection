# 数据汇聚 + 因果图构建 + Graph-to-Text 模块

## 功能说明

本模块实现毕设系统的前三步：
1. **数据汇聚** - 汇聚三种蜜点告警数据 + audit系统调用日志
2. **因果图构建** - 将告警转换为 Subject→Action→Object 有向因果图
3. **Graph-to-Text** - 将因果图转换为LLM提示词

## 数据源

| 数据源 | 来源 | 数据格式 |
|--------|------|----------|
| 文件蜜点 | alert_server SQLite数据库 | TriggerInfo |
| 账户蜜点 | ssh-vpn JSON日志 | SSH/VPN登录记录 |
| 寄生蜜点 | agent-go url_alert.json | URL访问记录 |
| audit日志 | agent-go日志目录 | 系统调用事件 |

## 使用方法

### 1. 演示模式（推荐先运行）

```bash
cd data_collector
python main.py demo
```

### 2. 实际数据汇聚

```bash
# 收集最近24小时所有数据源
python main.py collect --hours 24 --output output/unified_alerts.json

# 只收集特定数据源
python main.py collect --source file --hours 48
python main.py collect --source account --hours 12

# 按IP聚合分析
python main.py collect --aggregate
```

### 3. 构建因果图

```bash
# 从告警数据构建因果图
python main.py graph --input output/unified_alerts.json --output output/causal_graph.json

# 输出Mermaid格式
python main.py graph --input output/unified_alerts.json --format mermaid --output output/causal_graph.mmd

# 筛选特定IP的子图
python main.py graph --ip 192.168.1.100
```

### 4. Graph-to-Text转换

```bash
# 生成意图分析提示词
python main.py text --input output/pruned_graph.json --task intent_analysis

# 生成TTP映射提示词
python main.py text --input output/pruned_graph.json --task ttp_mapping --output output/llm_prompt_ttp.txt

# 生成事件报告提示词
python main.py text --input output/pruned_graph.json --task report --output output/llm_prompt_report.txt

# 生成原始叙述文本
python main.py text --input output/pruned_graph.json --task raw --output output/narrative.txt
```

## 输出文件

```
output/
├── unified_alerts.json       # 统一告警数据
├── causal_graph.json         # 因果图JSON
├── causal_graph.mmd          # Mermaid格式
├── pruned_graph.json         # DQN裁剪后的图
├── llm_prompt.txt            # 意图分析提示词
├── llm_prompt_ttp.txt        # TTP映射提示词
└── llm_prompt_report.txt     # 事件报告提示词
```

## Graph-to-Text 输出示例

### 意图分析提示词

```
你是一个资深网络安全威胁溯源专家。请根据以下Graph-to-Text还原的因果行为文本，分析攻击者的意图。

## 一、攻击事件概述

本次攻击事件涉及 11 个实体节点和 9 个攻击行为。

**涉及实体：**
- 网络地址: 4 个
- 文件: 4 个
- 进程: 3 个

**攻击行为：**
- 尝试SSH登录: 2 次
- 访问文件: 2 次
- ...

## 二、攻击时间线

[10:00:30] **步骤1：** 网络地址 192.168.1.100 尝试SSH登录 网络地址 192.168.1.20
[10:05:00] **步骤2：** 网络地址 192.168.1.100 访问文件 文件 /home/admin/passwords.xlsx
...

请严格按照以下步骤进行分析：
1. 原子动作分析
2. 战术阶段推导
3. 战略意图研判
4. 防御建议
```

## 目录结构

```
data_collector/
├── models.py           # 统一数据模型
├── adapters.py         # 各数据源适配器
├── collector.py        # 数据汇聚器
├── causal_graph.py     # 因果图构建器
├── graph_to_text.py    # Graph-to-Text转换器
├── config.py           # 配置文件
├── main.py             # 主入口
├── README.md           # 说明文档
└── output/             # 输出目录
```

## 后续步骤

| 步骤 | 内容 | 状态 |
|------|------|------|
| 1 | 汇聚三种蜜点的告警数据 | ✅ |
| 2 | 构建因果溯源图 | ✅ |
| 3 | 使用DQN进行图谱裁剪 | ✅ |
| 4 | Graph-to-Text转换 | ✅ |
| 5 | LLM攻击意图推理 | 待实现 |
