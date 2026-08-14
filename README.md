# 基于蜜点技术的APT攻击检测与意图推理系统

## 快速开始

### 1. 一键部署

```bash
cd deployment
python auto_deploy.py
```

### 2. 启动服务

```bash
# 启动管理端
cd ../systemwire2 && python app.py

# 或使用启动脚本
deployment/scripts/start_systemwire2.bat
```

### 3. 访问管理界面

打开浏览器访问: http://localhost:5001

### 4. 运行实验

```bash
cd ..
python run_experiment.py
```

## 目录结构

```
研究生毕设/
│
├── deployment/                     # ⭐ 部署管理
│   ├── auto_deploy.py              # 一键部署脚本
│   ├── deploy_manager.py           # 告警收集
│   ├── scripts/                    # 启动脚本
│   └── output/                     # 告警数据
│
├── systemwire2/                    # 管理端
├── agent-go/                       # 探针
├── alert_server/                   # 告警服务
├── ssh-vpn/                        # SSH蜜罐
│
├── step1_data_collection/          # 数据汇聚
├── step2_causal_graph/             # 因果图构建
├── step3_dqn_pruning/              # DQN裁剪
├── step4_graph_to_text/            # Graph-to-Text
│
├── run_experiment.py               # 端到端实验
└── main.py                         # 分步运行
```

## 部署流程

```
┌─────────────────────────────────────────────────────────────┐
│  步骤1: 一键部署                                            │
│  $ python deployment/auto_deploy.py                         │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  步骤2: 启动服务                                            │
│  $ cd systemwire2 && python app.py                          │
│  访问 http://localhost:5001                                 │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  步骤3: 部署蜜点                                            │
│  通过Web界面部署文件/账户/寄生蜜点                          │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  步骤4: 收集告警                                            │
│  $ python deployment/deploy_manager.py collect              │
│  $ python deployment/deploy_manager.py export               │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  步骤5: 运行分析                                            │
│  $ python run_experiment.py                                 │
└─────────────────────────────────────────────────────────────┘
```

## 数据流

```
deployment/ (组件+告警)
    │
    ▼ collected_alerts.json
step1_data_collection/output/
    │
    ▼ unified_alerts.json
step2_causal_graph/output/
    │
    ▼ causal_graph.json
step3_dqn_pruning/output/
    │
    ▼ pruned_graph.json
step4_graph_to_text/output/
    │
    ▼ llm_prompt_*.txt
LLM推理 → 攻击意图分析
```

## 实验结果

正式结果尚未生成。只有通过独立场景划分、双人标注、数据校验和完整基准测试的
`experiments/results/` 输出可以用于论文或答辩；历史单图及弱标签指标已作废。

## 详细文档

- [部署指南](deployment/DEPLOY_GUIDE.md) - 完整的部署步骤
- [本地 + 服务器实测部署指南](deployment/LOCAL_SERVER_DEPLOY_GUIDE.md) - 可直接复现实验环境与参数
- [项目结构](项目结构与数据流.md) - 详细的目录说明
- [论文实验](论文实验章节.md) - 实验内容和结果
