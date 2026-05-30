# 论文实验流程指南（无LLM在线推理）

本指南用于把当前项目整理成“可重复、可写论文、目录清晰”的实验流程。

## 1. 你要跑的主脚本

使用新增脚本：

```bash
python thesis_experiment_pipeline.py --run-name baseline_v1 --hours 24 --epochs 80 --seed 42
```

说明：
- `--run-name`：本次实验名（建议和论文表格一致，如 `baseline_v1`、`ablation_seed7`）
- `--hours`：Step1 收集最近 N 小时告警
- `--epochs`：Step3 DQN训练轮数
- `--seed`：随机种子（保证可复现）

## 2. 输出目录（统一）

每次运行都会写到：

`experiments/runs/<run_name>/`

主要文件：

- `step1_unified_alerts.json`：统一告警
- `step2_causal_graph.json`：因果图
- `step2_causal_graph.mmd`：图可视化（Mermaid）
- `checkpoints/dqn_best.pt`：DQN最优模型
- `step3_pruned_graph.json`：裁剪后图
- `step4_prompt_intent_analysis.txt`：意图分析提示词
- `step4_prompt_ttp_mapping.txt`：TTP映射提示词
- `step4_prompt_report.txt`：事件报告提示词
- `experiment_summary.json`：本次实验摘要（论文优先引用这个）

## 3. 建议的论文实验批次

你可以按以下批次跑（每次只改 `run-name/seed/epochs`）：

1. 基线实验：`baseline_seed42`
2. 随机种子敏感性：`seed7`、`seed21`、`seed84`
3. 训练轮数对比：`epoch40`、`epoch80`、`epoch120`

示例：

```bash
python thesis_experiment_pipeline.py --run-name seed7 --seed 7 --epochs 80
python thesis_experiment_pipeline.py --run-name seed21 --seed 21 --epochs 80
python thesis_experiment_pipeline.py --run-name epoch120 --seed 42 --epochs 120
```

## 4. 当前已做的流程优化

- 修复了 Step1 时间比较异常（offset-naive 与 offset-aware）
- 提升了告警适配兼容性（大小写字段、时间字符串、URL字段）
- 将实验输出从分散目录统一到 `experiments/runs/`
- 自动生成统一实验摘要 JSON，方便论文整理

## 5. 论文写作时建议引用

优先从 `experiment_summary.json` 取：

- 告警规模：`step1.count`
- 因果图规模：`step2.nodes`、`step2.edges`、`step2.triples`
- DQN指标：`step3.metrics.*`
- 裁剪统计：`step3.pruning_stats.*`

