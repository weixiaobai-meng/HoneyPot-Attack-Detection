# 实验执行指南

## 新版代码的必要迁移

旧图和checkpoint需要重新生成：新增了来源证据属性，正式构图也禁用了实验campaign锚点。
不得通过手工修改图版本号绕过验证。正式测试场景清单增加`path_gold`，其内容为独立人工复核
的有向连续边序列，例如：

```json
{"paths": [{"path_id": "reviewed_path_01", "edge_ids": ["实际边ID1", "实际边ID2"]}]}
```

人工路径是评价真值；图内`required_paths`是无标签构图产生的可达约束，二者不可混用。
不把`causal_score`称为因果正确率。完整路径召回率、可达约束保持、证据保持和压缩率须分别报告。

基准完成后，`graphs/<seed>/<method>/<场景哈希>/pruned.json`可直接作为LLM裁剪组输入。
单独对新图推理时使用：

```powershell
python -m experiments.prune_graph --graph path/to/graph.json `
  --checkpoint experiments/results/benchmark_v1/checkpoints/seed_42/dqn_path_constrained.pt `
  --output experiments/results/new_pruned.json
```

## LLM三条件闭环

准备清单，各路径相对于清单文件，同一case的原始告警与完整图必须具有相同事件ID集合，
裁剪图只可包含完整图的原始边。原始日志和图在上传前应按
相同规则去标识化；不要将生产凭据、密码或私钥放进输入。

```json
{"cases": [{"case_id": "scenario_test_001", "raw_alerts": "raw.json", "full_graph": "graph.json", "pruned_graph": "pruned.json"}]}
```

默认只生成可检查的`prepared.json`，不会调用LLM：

```powershell
python -m experiments.run_llm_benchmark --manifest path/to/llm_manifest.json --output experiments/results/llm
```

确认输入后，在已配置`DEEPSEEK_API_KEY`等环境变量的终端执行：

```powershell
python -m experiments.run_llm_benchmark --manifest path/to/llm_manifest.json `
  --output experiments/results/llm --execute --gold path/to/llm_gold.json
```

金标准只在本地用于评估，绝不进入提示词。金标准按`cases`组织，包含case_id、facts、ttps、
attack_stages及intent；facts/intent为人工规范化描述，或具有text字段的对象。
自动精确匹配不能处理全部同义表达，需结合盲评，尤其不能把所有未匹配项直接叫幻觉。
运行器验证输出schema和事件引用；引用正确仍可能存在错误解释，应由金标准和人工复核评判。
全部组使用相同模型参数和输出预算。超出输入预算时整组拒绝；缩小真实采集窗口后重新构图。
失败不自动填空为零分，也不挑选最有利响应。`--execute`若有失败返回非零退出码。

## 实验产物验收

```powershell
python -m experiments.check_readiness `
  --benchmark experiments/results/benchmark_v1/benchmark_results.json `
  --scale experiments/results/scale_v1.json `
  --llm experiments/results/llm/evaluation.json `
  --output experiments/results/readiness.json
```

这是本项目实验协议的完整性检查，不是学校毕业标准的自动判定。真实数据规模、论文创新性、
统计解释和负结果分析仍须导师审核。没有满足要求的真实数据时，不应用合成样本填充正式结果。

本目录用于生成可信实验数据，不用于提前生成论文结论。没有通过场景隔离和人工标注校验的数据，不能用于报告模型准确率、召回率或压缩率。

## 1. 收集场景

每次受控触发使用独立的时间窗口、测试来源和场景编号。原始告警必须从真实部署入口导出，不能直接写数据库或手工拼接告警 JSON。

```powershell
python deployment/export_alerts_to_step1.py export-scenario-live `
  --start "2026-07-20 10:00:00" `
  --end "2026-07-20 10:30:00" `
  --run-dir experiments/runs/scenario_001 `
  --scenario-id scenario_001 `
  --chain-ip "你的测试来源IP" `
  --chain-actor-id reviewer_note_only
```

这个命令从未标注的真实告警构图，并生成不含模型分数和推荐答案的 `step3/edge_labels.annotation_template.json`。

## 2. 人工标注

两位评审分别将模板另存为 `edge_labels.rater_a.json` 和 `edge_labels.rater_b.json`，为每条边填写：`1` 表示应保留的核心攻击链边，`0` 表示应裁剪的背景/冗余边。不要把 `scenario_id`、`scenario_role`、人工链路编号写回图数据。

至少两位评审者应独立标注全部数据；分歧边由第三方复核后形成最终 `edge_labels.json`。每个进入训练、验证和测试的场景都必须覆盖全部边。

```powershell
python -m experiments.evaluate_annotations `
  --graph experiments/data/scenario_001/causal_graph.json `
  --rater experiments/data/scenario_001/edge_labels.rater_a.json `
  --rater experiments/data/scenario_001/edge_labels.rater_b.json `
  --output experiments/data/scenario_001/annotation_review.json
```

将输出中的分歧项补充 `adjudicated_label` 和 `adjudication_note`，再形成最终 `edge_labels.json`。正式数据集整体 Cohen's Kappa 低于 0.60 时，应先统一标注规范并重新标注，不能直接训练。

## 3. 构建清单

复制 [dataset_manifest.example.json](D:/研究生毕设/experiments/dataset_manifest.example.json) 为真实清单。程序执行底线为 6 个训练场景、2 个验证场景、2 个测试场景；正式论文建议完成至少30个独立场景，并在预实验后根据方差复核样本量。

划分单位只能是独立攻击活动组 `group_id`，不能把同一张图的增广版本、同一批原始告警或同一测试过程拆到不同集合。每个场景必须记录原始告警、攻击类型和数据来源。

## 4. 校验数据

```powershell
python -m experiments.validate_dataset --manifest experiments/data/manifest.json
```

校验会拒绝：缺失标签、类别缺失、跨集合重复图结构、图中携带 `scenario_role` 等实验答案字段，以及缺少训练/验证/测试集合的清单。

## 5. 运行裁剪对比和消融

```powershell
python -m experiments.run_benchmark `
  --manifest experiments/data/manifest.json `
  --output-dir experiments/results/benchmark_v1 `
  --seeds 42,43,44,45,46 `
  --epochs 40 `
  --feature-ablations identity,cross_honeypot,temporal,origin_score,evidence_contract `
  --mechanism-ablations dynamic_state,terminal_reward,shuffled_order
```

输出包括JSON/CSV、各方法裁剪图、约束审计和输入哈希。九种对照为全保留、同压缩随机、证据规则、监督GAT、DQN、旧评分约束DQN、路径约束DQN、同约束规则和同约束监督GAT。以独立场景为统计单位，报告95%置信区间、配对检验和Holm校正。

## 6. 运行规模实验

先使用基准实验生成的 DQN checkpoint，再对不同真实场景窗口运行：

```powershell
python -m experiments.run_scale_benchmark `
  --manifest experiments/data/manifest.json `
  --checkpoint experiments/results/benchmark_v1/checkpoints/seed_42/dqn_path_constrained.pt `
  --output experiments/results/scale_v1.json `
  --partition-edges 0,128,256,512,1024 `
  --decision-batch-sizes 1,8,16 `
  --warmup 1 `
  --repeats 3
```

规模实验只统计实际采集到的图大小，不复制或伪造同一批告警扩大样本。记录边数、节点数、核心链召回率、噪声过滤率、压缩率、时延、内存和分区数，并报告每种分区相对完整图的质量变化。

## 7. 评价三元组和LLM

三元组金标准与预测结果使用同一 S-A-O JSON 格式：

```powershell
python -m experiments.evaluate_triples `
  --predicted path/to/step2_standard_triples.json `
  --gold path/to/reviewed_triples.json `
  --output experiments/results/triple_eval.json
```

LLM 每个测试场景应固定模型、温度和提示词，比较原始告警、未裁剪图、裁剪图三种条件。结构化结果使用 [llm_predictions.example.json](D:/研究生毕设/experiments/llm_predictions.example.json) 和 [llm_gold.example.json](D:/研究生毕设/experiments/llm_gold.example.json) 的格式：

```powershell
python -m experiments.evaluate_llm_reports `
  --predictions experiments/results/llm_predictions.json `
  --gold experiments/data/llm_gold.json `
  --conditions raw_alerts,full_graph,pruned_graph `
  --output experiments/results/llm_eval.json
```

必须报告事实精确率、事实覆盖率、TTP F1、未匹配事实数、输入输出Token和时延；
未匹配事实不直接等于幻觉，需对同义表述与证据真实性进行人工复核。
有人工评审时，每个条件至少两位评审者独立打分。

## 8. 不可使用的结果

- 从单一图谱随机丢边得到的训练/测试指标。
- 由攻击本源分、关系规则或 `scenario_role` 自动生成后再用同一规则评价的标签。
- 使用测试集标签恢复裁掉核心边后的召回率。
- 只展示一份LLM报告而没有事实和TTP评价的结论。
- 把软件冒烟测试、旧README指标或缺少双人标注的数据写入论文结果。
