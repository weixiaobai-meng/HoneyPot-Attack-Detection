# 实验数据准备说明

论文尚未开始撰写前，本项目只生成真实告警、攻击图、标注模板和可复现实验结果；不再用单图增广或弱标签生成论文指标。

完整执行顺序见 [EXPERIMENT_EXECUTION_GUIDE.md](D:/研究生毕设/experiments/EXPERIMENT_EXECUTION_GUIDE.md)。

核心入口：

```powershell
python -m experiments.validate_dataset --manifest experiments/data/manifest.json
python -m experiments.run_benchmark --manifest experiments/data/manifest.json --output-dir experiments/results/benchmark_v1
python -m experiments.run_scale_benchmark --manifest experiments/data/manifest.json --checkpoint path/to/dqn.pt --output experiments/results/scale_v1.json
```

只有通过场景级划分、全边人工标注、基线比较、消融和规模验证的数据，才可以进入后续论文实验章节。
