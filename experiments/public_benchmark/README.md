# 公开数据实验：AIT 告警、官方事件标签与 DQN 约束诊断

本目录是离线实验，不接入生产告警数据库，不自动发布模型，不修改线上保护约束。
模型统一采用当前 198 维输入，不读取历史 128 维权重。多个 seed/fold 的权重是
实验对照产物，不是同时上线的模型。完整研究协议见 [PROTOCOL.md](PROTOCOL.md)。

## 数据与标签

- AIT-ADS v1（Zenodo 8263181）完整 ZIP 和 labels.csv 校验官方 MD5，另记 SHA-256。
- AIT-LDSv2（5789064）按 HTTP Range 获取指定 intranet-server 的逐行标签及原始日志，
  不下载大体积 PCAP。ZIP 成员通过 CRC 并记录 SHA-256；**未验证整个 LDS ZIP 的 MD5**。
- 覆盖认证、audit、Apache access/error 四类日志，精确匹配 Wazuh/AMiner 告警原文。
  未覆盖来源、原文缺失、歧义重复行不作为正常标签。报告覆盖率与排除数量。
- 官方事件标签属于外部公开测试床真值，不冒充两位人工评审标注。
  两端都属于攻击事件的关联边仅构成“关联相关性代理标签”，不等于真实因果边。
- 数据、训练权重与完整结果留在 gitignored 的 experiments/data 与 experiments/results。
  不把公开测试床事件写入生产 PG，不计作自然蜜点攻击。

## 可复现命令

先安装适配本机的 PyTorch 与 `experiments/requirements.txt`。

```powershell
python -m experiments.public_benchmark.acquire
python -m experiments.public_benchmark.acquire_labels
python -m experiments.public_benchmark.prepare
python -m experiments.public_benchmark.run
python -m experiments.public_benchmark.mechanism_study
python -m experiments.public_benchmark.verify_artifacts
python -m unittest experiments.public_benchmark.test_public_benchmark -v
```

下载器不会绕过 403、限流或身份校验。已有文件与校验不符时保留现场并停止。
训练输出目录不得覆盖，复跑必须用 `--output` 指定新目录。首次准备输出目录也应
保持版本独立，避免覆盖已冻结的图及抽样清单。下载缓存可复用并重新检查。

## 分组及指标

保持八个原始场景完整隔离。一个场景的窗口不可同时进入训练和测试。
机制诊断轮流留出一个测试场景、一个验证场景，其余六个训练；seed 42–46，
最多 12 epoch，以验证集早停。独立统计单位是场景，而不是 40 个运行或 54 张窗口图。

原始事件保留、官方攻击事件保留、模型结构可达性、关联代理标签分数、压缩率分别报告。
由于没有独立的关联边/路径金标准，不能报告真实攻击路径召回率。
“100% 保留”如果来自强制约束，不能称为 DQN 学出来的效果。

原有路径约束可能锁定全部边，因此必须先做动作空间检查。若没有合法删除动作，
重训或扩大样本都不能让相同模型/约束产生压缩。不能先添加冗余边再把删掉它们的
比例包装成优于原始图的收益。

`mechanism_study` 对无约束训练策略施加不同推理过滤器，属于事后机制诊断。
它不等同于每一种过滤器都重新训练过的策略，也不是可以直接部署的正式对照结论。

## 来源与许可

- AIT-ADS：<https://doi.org/10.5281/zenodo.8263181>，CC BY 4.0。
- AIT-LDSv2：<https://doi.org/10.5281/zenodo.5789064>，CC BY-NC-SA 4.0。
- 作者处理说明：<https://github.com/ait-aecid/alert-data-set>。
- 后续外部验证：<https://github.com/darpa-i2o/Transparent-Computing>。

引用：Landauer et al., *Introducing a New Alert Data Set for Multi-Step Attack
Analysis*, CSET 2024；Landauer et al., *Maintainable Log Datasets for Evaluation of
Intrusion Detection Systems*, IEEE TDSC 2023，doi:10.1109/TDSC.2022.3201582。
