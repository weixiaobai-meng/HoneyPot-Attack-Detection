import zipfile
from pathlib import Path
import xml.etree.ElementTree as ET

src = Path(r"D:\研究生毕设\tmp\proposal_opening.pptx")
out = Path(r"D:\研究生毕设\tmp\6.9-开题报告-代码对齐版.pptx")

ns_uri = "http://schemas.openxmlformats.org/drawingml/2006/main"
ns = {"a": ns_uri}
ET.register_namespace("a", ns_uri)
ET.register_namespace("p", "http://schemas.openxmlformats.org/presentationml/2006/main")
ET.register_namespace("r", "http://schemas.openxmlformats.org/officeDocument/2006/relationships")

replacements = {
    "通过异构蜜点协同与eBPF内核审计技术，实时拦截底层系统调用，生成具备因果关系的攻击溯源图。":
    "通过异构蜜点协同与系统审计日志采集（当前代码实现：auditd/sysdig + agent-go）技术，实时汇聚底层行为，生成具备因果关系的攻击溯源图。",

    "构建 Graph-to-Text 转换模板；利用 思维链技术进行模型微调或 Prompt 优化，实现底层告警向 MITRE ATT&CK 阶段的自动映射 。":
    "构建 Graph-to-Text 转换模板；优先完成 Prompt 工程与规则映射（当前代码实现），并预留后续模型微调接口，实现底层告警向 MITRE ATT&CK 阶段的自动映射。",

    "提出构建 LLM 驱动的语义分析架构；利用思维链（CoT）逻辑解决技术动作与战略意图脱节识别难题。":
    "提出构建 LLM 驱动的语义分析架构；当前阶段先完成 Graph-to-Text + 结构化提示词输出，为后续思维链（CoT）推理奠定接口与数据基础。",

    "本研究的三个创新点环环相扣：首先通过多源诱饵捕获解决‘看不全’的问题；随后通过自适应剪枝解决攻击图谱‘看不明’的问题；最后通过大模型推理解决‘看不懂’的问题。”":
    "本研究的三个创新点环环相扣：首先通过多源诱饵捕获解决‘看不全’的问题；随后通过自适应剪枝解决攻击图谱‘看不明’的问题；最后通过 Graph-to-Text 与提示词工程推动‘看不懂’问题的阶段性解决（LLM在线推理作为下一阶段工作）。",

    "开展消融实验与对比实验（如对比传统 NoDoze 方法），验证意图识别的召回率、准确率及推理耗时等核心指标 。":
    "开展消融实验与对比实验（如对比传统图谱过滤方案），验证图谱裁剪的核心边召回率、压缩率及整体流程耗时等核心指标。",

    "诱骗阵地部署：已成功在本地环境下完成文件蜜点、账户蜜点及寄生诱饵的初步部署，并验证了基础日志的捕获能力":
    "诱骗阵地部署：已在本地完成文件蜜点、账户蜜点及寄生诱饵的初步部署，并验证了基础日志捕获与统一汇聚能力。",

    "开发工具链选型：已搭建基于 Python 的数据预处理框架及主流图算法库运行环境，具备对攻击行为进行初步因果建模的技术条件 。":
    "开发工具链选型：已搭建基于 Python 的数据预处理框架、图建模流程与 DQN 裁剪训练环境，具备开展阶段性实验的技术条件。",

    "图模型与攻击链分析：了解攻击链建模方法，包括节点/边设计、图嵌入和攻击阶段划分。":
    "图模型与攻击链分析：已完成节点/边设计、因果图构建、DQN裁剪与 Graph-to-Text 输出的流程实现。",
}

changed = 0

with zipfile.ZipFile(src, "r") as zin, zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zout:
    for item in zin.infolist():
        data = zin.read(item.filename)
        if item.filename.startswith("ppt/slides/slide") and item.filename.endswith(".xml"):
            root = ET.fromstring(data)
            updated = False
            for p in root.findall(".//a:p", ns):
                ts = p.findall(".//a:t", ns)
                if not ts:
                    continue
                old = "".join((t.text or "") for t in ts).strip()
                if old in replacements:
                    new_text = replacements[old]
                    ts[0].text = new_text
                    for t in ts[1:]:
                        t.text = ""
                    changed += 1
                    updated = True
            if updated:
                data = ET.tostring(root, encoding="utf-8", xml_declaration=True)
        zout.writestr(item, data)

print(f"written: {out}")
print(f"paragraphs changed: {changed}")
