import zipfile
from pathlib import Path
import xml.etree.ElementTree as ET

ppt = Path(r"D:\研究生毕设\tmp\6.9-开题报告-代码对齐版.pptx")
out = Path(r"D:\研究生毕设\tmp\6.9-开题报告-代码对齐版-v2.pptx")

ns_uri = "http://schemas.openxmlformats.org/drawingml/2006/main"
ns = {"a": ns_uri}
ET.register_namespace("a", ns_uri)
ET.register_namespace("p", "http://schemas.openxmlformats.org/presentationml/2006/main")
ET.register_namespace("r", "http://schemas.openxmlformats.org/officeDocument/2006/relationships")

changed = 0

with zipfile.ZipFile(ppt, "r") as zin, zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zout:
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
                new = old

                if "eBPF内核审计技术" in new:
                    new = new.replace(
                        "通过异构蜜点协同与eBPF内核审计技术，实时拦截底层系统调用，生成具备因果关系的攻击溯源图。",
                        "通过异构蜜点协同与系统审计日志采集（当前代码实现：auditd/sysdig + agent-go）技术，实时汇聚底层行为，生成具备因果关系的攻击溯源图。"
                    )
                if "基于 Graph-to-Text 与 LLM 思维链进行跨维度推理，自动生成对齐 ATT&CK 的攻击意图报告。" in new:
                    new = new.replace(
                        "基于 Graph-to-Text 与 LLM 思维链进行跨维度推理，自动生成对齐 ATT&CK 的攻击意图报告。",
                        "基于 Graph-to-Text 输出结构化提示词，形成可解释的意图分析输入；后续阶段接入 LLM 在线推理，生成对齐 ATT&CK 的攻击意图报告。"
                    )

                if new != old:
                    ts[0].text = new
                    for t in ts[1:]:
                        t.text = ""
                    changed += 1
                    updated = True

            if updated:
                data = ET.tostring(root, encoding="utf-8", xml_declaration=True)
        zout.writestr(item, data)

print(f"written: {out}")
print(f"paragraphs changed: {changed}")
