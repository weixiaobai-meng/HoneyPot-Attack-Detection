"""Render static discoverable links from the actual management file catalog."""
import argparse
import html
import json
from pathlib import Path


def render(catalog):
    cards = []
    for item in catalog:
        file_id = int(item["id"])
        name = html.escape(item.get("title") or item["name"])
        cards.append(f'<article><span class="kind">研究资料 · DOCX</span><h2><a href="/downloads/{file_id}">{name}</a></h2>'
                     f'<p>技术资料与研究文档，点击下载查看全文。</p><a class="download" href="/downloads/{file_id}">下载文档 →</a></article>')
    template = Path(__file__).with_name("index.template.html").read_text(encoding="utf-8")
    return template.replace("<!--CATALOG-->", "\n".join(cards))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--catalog", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    Path(args.output).write_text(render(json.loads(Path(args.catalog).read_text(encoding="utf-8"))), encoding="utf-8")
