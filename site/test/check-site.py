"""Validate authored chapter paths and the assembled Pages site's local links.

python site/test/check-site.py [--dist path/to/dist]
Only reads local files. No requests to external links.
"""
import argparse
from html.parser import HTMLParser
from pathlib import Path
import re
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser()
parser.add_argument("--dist", type=Path)
args = parser.parse_args()
source = ROOT / "docs-src/src"
summary = (source / "SUMMARY.md").read_text(encoding="utf-8")
chapters = re.findall(r"\]\(([^)]+\.md)\)", summary)
assert chapters, "No chapters in SUMMARY.md"
for chapter in chapters:
    path = source / chapter
    assert path.is_file(), f"SUMMARY points to a missing chapter: {path}"
    assert len(path.read_text(encoding="utf-8").strip()) > 100, f"Empty / placeholder chapter: {path}"

# The quickstart must use the actual public child-command syntax, not internal flags.
quickstart = (source / "getting-started.md").read_text(encoding="utf-8")
assert "blackbox run --upstream-port 3000 -- node server.js" in quickstart
assert not re.search(r"blackbox run[^\n]*(--exec|--env-file)", quickstart), "Unsupported quickstart CLI flags"


class Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.refs = []
        self.ids = set()

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if "id" in attrs:
            self.ids.add(attrs["id"])
        key = "href" if tag in ("a", "link") else "src" if tag in ("img", "script") else None
        if key and attrs.get(key):
            self.refs.append(attrs[key])


if args.dist:
    dist = args.dist.resolve()
    documents = {}
    for path in dist.rglob("*.html"):
        doc = Links()
        doc.feed(path.read_text(encoding="utf-8"))
        documents[path.resolve()] = doc
    assert dist / "index.html" in documents, "Landing page is missing"
    checked = 0
    for path, doc in documents.items():
        for ref in doc.refs:
            url = urlsplit(ref)
            if url.scheme or url.netloc:
                continue
            target = (dist / unquote(url.path).lstrip("/") if url.path.startswith("/") else
                      path.parent / unquote(url.path)) if url.path else path
            if target.is_dir():
                target /= "index.html"
            target = target.resolve()
            assert target.is_relative_to(dist), f"Local link escapes dist: {path}: {ref}"
            assert target.is_file(), f"Broken local link: {path.relative_to(dist)} -> {ref}"
            if url.fragment and target in documents:
                assert unquote(url.fragment) in documents[target].ids, f"Missing anchor: {path.relative_to(dist)} -> {ref}"
            checked += 1
    for chapter in chapters:
        html = dist / "docs" / Path(chapter).with_suffix(".html")
        assert html in documents, f"Chapter HTML not published at expected path: {html}"
        text = html.read_text(encoding="utf-8")
        assert len(text) > 3000, f"Chapter HTML looks like a placeholder: {html}"
    print(f"Pages link check PASS: {len(documents)} HTML documents, {checked} local links")
else:
    print(f"Documentation source check PASS: {len(chapters)} real chapters")
