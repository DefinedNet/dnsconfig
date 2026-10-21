#!/usr/bin/env python3
"""Check tracked Markdown files for missing local targets and heading anchors."""

import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]


def markdown(path):
    """Ignore fenced code when finding links and headings."""
    return re.sub(r"^(`{3,}|~{3,}).*?^\1[^\n]*$", "", path.read_text(), flags=re.M | re.S)


def anchors(path):
    found = set()
    counts = {}
    source = markdown(path)
    for heading in re.findall(r"^#{1,6}\s+(.+?)\s*#*\s*$", source, re.M):
        slug = re.sub(r"[^\w\- ]", "", heading.lower()).replace(" ", "-")
        count = counts.get(slug, 0)
        counts[slug] = count + 1
        found.add(slug + (f"-{count}" if count else ""))
    found.update(re.findall(r'<a\s+(?:name|id)=["\']([^"\']+)', source))
    return found


def main():
    files = subprocess.check_output(
        ["git", "ls-files", "--", "*.md"],
        cwd=ROOT, text=True,
    ).splitlines()
    failures = []
    local = external = 0
    for name in files:
        source = ROOT / name
        body = markdown(source)
        links = re.findall(r"\[[^\]\n]*\]\(<?([^\s)>]+)>?(?:\s+\"[^\"]*\")?\)", body)
        links += re.findall(r"^\s*\[[^\]\n]+\]:\s*<?([^\s>]+)", body, re.M)
        for link in links:
            url = urlsplit(link)
            if url.scheme or url.netloc:
                external += 1
                continue
            local += 1
            target = (source.parent / unquote(url.path)).resolve() if url.path else source
            if not target.is_relative_to(ROOT):
                failures.append(f"{name}: target outside repository: {link}")
            elif not target.exists():
                failures.append(f"{name}: missing target: {link}")
            elif url.fragment and target.suffix == ".md" and unquote(url.fragment) not in anchors(target):
                failures.append(f"{name}: missing heading: {link}")
    for failure in failures:
        print(failure)
    print(f"Checked {len(files)} Markdown files and {local} local links; "
          f"{len(failures)} failures. Skipped {external} external URLs.")
    return bool(failures)


if __name__ == "__main__":
    sys.exit(main())
