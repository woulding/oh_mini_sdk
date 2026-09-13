#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (C) 2022 Huawei Device Co., Ltd.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
"""
Inject stable .id() on tagged ArkUI components in main module page sources,
and write main_page_control_manifest.json for UI test generation.

Block-body components (Button { } / Scroll { } / …): .id is placed after the
closing brace of the body, before trailing modifiers like .width().

Re-run after adding pages or controls:
  python3 scripts/inject_main_page_control_ids.py
"""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAIN_PAGES_JSON = ROOT / "entry/src/main/resources/base/profile/main_pages.json"
MAIN_ETS = ROOT / "entry/src/main/ets"
MANIFEST_OUT = ROOT / "entry/src/ohosTest/ets/apitest/main_page_control_manifest.json"

COMPONENTS: list[tuple[str, str]] = [
    ("TextInput", "ti"),
    ("Button", "btn"),
    ("Switch", "sw"),
    ("Slider", "sl"),
    ("Checkbox", "cb"),
    ("Radio", "rd"),
    ("Image", "img"),
    ("PageTitle", "pt"),
    ("MainPageTitle", "mpt"),
    ("TitleComponent", "tt"),
    ("ButtonComponent", "bcomp"),
    ("Scroll", "sc"),
    ("ListItem", "li"),
    ("TabContent", "tc"),
    ("Tabs", "tabs"),
]

# These often use Component(args) { ... }.modifiers — .id must follow the block's }.
BLOCK_AFTER_BRACE = frozenset({"Button", "Scroll", "ListItem", "TabContent", "Tabs"})

ID_PREFIX = "pages_"


def route_to_slug(route: str) -> str:
    return route.replace("/", "_")


def find_close_paren(s: str, open_i: int) -> int:
    depth = 0
    i = open_i
    n = len(s)
    while i < n:
        c = s[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def find_close_brace(s: str, open_i: int) -> int:
    """s[open_i] must be '{'. Returns index of matching '}'."""
    depth = 0
    i = open_i
    n = len(s)
    while i < n:
        c = s[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def skip_ws(s: str, i: int) -> int:
    n = len(s)
    while i < n and s[i] in " \t\n\r":
        i += 1
    return i


def line_has_comment_before(pos: int, s: str) -> bool:
    line_start = s.rfind("\n", 0, pos) + 1
    chunk = s[line_start:pos]
    return "//" in chunk


def insertion_index(s: str, open_paren: int, comp: str) -> int:
    cp = find_close_paren(s, open_paren)
    if cp < 0:
        return -1
    j = skip_ws(s, cp + 1)
    if comp in BLOCK_AFTER_BRACE and j < len(s) and s[j] == "{":
        cb = find_close_brace(s, j)
        if cb < 0:
            return -1
        return cb + 1
    return cp + 1


def already_has_our_id_near(s: str, ins: int) -> bool:
    start = max(0, ins - 80)
    tail = s[start : ins + 500]
    m = re.search(r"\.id\s*\(\s*['\"]([^'\"]+)['\"]", tail)
    return bool(m and m.group(1).startswith(ID_PREFIX))


def build_comp_pattern(comp: str) -> re.Pattern[str]:
    return re.compile(rf"\b{re.escape(comp)}\s*\(")


def inject_file(path: Path, route: str) -> int:
    slug = route_to_slug(route)
    text = path.read_text(encoding="utf-8")
    counters: dict[str, int] = {}
    inserts: list[tuple[int, str]] = []

    for comp, kind in COMPONENTS:
        pat = build_comp_pattern(comp)
        for m in pat.finditer(text):
            open_paren = m.end() - 1
            if line_has_comment_before(open_paren, text):
                continue
            ins = insertion_index(text, open_paren, comp)
            if ins < 0:
                continue
            if already_has_our_id_near(text, ins):
                continue
            idx = counters.get(kind, 0)
            cid = f"{slug}__{kind}_{idx}"
            counters[kind] = idx + 1
            snippet = f"\n  .id('{cid}')"
            inserts.append((ins, snippet))

    inserts.sort(key=lambda x: -x[0])
    out = text
    for pos, snippet in inserts:
        out = out[:pos] + snippet + out[pos:]

    if out != text:
        path.write_text(out, encoding="utf-8")

    return len(inserts)


def collect_page_control_rows(path: Path, route: str) -> list[dict]:
    """Full manifest from existing .id('pages_…') in the page source (stable across re-runs)."""
    slug = route_to_slug(route)
    prefix = f"{slug}__"
    text = path.read_text(encoding="utf-8")
    found = sorted(set(re.findall(r"\.id\s*\(\s*'([^']+)'\s*\)", text)))
    rows: list[dict] = []
    for cid in found:
        if cid.startswith(prefix):
            rows.append({"route": route, "id": cid})
    return rows


def main() -> None:
    routes = json.loads(MAIN_PAGES_JSON.read_text(encoding="utf-8"))["src"]
    for route in routes:
        rel = route + ".ets"
        path = MAIN_ETS / rel
        if not path.is_file():
            print("skip missing", path)
            continue
        n = inject_file(path, route)
        if n:
            print(route, "inserted", n)

    all_rows: list[dict] = []
    for route in routes:
        rel = route + ".ets"
        path = MAIN_ETS / rel
        if not path.is_file():
            continue
        rows = collect_page_control_rows(path, route)
        all_rows.extend(rows)
        if rows:
            print(route, "manifest", len(rows))

    MANIFEST_OUT.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST_OUT.write_text(json.dumps(all_rows, ensure_ascii=False, indent=2), encoding="utf-8")
    print("total controls", len(all_rows), "manifest", MANIFEST_OUT)


if __name__ == "__main__":
    main()
