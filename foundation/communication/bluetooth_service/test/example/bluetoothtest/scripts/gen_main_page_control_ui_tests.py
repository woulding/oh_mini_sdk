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
Emit Hypium UI tests: one it() per control id in main_page_control_manifest.json.
Splits into multiple files so each stays under MAX_LINES (default 1500).

  python3 scripts/gen_main_page_control_ui_tests.py
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# Manifest is produced by inject_main_page_control_ids.py (may live under scripts/ui_tests_backup
# when UiTest sources are moved out of the compile tree).
MANIFEST = ROOT / "entry/src/ohosTest/ets/apitest/main_page_control_manifest.json"
MANIFEST_ALT = ROOT / "scripts/ui_tests_backup/main_page_control_manifest.json"
OUT_DIR = ROOT / "entry/src/ohosTest/ets/uitest"
MAX_LINES = 1500
TESTS_PER_CHUNK = 280  # ~5 lines/test + ~60 header → under 1500

HEADER = """/**
 * Auto-generated: one UI existence check per main-page control (.id).
 * Regenerate: python3 scripts/gen_main_page_control_ui_tests.py
 */
import {{ describe, it }} from '@ohos/hypium';
import {{ assertControlVisible, startMainPage }} from './MainPageControlUiShared';

export default function {fn}() {{
  describe('{suite}', () => {{
"""

FOOTER = """  });
}
"""


def main() -> None:
    mp = MANIFEST if MANIFEST.is_file() else MANIFEST_ALT
    if not mp.is_file():
        raise SystemExit(f"manifest not found: {MANIFEST} or {MANIFEST_ALT}")
    rows = json.loads(mp.read_text(encoding="utf-8"))
    by_route: dict[str, list[dict]] = {}
    for r in rows:
        by_route.setdefault(r["route"], []).append(r)
    routes_sorted = sorted(by_route.keys())
    ordered: list[dict] = []
    for route in routes_sorted:
        ordered.extend(sorted(by_route[route], key=lambda x: x["id"]))

    chunks: list[list[dict]] = []
    cur: list[dict] = []
    for r in ordered:
        cur.append(r)
        if len(cur) >= TESTS_PER_CHUNK:
            chunks.append(cur)
            cur = []
    if cur:
        chunks.append(cur)

    # remove old generated files
    for p in OUT_DIR.glob("MainPageControlsUi*.test.ets"):
        p.unlink()

    for i, chunk in enumerate(chunks, start=1):
        fn = f"mainPageControlsUi{i:02d}"
        suite = f"MainPageControlsUi{i:02d}"
        parts = [HEADER.format(fn=fn, suite=suite)]
        for r in chunk:
            rid = r["id"]
            route = r["route"]
            # Hypium name: keep short; id is unique
            parts.append(f"    it('{rid}', 0, async () => {{\n")
            parts.append(f"      await startMainPage('{route}');\n")
            parts.append(f"      await assertControlVisible('{rid}');\n")
            parts.append(f"    }});\n")
        parts.append(FOOTER)
        text = "".join(parts)
        out = OUT_DIR / f"MainPageControlsUi{i:02d}.test.ets"
        out.write_text(text, encoding="utf-8")
        nlines = text.count("\n") + (1 if text and not text.endswith("\n") else 0)
        print(out.name, "cases", len(chunk), "lines", nlines)

    print("Update List.test.ets imports if chunk count changes.")


if __name__ == "__main__":
    main()
