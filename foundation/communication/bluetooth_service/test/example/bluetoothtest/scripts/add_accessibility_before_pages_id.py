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
"""在 .id('pages_...') 行前插入 .accessibilityLevel('yes')，便于 UiTest Driver 枚举（上一行尚未有时才插入）。"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "entry" / "src" / "main" / "ets" / "pages"

ID_LINE = re.compile(r"^(\s*)\.id\('pages_")


def patch_file(path: Path) -> bool:
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)
    out: list[str] = []
    changed = False
    for line in lines:
        m = ID_LINE.match(line)
        if m:
            prev = out[-1] if out else ""
            if "accessibilityLevel('yes')" not in prev and "accessibilityLevel(\"yes\")" not in prev:
                indent = m.group(1)
                out.append(f"{indent}.accessibilityLevel('yes')\n")
                changed = True
        out.append(line)
    if changed:
        path.write_text("".join(out), encoding="utf-8")
    return changed


def main() -> int:
    n = 0
    for p in sorted(ROOT.rglob("*.ets")):
        if patch_file(p):
            print("patched", p.relative_to(ROOT))
            n += 1
    print("files", n)
    return 0


if __name__ == "__main__":
    sys.exit(main())
