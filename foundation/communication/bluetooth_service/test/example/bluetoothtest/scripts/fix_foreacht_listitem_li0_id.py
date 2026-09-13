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
"""ForEach 内多行共用同一 .id('...__li_0') 会导致重复 id / 崩溃；为首个保留 __li_0，其余用 __li_${index}。"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "entry" / "src" / "main" / "ets" / "pages"

# 仅匹配 ForEach 的回调行，避免误改 `} , (item: T) => item.id` 这类 key 函数
PATTERNS = [
    (r"\(item:\s*TestData\)\s*=>\s*\{", "(item: TestData, index: number) => {"),
    (r"\(item:\s*PairDevices\)\s*=>\s*\{", "(item: PairDevices, index: number) => {"),
    (r"\(item:\s*string\)\s*=>\s*\{", "(item: string, index: number) => {"),
    (r"\(item:\s*BluetoothDevice\)\s*=>\s*\{", "(item: BluetoothDevice, index: number) => {"),
]

LI0_ID = re.compile(r"\.id\('(pages[^']+__li_)0'\)")


def patch(text: str) -> str:
    if "ForEach(" not in text:
        return text
    out_lines = []
    for line in text.split("\n"):
        if "ForEach(" in line and "index: number" not in line:
            for pat, repl in PATTERNS:
                if re.search(pat, line):
                    line = re.sub(pat, repl, line, count=1)
                    break
        out_lines.append(line)
    text = "\n".join(out_lines)
    text = LI0_ID.sub(
        lambda m: f".id(index === 0 ? '{m.group(1)}0' : `{m.group(1)}${{index}}`)",
        text,
    )
    return text


def main() -> int:
    n = 0
    for path in sorted(ROOT.rglob("*.ets")):
        t = path.read_text(encoding="utf-8")
        nt = patch(t)
        if nt != t:
            path.write_text(nt, encoding="utf-8")
            print("patched", path.relative_to(ROOT))
            n += 1
    print("total", n)
    return 0


if __name__ == "__main__":
    sys.exit(main())
