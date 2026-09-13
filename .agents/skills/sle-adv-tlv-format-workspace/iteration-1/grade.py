#!/usr/bin/env python3
"""Grade iteration-1 outputs for the sle-adv-tlv-format skill."""
import json
import re
from pathlib import Path

WS = Path("/home/woulding/oh_sdk_mini/.agents/skills/sle-adv-tlv-format-workspace/iteration-1")

EVALS = {
    "eval-0-broken-tlv-scan": [
        ("states the TLV order is [type][length][value]",
         r"\[\s*type\s*\]\s*\[\s*length\s*\]\s*\[\s*value"),
        ("identifies the length off-by-one / type-inclusive root cause",
         r"(多算|多 1|多1|off-by-one|value 的字节数|value 字节数|不含 type|不包含 type|\+ ?1)"),
        ("gives corrected announce bytes 01 01 01 02 01 00",
         r"01 01 01 02 01 00"),
        ("gives corrected seek bytes 0c 01 06 0b 0a ...",
         r"0c 01 06 0b 0a 73 6c 65 5f 73 65 72 76 65 72"),
        ("explains a malformed discovery-level TLV makes the device invisible",
         r"(发现等级|discovery)[\s\S]{0,400}(不可发现|隐藏|扫描不到|扫不到|invisible)"),
    ],
    "eval-1-port-sle-uart-adv": [
        ("warns the sample name TLV is reversed and/or strlen+1",
         r"(写反|反了|顺序.{0,6}反|strlen\s*\+\s*1|local_name_len\s*\+\s*1|\[length\]\[type\])"),
        ("states the layout is [type][length][value]",
         r"\[\s*type\s*\]\s*\[\s*length\s*\]\s*\[\s*value"),
        ("provides type-first TLV construction code",
         r"SLE_ADV_DATA_TYPE_COMPLETE_LOCAL_NAME"),
        ("references the ble_sle_tag oracle or the bundled decoder",
         r"(ble_sle_tag|decode_sle_adv)"),
        ("mentions secondary checks (address / peripheral role / task context)",
         r"(sle_set_local_addr|SUPPORT_SLE_BLE_PERIPHERAL|peripheral|enable 回调|任务上下文|enable callback)"),
    ],
    "eval-2-decode-adv-bytes": [
        ("flags TX power length=2 as invalid (should be 1)",
         r"(0x0C|0x0c|TX ?Power|发送功率)[\s\S]{0,200}(应为\s*1|length\s*=\s*1|多算|多了|多计|invalid|错误|越界)"),
        ("identifies the device name as sle_server",
         r"sle_server"),
        ("gives corrected bytes 0c 01 06 0b 0a ...",
         r"0c 01 06 0b 0a 73 6c 65 5f 73 65 72 76 65 72"),
        ("states the name length should be 10 / 0x0A",
         r"(0x0[Aa]|0b 0a|0x0B 0x0A|10 字节|length\s*=\s*10)"),
    ],
}


def grade():
    summary = {}
    for evaldir, checks in EVALS.items():
        summary[evaldir] = {}
        for cfg in ("with_skill", "without_skill"):
            run_dir = WS / evaldir / cfg / "run-1"
            run_dir.mkdir(parents=True, exist_ok=True)
            ans = run_dir / "outputs" / "answer.md"
            text = ans.read_text(encoding="utf-8", errors="replace") if ans.exists() else ""
            exps = []
            for desc, pat in checks:
                m = re.search(pat, text, re.IGNORECASE | re.DOTALL)
                exps.append({
                    "text": desc,
                    "passed": bool(m),
                    "evidence": (m.group(0).replace("\n", " ")[:90] if m else "not found"),
                })
            passed = sum(1 for e in exps if e["passed"])
            total = len(exps)
            grading = {
                "eval_dir": evaldir,
                "config": cfg,
                "summary": {
                    "passed": passed,
                    "failed": total - passed,
                    "total": total,
                    "pass_rate": round(passed / total, 4),
                },
                "expectations": exps,
            }
            (run_dir / "grading.json").write_text(
                json.dumps(grading, ensure_ascii=False, indent=2), encoding="utf-8")
            summary[evaldir][cfg] = f"{passed}/{total}"
            print(f"{evaldir:32s} {cfg:14s} {passed}/{total}")
    return summary


if __name__ == "__main__":
    grade()
