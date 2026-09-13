# sle-adv-tlv-format — evaluation record

Date: 2026-09-12. Skill: `sle-adv-tlv-format`.
Workspace with raw outputs: `.agents/skills/sle-adv-tlv-format-workspace/`.

This file records what was measured and what changed, so a future edit does not
regress the triggering or the known-good answers.

## 1. Effect evaluation (does the skill change the answer?)

Harness: `skill-creator` layout — 3 realistic prompts from `evals/evals.json`, each
run by an independent subagent with the skill injected vs a baseline with no skill.
13 objectively checkable assertions (see `workspace/iteration-1/grade.py`).

| eval | with skill | baseline |
|---|---|---|
| `broken-tlv-scan-fail` — logs all green, scanner can't find the device | 5/5 | 4/5 |
| `port-sle-uart-adv` — port the SDK adv code, pitfalls + usable code | 5/5 | 5/5 |
| `decode-adv-bytes` — decode/check a scan response | 4/4 | 3/4 |
| **total** | **14/14 (100%)** | **12/14 (85%)** delta **+15%** |

The baseline was already strong on these prompts, so the delta is modest. The skill's
real contribution is consistency plus the skill-specific behaviours the baseline did
not show: citing the `ble_sle_tag` oracle and actually running the bundled decoder.

### Flaw found and fixed by this eval

In `decode-adv-bytes` the with-skill run called `"sle_server"` a 9-character name —
it copied the length from the `ble_sle_tag` example `"sleserver"` (9 chars), which is a
*different* name. Fix: the "Count the name characters carefully" note in `SKILL.md`.
A re-run (workspace `iteration-2`) then reported 10 characters and `0B 0A`.

## 2. Trigger evaluation (does the description get the skill consulted?)

Trigger set: `evals/trigger-eval.json` (10 should-trigger, 10 near-miss
should-not-trigger). Two harnesses were used:

- `skill-creator/scripts/run_loop.py` (Claude CLI + `.claude/commands`):
  results in `workspace/trigger-results/2026-09-12_210346/`.
  Iterations 1–3 gave train recall 0% → 11% → 11%, test recall 0% throughout.
  This backend (glm-5.3-flash via `claude -p`) rarely invokes the custom command, so
  the loop could not converge and `best_description` fell back to the original. Treat
  these numbers as a weak signal, not ground truth.
- opencode live probe (the mechanism the user actually experiences): a fresh
  subagent is given only the natural-language query and reports what it used.

Description before / after:

```
BEFORE (original):
Correctly encode and decode SLE / 星闪 announce (广播) and seek / scan-response
(扫描响应) data as TLVs ... Use this skill whenever you write or debug SLE advertising
/ announce data / scan response (sle_set_announce_data, sle_set_adv_data,
sle_set_scan_response_data), when a "星闪调试助手" / phone scanner cannot find an SLE
device even though ssaps_register_server / sle_start_announce / "announce enable" all
report success, ... [908 chars]

AFTER (current):
Decode, check, or fix SLE / 星闪 (NearLink) broadcast TLV bytes. Use whenever the user
pastes raw SLE announce / scan-response hex and asks to 解码/解析/检查 it or "这段广播
数据对不对", or asks what bytes a TLV should be, why `sle_set_adv_local_name` writes
`local_name_len + 1`, whether SLE length counts the type byte, or how to encode
discovery level 发现等级 / access mode / TX power / complete local name 完整名称 ...
Key fact: SLE is [type][length][value] with length = VALUE bytes only, NOT type+value
unlike BLE; several SDK samples get this wrong. Not for general BLE GATT questions.
[984 chars]
```

opencode probe comparison (skill used? / answer correct?):

| query | before | after |
|---|---|---|
| `sle_set_adv_local_name` 为什么写 `local_name_len + 1` + 扫不到 | wrong skill used, **answer wrong** (claimed +1 correct) | `sle-adv-tlv-format` used, **answer correct** |
| 帮我把这段 SLE 广播数据解码检查一下：`0c 02 06 0b 0b ...` | **not triggered**, answer wrong (called it valid) | triggered, **answer correct** (off-by-one, `0c 01 06 0b 0a ...`) |
| 这段星闪 SLE 广播数据对不对：`0c 02 06 0b 0b ...` | — | triggered, answer correct |
| `ble_sle_tag` 的 `g_sle_adv_data` 29 字节 | triggered, correct | triggered, correct |
| negative: HEX→bin + UART baud rate | not triggered | seen in list but **not used** (no over-trigger) |
| negative: BLE GATT service discovery | not triggered | not triggered |

Key wording that fixed the miss: leading with **"Decode, check, or fix"** and adding
the literal user phrasings `解码/解析/检查` and `"这段广播数据对不对"`.

## 3. Reproduce

```bash
# effect eval grading (after running the prompts into the workspace)
python3 .agents/skills/sle-adv-tlv-format-workspace/iteration-1/grade.py
python3 -m scripts.aggregate_benchmark <workspace>/iteration-1 --skill-name sle-adv-tlv-format

# description optimization (needs a backend that invokes custom commands)
cd <a dir with .claude/> && PYTHONPATH=<skill-creator> python3 -m scripts.run_loop \
  --eval-set <skill>/evals/trigger-eval.json \
  --skill-path <skill> --model <model> --max-iterations 3 --verbose

# always re-validate after editing the description
python3 .agents/skills/skill-creator/scripts/quick_validate.py .agents/skills/sle-adv-tlv-format
```

## 4. Editing rules

- Keep the `description` ≤ 1024 characters or `quick_validate.py` fails.
- Preserve the trigger phrases `解码/解析/检查`, `这段广播数据对不对`,
  `local_name_len + 1`, `[type][length][value]`, and the "NOT type+value unlike BLE"
  key fact — each was added to fix a measured miss.
- Keep `"sle_server" = 10 bytes` explicit; the `ble_sle_tag` oracle's `"sleserver"`
  is a different 9-byte name and has already caused one miscount.
