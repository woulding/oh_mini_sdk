---
name: sle-adv-tlv-format
description: >-
  Decode, check, or fix SLE / 星闪 (NearLink) broadcast TLV bytes. Use whenever the
  user pastes raw SLE announce / scan-response hex and asks to 解码/解析/检查 it or "这段
  广播数据对不对", or asks what bytes a TLV should be, why `sle_set_adv_local_name`
  writes `local_name_len + 1`, whether SLE length counts the type byte, or how to
  encode discovery level 发现等级 / access mode / TX power / complete local name 完整
  名称 (e.g. the name-length for "sle_server"). Also use when a 星闪 SLE device is
  invisible to 星闪调试助手 / a phone scanner although "set announce data success" and
  sle_start_announce succeed, or when porting/fixing announce_data / seek_rsp_data /
  adv_data code (sle_set_announce_data, sle_set_adv_data, sle_set_scan_response_data,
  sle_adv_common_value, g_sle_adv_data, sle_uart_server) in HiSilicon FBB LiteOS /
  OpenHarmony SDKs. Key fact: SLE is [type][length][value] with length = VALUE bytes
  only, NOT type+value unlike BLE; several SDK samples get this wrong. Not for general
  BLE GATT questions.
---

# SLE (星闪) announce / scan-response TLV layout

## The one rule

SLE broadcast data is a concatenation of TLVs with the byte layout:

```
[type] [length] [value ...]      length = number of VALUE bytes (type NOT counted)
```

`type` comes first, `length` second, and `length` does **not** include the type byte
and must **not** be `len(value)+1`. Everything in this skill follows from that.

## Symptom this skill prevents

The firmware logs look completely healthy:

```
[sle server] set announce data success.
[ACore] sle adv cbk in, event:0..3 status:0
[sle server] sle announce enable cbk id:01, state:0
```

…and the phone / 星闪调试助手 still lists **no device**. A malformed announce TLV
(often the discovery-level field) can make a strict scanner decide the device is not
discoverable and hide it. The SLE APIs never validate the payload, so the bug is
silent on the device side and only visible in the raw bytes on the air.

## Ground truth: the hand-crafted reference

Do not trust the helper-based encoders in most samples. The trustworthy reference is
the hand-written byte arrays in:

```
device/soc/hisilicon/<soc>/sdk/application/samples/products/ble_sle_tag/sle_server/sle_server_adv.c
```

Its scan response is `{ 0x0B, 0x09, 's','l','e','s','e','r','v','e','r' }`, which
decodes as `type=0x0B` (COMPLETE_LOCAL_NAME), `length=0x09`, 9 value bytes — exactly
the rule above. Its 29-byte `g_sle_adv_data` decodes cleanly into three TLVs
(`01`/`1`, `05`/`4`, `03`/`18`) and sums to 29. Use it as the oracle.

**Count the name characters carefully** — `length` is the number of visible
characters, with no trailing NUL, and the reference name is easy to miscount. The
`ble_sle_tag` oracle uses the 9-character name `"sleserver"` (`0B 09 ...`), while the
ohos `sle_server` demo uses the 10-character name `"sle_server"` (`0B 0A ...`).
`"sle_server"` is s-l-e-_-s-e-r-v-e-r = **10** bytes, not 9. When in doubt, count with
`len(name)` / `strlen(name)`, never reuse the oracle's length byte.

## The trap: the sle_uart_server helper encoder

Many samples share `struct sle_adv_common_value` plus a `sle_set_adv_data` /
`sle_set_adv_local_name` pair. Several variants of it are buggy:

- `struct sle_adv_common_value { uint8_t type; uint8_t length; uint8_t value; }`
  with `.length = sizeof(struct) - 1` writes `length = 2` for a 1-byte value
  (should be `1`) — every TLV is off by one.
- Some name helpers write `adv_data[i++] = strlen(name) + 1; adv_data[i++] = TYPE;`
  — that emits `[length][type]`, i.e. the order is **swapped**, and the length is
  `strlen+1` instead of `strlen`. For the specific name `"sle_server"` this can look
  accidentally correct (`11 == 0x0B == COMPLETE_LOCAL_NAME`) which is why it survives
  casual inspection.

Real before/after from an OHOS bs21e port (`src/sle_server_adv.c`):

```
# broken (sle_uart helper): lengths all +1, name type/length swapped
announce_data: 01 02 01 02 02 00
seek_rsp_data: 0c 02 06 0b 0b "sle_server"

# fixed ([type][length][value], length = value bytes)
announce_data: 01 01 01 02 01 00
seek_rsp_data: 0c 01 06 0b 0a "sle_server"
```

## Correct encoding recipe

| field | bytes |
|---|---|
| discovery level (发现等级) | `01 01 <SLE_ANNOUNCE_LEVEL_NORMAL>` |
| access mode (接入层能力) | `02 01 00` |
| TX power (发送功率) | `0C 01 <dbm>` |
| complete local name (完整名称) | `0B <strlen(name)> <name bytes>` |
| 16-bit service data | `03 <n> <uuid...> <data...>` |

If you keep the struct helper, its `{type, length, value}` field order is fine
(type-first) — only set `.length` to the true value-byte count (usually `1`), and
never `sizeof(struct)-1`. For the name, always emit type first:
`adv_data[i++] = SLE_ADV_DATA_TYPE_COMPLETE_LOCAL_NAME; adv_data[i++] = strlen(name);`
then copy the name.

## Always verify with the decoder

After changing ADV code, rebuild and paste the logged byte dumps into
`scripts/decode_sle_adv.py`. Every TLV must decode without the length overrunning the
buffer, and the consumed bytes must equal the reported length.

```bash
python3 scripts/decode_sle_adv.py "01 01 01 02 01 00"
python3 scripts/decode_sle_adv.py "0c 01 06 0b 0a 73 6c 65 5f 73 65 72 76 65 72"
```

The decoder flags a length that overruns the buffer — the exact off-by-one symptom.
Do this for BOTH `announce_data` and `seek_rsp_data`; a broken discovery-level TLV in
`announce_data` alone is enough to make the device invisible.

## Related checks (only after the TLVs decode cleanly)

If the TLVs are well-formed and the device is still invisible:

- **Local address**: call `sle_set_local_addr()` before `sle_set_announce_param()`
  (`ble_sle_tag` does this; `sle_uart_server` does not and relies on a factory/NV
  address). Log `sle_get_local_addr()` to confirm it is non-zero.
- **Role/config**: a product built for the SLE/BLE *central* role
  (`CONFIG_SUPPORT_SLE_BLE_CENTRAL_DEFAULT=y`) may not actually put announces on the
  air. Server/peripheral products add `SUPPORT_SLE_BLE_PERIPHERAL` and link the
  peripheral prebuilt protocol libs.
- **Do the business in a task, not in the enable callback**: register callbacks, call
  `enable_sle()`, poll a flag set by the enable callback, then add the service and
  start announcing from the task context (the `ble_sle_tag` pattern). This avoids
  blocking the SLE service thread.

These are secondary — fix the TLV bytes first, because they are the most common cause
of "host says OK, scanner sees nothing".
