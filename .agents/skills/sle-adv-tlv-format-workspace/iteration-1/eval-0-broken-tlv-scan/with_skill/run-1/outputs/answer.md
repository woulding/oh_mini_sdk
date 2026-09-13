# BS21E SLE 广播扫描不到设备：根因与修复

## 结论（根因）

设备端 API 全部返回成功，是因为 SLE 协议栈**不校验广播净荷的 TLV 格式**，所以错误只在空口字节上体现。你的两段数据都违反了 SLE 广播的 TLV 编码规则：

> 空口布局是 `[type][length][value...]`，其中 `length` **只计 value 的字节数**，既不含 type，也不等于 `len(value)+1`。

具体问题来自 `sle_uart_server` 示例里的 helper 编码器（`struct sle_adv_common_value` / `sle_set_adv_data` / `sle_set_adv_local_name`）：

1. **length 全部多算了 1**：用 `sizeof(struct)-1` 得到 `2`（正确应为 `1`），于是每个 TLV 都多写一个字节。
2. **名称 TLV 的 type/length 被写反**：代码写成 `adv_data[i++] = strlen(name)+1; adv_data[i++] = TYPE;`，实际发出的是 `[length][type]`，且 length=`strlen+1`。对 `"sle_server"` 来说 0x0B 恰好又等于 `COMPLETE_LOCAL_NAME`，所以肉眼很难发现。

**为什么扫描不到**：`announce_data` 的发现等级（discovery level）TLV 被写坏 —— `01 02 01 02 02 00` 被解析成 `type=0x01 length=2 value=01 02`，随后再解析出 `type=0x02 length=0` 的零长 TLV，解析完全失步。严格的星闪调试助手会把设备判定为“不可发现”而直接隐藏；`seek_rsp_data` 的名称 TLV `0b 0b` 更是声明 length=11 但实际只有 10 字节，长度越界。设备侧 `announce enable cbk` 仍然成功，因此日志看起来一切正常。

## 解码器验证

用 `scripts/decode_sle_adv.py` 复核原始字节：

- 坏数据 `01 02 01 02 02 00` → `RESULT: SUSPECT/MALFORMED`（0x01 长度应为 1，且出现零长 TLV）
- 坏数据 `0c 02 06 0b 0b ...` → `RESULT: SUSPECT/MALFORMED`（0x0C 长度应为 1；0x0B 声明 length=11 但缓冲区只剩 10 字节，LENGTH OVERRUNS）

## 修复后的字节（可直接替换）

```
announce_data: 01 01 01 02 01 00
seek_rsp_data: 0c 01 06 0b 0a 73 6c 65 5f 73 65 72 76 65 72
```

解码结果（两段均 OK）：

```
announce_data:
  offset 0: type=0x01 (DISCOVERY_LEVEL 发现等级) length=1 value=01
  offset 3: type=0x02 (ACCESS_MODE 接入层能力)   length=1 value=00
  RESULT: OK

seek_rsp_data:
  offset 0: type=0x0C (TX_POWER_LEVEL 发送功率) length=1 value=06
  offset 3: type=0x0B (COMPLETE_LOCAL_NAME 完整名称) length=10 value='sle_server'
  RESULT: OK
```

对比（坏 → 好）：

| 字段 | 坏 | 好 | 变化 |
|---|---|---|---|
| announce 发现等级 | `01 02 01` | `01 01 01` | length 由 2 改回 1 |
| announce 接入层 | `02 02 00` | `02 01 00` | length 由 2 改回 1 |
| seek 发送功率 | `0c 02 06` | `0c 01 06` | length 由 2 改回 1 |
| seek 完整名称 | `0b 0b "sle_server"` | `0b 0a "sle_server"` | type/length 归位，length=10=strlen(name) |

## 修复做法（代码层）

1. 若是 struct helper：`{type, length, value}` 字段顺序本身没问题（type 在前），**只把 `.length` 设为真实的 value 字节数**（单字节字段就是 `1`），绝不能再用 `sizeof(struct)-1`。
2. 若是名称 helper：务必 type 在前，length 用 `strlen(name)`（不加 1）：
   ```c
   adv_data[i++] = SLE_ADV_DATA_TYPE_COMPLETE_LOCAL_NAME;  /* 0x0B */
   adv_data[i++] = strlen(name);                            /* 不是 +1 */
   memcpy(&adv_data[i], name, strlen(name));
   i += strlen(name);
   ```
3. 改完重新编译，把 `announce_data` 与 `seek_rsp_data` 的日志字节都丢进 `decode_sle_adv.py` 验证，**两段都必须解码到 OK**（只修其中一段不够，`announce_data` 的发现等级坏掉一项就足以让设备不可见）。

> 补充：若 TLV 修好后仍扫不到，再依次排查本地地址（`sle_set_local_addr()` 是否在 `sle_set_announce_param()` 之前调用、`sle_get_local_addr()` 是否非零）与角色配置（server/peripheral 需要 `SUPPORT_SLE_BLE_PERIPHERAL`，central 版不会真正发包）。
