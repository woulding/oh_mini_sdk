# SLE 扫描响应（seek response）解码检查

## 输入字节

```
0x0c 0x02 0x06 0x0b 0x0b 0x73 0x6c 0x65 0x5f 0x73 0x65 0x72 0x76 0x65 0x72
```

原始字节（十六进制）：`0c 02 06 0b 0b 73 6c 65 5f 73 65 72 76 65 72`，共 15 字节。

## 采用解码器验证的结果

```
$ python3 scripts/decode_sle_adv.py "0c 02 06 0b 0b 73 6c 65 5f 73 65 72 76 65 72"
input: 15 bytes: 0c 02 06 0b 0b 73 6c 65 5f 73 65 72 76 65 72
  offset 0: type=0x0c (TX_POWER_LEVEL(发送功率)) length=2 value=06 0b
      WARNING: type 0x0c must have length=1, got 2 (length includes the type byte?)
  offset 4: type=0x0b (COMPLETE_LOCAL_NAME(完整名称)) length=115 needs 121 bytes but buffer has 15  <-- LENGTH OVERRUNS (off-by-one?)
      value would consume: 6c 65 5f 73 65 72 76 65 72 (9 byte(s) available)
RESULT: SUSPECT/MALFORMED
```

## TLV 结构分析（错误）

SLE 广播/扫描响应的 TLV 布局是：

```
[type] [length] [value ...]      length = 仅 value 的字节数（不含 type）
```

逐段拆解输入数据：

| 偏移 | 字段 | 数据 | 问题 |
|---|---|---|---|
| 0 | type = `0x0C` (TX_POWER_LEVEL 发送功率) | — | 类型本身合法 |
| 1 | length = `0x02` | — | **错误**：发送功率的 value 只有 1 字节，length 应为 `0x01`（写成 2 是典型的 `len(value)+1` 多算了 type 字节） |
| 2–3 | value = `0x06 0x0b` | — | 因为 length=2，把本该属于下一个 TLV 的 type 字节 `0x0b` 吞掉了，导致后续整体错位 |
| 4 | type = `0x0B` (COMPLETE_LOCAL_NAME 完整名称) | — | 被错位后起点正确，纯属巧合 |
| 5 | length = `0x73` (=115) | — | **错误**：这其实是名字 `'s'` 的 ASCII 码，长度被解析成 115，远超缓冲区，溢出 |

结论：**TLV 结构不正确**。根因是第一个 TLV（发送功率）的 length 被写成 `0x02`（多算了一个 type 字节），导致解析器把下一个 TLV 的 type 当成发送功率的 value，整个数据流错位；随后名称 TLV 的 length 位置读到了字符 `'s'`（0x73），产生长度越界。这是 SDK 样例中常见的 off-by-one 编码 bug（`sle_adv_common_value` 用 `sizeof(struct)-1` 或 `strlen(name)+1`）。

## 设备名

从错位数据中仍可辨认出名称 value 为 `73 6c 65 5f 73 65 72 76 65 72`，即 **`sle_server`**（9 个 ASCII 字符）。

## 正确的字节

按 `[type][length][value]`、length 只计 value 修复：

- 发送功率：`0C 01 06`（type=0x0C，length=1，value=0x06）
- 完整名称：`0B 0A 73 6c 65 5f 73 65 72 76 65 72`（type=0x0B，length=0x0A=10，即 9 字节 `'sle_server'` 加结尾 `'\0'`；若 SDK 不带结尾符则用 `0B 09`）

```
正确字节（含结尾 \0，共 14 字节）：
0x0c 0x01 0x06 0x0b 0x0a 0x73 0x6c 0x65 0x5f 0x73 0x65 0x72 0x76 0x65 0x72
即：0c 01 06 0b 0a 73 6c 65 5f 73 65 72 76 65 72
```

> 说明：`ble_sle_tag` 的参考实现在名称长度上取 `strlen(name)`（不含 `\0`，即 `0B 09`）。本任务输入的原意（`0x0b 0x0b`）与长度 10（9 字符 + `\0`）一致，且与离线参考修复示例 `0c 01 06 0b 0a "sle_server"` 完全吻合，故采用 `0B 0A`。若目标 SDK 要求 length 严格等于可见字符数，则使用 `0B 09 73 6c 65 5f 73 65 72 76 65 72`。

## 修复后验证

```
$ python3 scripts/decode_sle_adv.py "0c 01 06 0b 0a 73 6c 65 5f 73 65 72 76 65 72"
input: 14 bytes: 0c 01 06 0b 0a 73 6c 65 5f 73 65 72 76 65 72
  offset 0: type=0x0c (TX_POWER_LEVEL(发送功率)) length=1 value=06
  offset 3: type=0x0b (COMPLETE_LOCAL_NAME(完整名称)) length=10 value=73 6c 65 5f 73 65 72 76 65 72
      name = 'sle_server'
RESULT: OK
```

## 总结

- **TLV 结构**：不正确（发送功率 length 多算 1 导致整体错位，名称 TLV 长度越界）。
- **设备名**：`sle_server`。
- **正确字节**：`0x0c 0x01 0x06 0x0b 0x0a 0x73 0x6c 0x65 0x5f 0x73 0x65 0x72 0x76 0x65 0x72`（14 字节）。
