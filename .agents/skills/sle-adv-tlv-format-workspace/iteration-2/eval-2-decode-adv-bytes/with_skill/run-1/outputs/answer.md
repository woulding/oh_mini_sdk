# SLE 扫描响应（seek response）解码与检查

## 待检查数据

```
0x0c 0x02 0x06 0x0b 0x0b 0x73 0x6c 0x65 0x5f 0x73 0x65 0x72 0x76 0x65 0x72
```

共 15 字节。设备名部分 `73 6c 65 5f 73 65 72 76 65 72` 即 ASCII 的 `sle_server`。

## 解码结果（按 `[type][length][value...]`，length 只计 value 字节）

按正确规则解析原始字节，得到的结构是：

| 偏移 | type | 名称 | length | value | 结论 |
|---|---|---|---|---|---|
| 0 | `0x0c` | TX_POWER_LEVEL(发送功率) | `0x02` | `06 0b` | **错误**：发送功率 TLV 的 length 必须为 1，这里是 2 |
| 4 | `0x0b` | COMPLETE_LOCAL_NAME(完整名称) | `0x73`(115) | — | **错误**：length 越界，需要 121 字节但缓冲区只有 15 字节 |

`scripts/decode_sle_adv.py` 输出：

```
input: 15 bytes: 0c 02 06 0b 0b 73 6c 65 5f 73 65 72 76 65 72
  offset 0: type=0x0c (TX_POWER_LEVEL(发送功率)) length=2 value=06 0b
      WARNING: type 0x0c must have length=1, got 2 (length includes the type byte?)
  offset 4: type=0x0b (COMPLETE_LOCAL_NAME(完整名称)) length=115 needs 121 bytes but buffer has 15  <-- LENGTH OVERRUNS (off-by-one?)
      value would consume: 6c 65 5f 73 65 72 76 65 72 (9 byte(s) available)
RESULT: SUSPECT/MALFORMED
```

## 结论

**TLV 结构不正确（MALFORMED / SUSPECT）**，共两处错误：

1. **发送功率 TLV 长度多 1**：`0c 02 06 0b` 中 `length=0x02` 把 type 字节也算进去了。实际只有 1 个 value 字节 `06`，应为 `0c 01 06`。（这是 `.length = sizeof(struct) - 1` 这类helper 的经典 off-by-one。）
2. **完整名称 TLV 的 type/length 顺序颠倒且长度多 1**：原始数据里是 `0b 0b 73 6c ...`，即先写 length（`strlen+1 = 11 = 0x0b`）再写 type（`0x0b`），顺序被交换，且 length 应为 `strlen = 10 = 0x0a`。正确应为 `0b 0a 73 6c ...`。

注意：对 `"sle_server"` 这个特定名字，`strlen+1 = 11 = 0x0B` 恰好等于 `COMPLETE_LOCAL_NAME` 的 type 值，所以 `0b 0b` 这种错误很容易被忽略。

## 设备名与字符数

- 设备名：`sle_server`
- 精确字符数：**10 个字符**（`s-l-e-_-s-e-r-v-e-r`，即 10 字节，无结尾 NUL）

## 正确的字节

```
0x0c 0x01 0x06 0x0b 0x0a 0x73 0x6c 0x65 0x5f 0x73 0x65 0x72 0x76 0x65 0x72
```

解码验证：

```
input: 15 bytes: 0c 01 06 0b 0a 73 6c 65 5f 73 65 72 76 65 72
  offset 0: type=0x0c (TX_POWER_LEVEL(发送功率)) length=1 value=06
  offset 3: type=0x0b (COMPLETE_LOCAL_NAME(完整名称)) length=10 value=73 6c 65 5f 73 65 72 76 65 72
      name = 'sle_server'
RESULT: OK
```

- `0c 01 06`：发送功率，length=1，value=`0x06`
- `0b 0a 73 6c 65 5f 73 65 72 76 65 72`：完整名称，length=10，value=`"sle_server"`
- 总长 3 + 2 + 10 = 15 字节，所有 TLV 解码无越界，消费字节数等于缓冲区长度，`RESULT: OK`。
