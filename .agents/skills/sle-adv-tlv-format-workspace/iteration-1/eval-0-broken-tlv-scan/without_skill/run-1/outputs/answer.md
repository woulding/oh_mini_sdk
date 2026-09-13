# BS21E SLE Server 扫描不到：广播 TLV 长度字段多算了 1 个字节

## 一、根因

SLE 的广播数据 / 扫描响应数据由若干 AD 结构（TLV）拼接而成，格式为：

```
[type: 1 字节][length: 1 字节][value: length 字节]
```

关键点：**`length` 必须等于 value 的字节数，不包含 type 和 length 本身**（这与 BLE 的 `[length][type][value]`、且 length 含 type 的算法不同）。

日志里的两段数据恰好能证明问题是“length = value 字节数 + 1”：

```
announce_data: 01 02 01 02 02 00
  ├─ 01 02 01  -> type=0x01(发现等级), length=0x02, value=0x01   ← length 多了 1
  └─ 02 02 00  -> type=0x02(接入层能力), length=0x02, value=0x00   ← length 多了 1

seek_rsp_data: 0c 02 06 0b 0b 73 6c 65 5f 73 65 72 76 65 72
  ├─ 0c 02 06              -> type=0x0C(发送功率), length=0x02, value=0x06  ← length 多了 1
  └─ 0b 0b "sle_server"    -> type=0x0B(完整本地名称), length=0x0B, value=10 字节 ← length 多了 1
```

- 发现等级 / 接入层能力 / 发送功率的值本来都只有 **1 字节**，却被写成 `length=0x02`；
- 本地名称 `"sle_server"` 只有 **10(0x0A) 字节**，却被写成 `length=0x0B`。

解析方是严格按 `length` 跳转的：每个 TLV 都会多吞掉 1 个字节，把下一段的 `type` 当成上一段的 value，于是整条 AD 结构错位、非法，发现等级和完整名称都解析不出来。星闪调试助手按“可发现等级 / 完整名称”过滤，自然扫描不到设备。

同时，`sle_set_announce_data()` 只校验**总长度**是否越界，不做 TLV 语义校验，所以设备端依旧打印 `set announce data success`、`announce enable cbk state:0`，造成“日志全成功但扫不到”的假象。

## 二、修复后的字节

`announce_data`（6 字节，总长不变）：

```
01 01 01 02 01 00
```

- `01 01 01` = 发现等级：type=0x01, length=0x01, value=0x01（`SLE_ANNOUNCE_LEVEL_NORMAL`，一般可发现）
- `02 01 00` = 接入层能力：type=0x02, length=0x01, value=0x00

`seek_rsp_data`（15 字节，总长不变）：

```
0c 01 06 0b 0a 73 6c 65 5f 73 65 72 76 65 72
```

- `0c 01 06` = 发送功率：type=0x0C, length=0x01, value=0x06
- `0b 0a 73 6c 65 5f 73 65 72 76 65 72` = 完整本地名称：type=0x0B, length=0x0A, value=`"sle_server"`（10 字节）

修复前后总长度一致（announce 6、seek 15），只是把每个 TLV 的 length 减 1。

## 三、代码修改

文件：`applications/demo/ohos_bs21e/sle_server/src/sle_server_adv.c`
（对应 `sle_set_adv_data()` / `sle_set_scan_response_data()` / `sle_set_adv_local_name()`）

把 length 从“value 字节数 + 1”改为“value 字节数”：

```c
/* struct sle_adv_common_value { uint8_t type; uint8_t length; uint8_t value; } */

/* 发现等级：value 只有 1 字节 */
struct sle_adv_common_value adv_disc_level = {
    .length = 1,                              /* 原来是 sizeof(struct) - 1 == 2 */
    .type   = SLE_ADV_DATA_TYPE_DISCOVERY_LEVEL,
    .value  = SLE_ANNOUNCE_LEVEL_NORMAL,      /* 0x01 */
};

/* 接入层能力：value 只有 1 字节 */
struct sle_adv_common_value adv_access_mode = {
    .length = 1,                              /* 原来是 sizeof(struct) - 1 == 2 */
    .type   = SLE_ADV_DATA_TYPE_ACCESS_MODE,
    .value  = 0,
};

/* 发送功率：value 只有 1 字节 */
struct sle_adv_common_value tx_power_level = {
    .length = 1,                              /* 原来是 sizeof(struct) - 1 == 2 */
    .type   = SLE_ADV_DATA_TYPE_TX_POWER_LEVEL,
    .value  = SLE_ADV_TX_POWER,               /* 0x06 */
};

/* 本地名称：length = strlen(name)，不要 +1 */
adv_data[index++] = SLE_ADV_DATA_TYPE_COMPLETE_LOCAL_NAME;
adv_data[index++] = local_name_len;           /* 原来是 local_name_len + 1 */
memcpy_s(&adv_data[index], max_len - index, local_name, local_name_len);
```

一句话总结：SLE 的 TLV 是 `[type][length=value 字节数][value]`，把 length 里多算的那个字节去掉即可，AD 总长度不用改。
