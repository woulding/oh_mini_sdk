# SLE 扫描响应（seek response）解码分析

## 原始字节（15 字节）

```
0x0C 0x02 0x06 0x0B 0x0B 0x73 0x6C 0x65 0x5F 0x73 0x65 0x72 0x76 0x65 0x72
```

## 一、SLE AD/TLV 结构约定

SLE 广播/扫描响应由若干个 AD 元素组成，每个元素为 **TLV**：

| 字段 | 长度 | 说明 |
|------|------|------|
| Type | 1 字节 | AD 类型 |
| Length | 1 字节 | 紧随其后的 Value 字节数（**不含** Type、Length 本身）|
| Value | Length 字节 | 数据 |

常用 SLE AD 类型：

- `0x01` Discovery Level
- `0x02` Access Mode
- `0x0B` Local Name（设备名）
- `0x0C` TX Power Level
- `0xFF` Manufacturer Specific Data

## 二、逐字节解析（发现问题）

按 TLV 解析：

- **TLV1**：Type=`0x0C`（TX Power Level），Length=`0x02` → Value 取 2 字节：`0x06 0x0B`。
  - 但 TX Power Level 的 Value 只有 **1 字节**（dBm），Length 写成 `0x02` 多算了 1 个字节，把紧接着属于下一个 TLV 的 Type `0x0B` 吞掉了。
- 继续解析：剩余字节中 `0x73`（'s'）被当成 Type，`0x6C`（'l'）被当成 Length，结构彻底错乱，无法解析。

数据作者本意应为：

1. TX Power Level = 6 dBm
2. Local Name = `sle_server`

但两处 Length 都按“**包含 Type 字节**”的 BLE 写法来算（Length = Type + Value），而不是 SLE 的 Length = Value：

- 元素1：应为 `0x0C 0x01 0x06`，实际写成 `0x0C 0x02 0x06`（Length 多了 1）
- 元素2：应为 `0x0B 0x0A "sle_server"`，实际写成 `0x0B 0x0B "sle_server"`（Length 多了 1）

## 三、设备名

```
0x73 0x6C 0x65 0x5F 0x73 0x65 0x72 0x76 0x65 0x72
 s    l    e    _    s    e    r    v    e    r
```

设备名 = **`sle_server`**

## 四、结论与正确字节

- **TLV 结构：不正确。** 两个元素的 Length 字段都多计了 1 个 Type 字节，导致解析在第二个元素处错位。
- **设备名：`sle_server`**
- **正确字节（共 15 字节）：**

```
0x0C 0x01 0x06 0x0B 0x0A 0x73 0x6C 0x65 0x5F 0x73 0x65 0x72 0x76 0x65 0x72
```

正确分组：

| Type | Length | Value | 含义 |
|------|--------|-------|------|
| `0x0C` | `0x01` | `0x06` | TX Power Level = 6 dBm |
| `0x0B` | `0x0A` | `73 6C 65 5F 73 65 72 76 65 72` | Local Name = `sle_server` |
