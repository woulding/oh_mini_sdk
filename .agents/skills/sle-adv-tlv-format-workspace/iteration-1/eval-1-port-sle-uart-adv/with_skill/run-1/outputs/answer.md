# 把 sle_uart_server 的 SLE 广播构造移植到 OHOS `applications/demo/ohos_bs21e/sle_server` —— 坑与可用代码

## 0. 一句话结论

SLE 广播/扫描响应是一个个 TLV 直接拼在缓冲区里，空中布局固定为：

```
[type] [length] [value ...]      length = value 的字节数（不含 type，也不是 len+1）
```

设备端 API 从不校验这个 payload，所以你即使把 `length` 写错，`sle_set_announce_data` 依然返回成功、`announce enable` 回调依然是 `state:0`，但手机上的星闪调试助手会因为发现等级/名字 TLV 畸形而把设备判定为"不可发现"，直接扫描不到。**修复必须先改字节，再查地址/角色。**

---

## 1. 直接照抄 `sle_uart_server_adv.c` 会踩的坑

对照 `device/soc/hisilicon/bs2xv107/sdk/application/samples/products/sle_uart/sle_uart_server/sle_uart_server_adv.c`：

1. **扫描响应里 TX Power 的长度多算了 1**（`:114`）：
   ```c
   size_t scan_rsp_data_len = sizeof(struct sle_adv_common_value);   // = 3
   struct sle_adv_common_value tx_power_level = {
       .length = scan_rsp_data_len - 1,   // ← 3-1 = 2，错！应为 1
       .type = SLE_ADV_DATA_TYPE_TX_POWER_LEVEL,
       .value = SLE_ADV_TX_POWER,
   };
   ```
   输出 `0c 02 06`，把下一个 TLV 的 type 字节吞掉，整个 seek response 解析错位。
   实测（`decode_sle_adv.py`）原始样例名 `sle_uart_server` 时：
   ```
   seek: 0c 02 06 10 0b 73 6c 65 5f 75 61 72 74 5f 73 65 72 76 65 72
   offset 0: type=0x0c (TX_POWER_LEVEL) length=2 ... WARNING: 必须 length=1
   offset 4: type=0x0b (COMPLETE_LOCAL_NAME) length=115 ... LENGTH OVERRUNS
   RESULT: SUSPECT/MALFORMED
   ```

2. **本地名 helper 把 type/length 顺序写反，且长度 +1**（`:62-63`）：
   ```c
   adv_data[index++] = local_name_len + 1;                       // 先写 length+1（错）
   adv_data[index++] = SLE_ADV_DATA_TYPE_COMPLETE_LOCAL_NAME;    // 后写 type（错）
   ```
   应该是 `[type][length]`，且 `length = strlen(name)`。
   最阴的一点：如果你的名字恰好是 `"sle_server"`（strlen=10），`10+1 == 0x0B`，而 `0x0B` 正好又是 COMPLETE_LOCAL_NAME 的 type，于是 `0b 0b` 看起来"像个正经 TLV"，肉眼很容易放过。真正的名字 TLV 应为 `0b 0a "sle_server"`。

3. **依赖 `sizeof(struct)` / `sizeof(array)-1` 这种表达式**。原 `sle_set_adv_data()`（`:80,83`）用 `.length = len - 2`、`len = sizeof(struct sle_adv_common_value)`。这个结构体只有 3 个 `uint8_t`、无 padding 时 size=3，所以 `len-2=1` 恰好正确——**但这是巧合，不是规则**。一旦编译器加 padding、或你给结构体加字段，就立刻错位。部分 SDK 变体写的是 `.length = sizeof(struct) - 1`（=2），于是连 announce 的发现等级都变成 `01 02 01 ...`：
   ```
   announce: 01 02 01 02 02 00
   offset 0: type=0x01 (DISCOVERY_LEVEL) length=2 ... WARNING
   offset 4: type=0x02 (ACCESS_MODE)    length=0 ... WARNING zero-length
   RESULT: SUSPECT/MALFORMED
   ```
   一个坏的发现等级 TLV 就足以让设备在扫描列表里消失。

4. **别用 `memcpy_s(..., struct, sizeof(struct))` 去凑 TLV**。广播字节流的语义是逐字节 TLV，不是结构体快照。移植时最稳的是**显式逐字节写**，或写一个统一的 append 函数。

5. **长度上限与缓冲**：`SLE_ADV_DATA_LEN_MAX = 251`，`memcpy_s` 的 destSize 要传剩余容量 `cap - idx`，否则越界或返回失败被当成 `len=0` 静默丢掉整段数据。名字长度要 `strlen`，**不要**把结尾 `'\0'` 或数组空洞算进去。

6. **名字只出现在扫描响应（seek_rsp_data）里**。星闪调试助手列表显示的就是这个 `COMPLETE_LOCAL_NAME`；写错 type/长度会导致连接前就无法识别。

7. **次要因素（TLV 修好后再查）**：
   - 本地地址：`sle_uart_server` 没有 `sle_set_local_addr()`，靠出厂/NV 地址；模组没烧地址时广播地址非法 → 扫描不到。OHOS demo 里显式设置（`ble_sle_tag` 的做法，参考已移植的 `sle_server_adv.c:135`）。
   - 角色：如果是 central-only 的配置，可能根本不上报广播；server/peripheral 产品要开 `SUPPORT_SLE_BLE_PERIPHERAL` 并链 peripheral 预编译协议库。
   - **业务不要放在 enable 回调里**：回调运行在 SLE service 线程，只置标志；在应用任务里轮询标志后注册 service、启动广播（`ble_sle_tag` 模式）。

> 参考：本仓库已移植好的 `applications/demo/ohos_bs21e/sle_server/src/sle_server_adv.c` 已经把上面 1、2 两点改对了（`:62-66` 名字顺序、`:82-98`/`:116-120` 长度固定为 1）。
> 可信 oracle 是 `ble_sle_tag/sle_server/sle_server_adv.c` 的手写数组：seek = `{0x0B, 0x09, 's','l','e','s','e','r','v','e','r'}`。

---

## 2. 可直接使用的广播构造代码

建议不要再 `memcpy` 结构体，用一个带容量检查的 TLV 追加器，语义清楚、永不差一。把下面代码放进 `applications/demo/ohos_bs21e/sle_server/src/sle_server_adv.c`（替换原来的 `sle_set_adv_data` / `sle_set_scan_response_data` / `sle_set_adv_local_name`）。

```c
#include "securec.h"
#include "sle_common.h"
#include "sle_device_discovery.h"
#include "sle_errcode.h"
#include "sle_server_adv.h"

#define SLE_ADV_DATA_LEN_MAX        251
#define SLE_ADV_HANDLE_DEFAULT      1
#define SLE_ADV_TX_POWER            6

/* 星闪调试助手上显示/过滤用的名字；只算字符，不含结尾 '\0' */
static const char g_sle_local_name[] = "sle_server";

/* 带容量检查的 TLV 写入器：统一保证 [type][length][value]，length 只数 value */
typedef struct {
    uint8_t *buf;
    uint16_t cap;
    uint16_t len;
} sle_tlv_writer_t;

static bool sle_tlv_put(sle_tlv_writer_t *w, uint8_t type, const uint8_t *value, uint8_t value_len)
{
    if (w->buf == NULL || (uint32_t)w->len + 2u + value_len > w->cap) {
        return false;
    }
    w->buf[w->len++] = type;
    w->buf[w->len++] = value_len;              /* 关键：只算 value 字节，不含 type */
    if (value_len != 0) {
        if (memcpy_s(&w->buf[w->len], w->cap - w->len, value, value_len) != EOK) {
            return false;
        }
        w->len += value_len;
    }
    return true;
}

/* announce_data：发现等级 + 接入层能力。
 * 发现等级是一字节，长度必须=1，否则调试助手认为设备不可发现。 */
static uint16_t sle_server_build_announce_data(uint8_t *buf, uint16_t cap)
{
    sle_tlv_writer_t w = { buf, cap, 0 };
    uint8_t disc_level = (uint8_t)SLE_ANNOUNCE_LEVEL_NORMAL;  /* 通常 0x01 */
    uint8_t access_mode = 0x00;

    if (!sle_tlv_put(&w, SLE_ADV_DATA_TYPE_DISCOVERY_LEVEL, &disc_level, 1) ||
        !sle_tlv_put(&w, SLE_ADV_DATA_TYPE_ACCESS_MODE, &access_mode, 1)) {
        return 0;
    }
    return w.len;
}

/* seek_rsp_data（扫描响应）：发送功率 + 完整本地名。
 * 名字长度用 strlen，千万不要 +1，也不要把 '\0' 算进去。 */
static uint16_t sle_server_build_seek_rsp_data(uint8_t *buf, uint16_t cap)
{
    sle_tlv_writer_t w = { buf, cap, 0 };
    uint8_t tx_power = SLE_ADV_TX_POWER;
    uint8_t name_len = (uint8_t)(sizeof(g_sle_local_name) - 1);  /* 不含 '\0' */

    if (!sle_tlv_put(&w, SLE_ADV_DATA_TYPE_TX_POWER_LEVEL, &tx_power, 1) ||
        !sle_tlv_put(&w, SLE_ADV_DATA_TYPE_COMPLETE_LOCAL_NAME,
                     (const uint8_t *)g_sle_local_name, name_len)) {
        return 0;
    }
    return w.len;
}
```

接着在原来的 `sle_set_default_announce_data()` 里这样用（其余参数配置不变）：

```c
static int sle_server_set_default_announce_data(void)
{
    errcode_t ret;
    sle_announce_data_t data = {0};
    uint8_t adv_handle = SLE_ADV_HANDLE_DEFAULT;
    static uint8_t announce_data[SLE_ADV_DATA_LEN_MAX] = {0};
    static uint8_t seek_rsp_data[SLE_ADV_DATA_LEN_MAX] = {0};
    uint16_t announce_len, seek_len, i;

    announce_len = sle_server_build_announce_data(announce_data, sizeof(announce_data));
    seek_len     = sle_server_build_seek_rsp_data(seek_rsp_data, sizeof(seek_rsp_data));
    if (announce_len == 0 || seek_len == 0) {
        sample_log_print("%s build adv data fail\r\n", SLE_SERVER_LOG);
        return ERRCODE_SLE_FAIL;
    }

    data.announce_data = announce_data;
    data.announce_data_len = announce_len;
    data.seek_rsp_data = seek_rsp_data;
    data.seek_rsp_data_len = seek_len;

    sample_log_print("%s announce(%u): ", SLE_SERVER_LOG, announce_len);
    for (i = 0; i < announce_len; i++) {
        sample_log_print("0x%02x ", announce_data[i]);
    }
    sample_log_print("%s seek(%u): ", SLE_SERVER_LOG, seek_len);
    for (i = 0; i < seek_len; i++) {
        sample_log_print("0x%02x ", seek_rsp_data[i]);
    }
    sample_log_print("\r\n");

    ret = sle_set_announce_data(adv_handle, &data);
    if (ret != ERRCODE_SLE_SUCCESS) {
        sample_log_print("%s set announce data fail:0x%x\r\n", SLE_SERVER_LOG, ret);
        return ret;
    }
    sample_log_print("%s set announce data success.\r\n", SLE_SERVER_LOG);
    return ERRCODE_SLE_SUCCESS;
}
```

上面这段的期望输出（会用第 3 节验证）：

```
announce(6):  01 01 01 02 01 00
seek(15):     0c 01 06 0b 0a 73 6c 65 5f 73 65 72 76 65 72
                    └── type=0x0C, length=1, value=06 (TX power)
                         type=0x0B, length=0x0A(=10), value="sle_server"
```

如果你更想"和 `ble_sle_tag` 完全一样的 29 字节 announce"，也可以直接用手写数组（永不差一）：

```c
static uint8_t g_adv_data[29] = {
    0x01, 0x01, 0x01,                     /* discovery level = 1 */
    0x05, 0x04, 0x0B, 0x06, 0x09, 0x06,   /* 16-bit service uuids */
    0x03, 0x12, 0x09, 0x06, 0x07, 0x03, 0x02, 0x05, 0x00, 0x06, 0x09,
    0x73, 0x6c, 0x65, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72,   /* "sleserver" */
};
/* seek response: 0b 09 73 6c 65 73 65 72 76 65 72 */
```

---

## 3. 落地自检（务必对两段都跑）

改完编译前，先把设备日志里打印的原始字节粘进本 skill 的 decoder：

```bash
python3 .agents/skills/sle-adv-tlv-format/scripts/decode_sle_adv.py "01 01 01 02 01 00"
python3 .agents/skills/sle-adv-tlv-format/scripts/decode_sle_adv.py "0c 01 06 0b 0a 73 6c 65 5f 73 65 72 76 65 72"
```

判定标准：每个 TLV 都能解析、`length` 不越界、消费字节数 == 上报长度、名字打印为 `'sle_server'`，输出 `RESULT: OK`。**只修 announce 或只修 seek 都不够**——只要有一个 TLV 畸形，调试助手就可能扫不到。

对照解码结果（已用本 skill 脚本实测）：

| 数据 | 字节 | 结果 |
|---|---|---|
| 修复后 announce | `01 01 01 02 01 00` | `RESULT: OK` |
| 修复后 seek | `0c 01 06 0b 0a 73 6c 65 5f 73 65 72 76 65 72`，name=`'sle_server'` | `RESULT: OK` |
| 坏 announce（`sizeof-1`） | `01 02 01 02 02 00` | `SUSPECT/MALFORMED` |
| 坏 seek（原样例） | `0c 02 06 10 0b 73 6c 65 5f 75 61 72 74 5f 73 65 72 76 65 72` | `LENGTH OVERRUNS` |

TLV 全部 OK 后若仍扫不到，再依次检查：`sle_set_local_addr()` 是否在 `sle_set_announce_param()` 之前调用且地址非零；产品是否具备 peripheral 角色；注册 service / 启动广播是否在应用任务里（而非 enable 回调）执行。
