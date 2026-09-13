# 将 sle_uart_server 广播配置移植到 applications/demo/ohos_bs21e/sle_server

目标文件：`applications/demo/ohos_bs21e/sle_server/src/sle_server_adv.c`
参考源：`device/soc/hisilicon/bs2xv107/sdk/application/samples/products/sle_uart/sle_uart_server/sle_uart_server_adv.{c,h}`

结论先说：**原 SDK 的广播数据构造本身有“半截 BLE 风格”的坑，直接照抄会出现“能扫到设备但名字乱码/按名字过滤扫不到/后续 TLV 被吞”。** 下面逐条说明，再给可直接使用的构造代码。

---

## 一、移植广播数据构造部分的坑

### 1. TLV 字节序：SLE 是 `[type][length][value]`，不是 BLE 的 `[length][type][value]`

SLE 广播数据（设备公开数据）的权威编码见
`device/soc/hisilicon/bs2xv107/sdk/application/samples/bt/sle/service_common.c`：

```c
typedef struct {           /* service_common.h */
    uint8_t data_type;
    uint8_t data_len;
    uint8_t data[0];
} sle_service_adv_encode_data;
```

即先 `type` 后 `length`，并且 **`length` 是 value 的字节数，不包含 type/length 自身**。
`ble_sle_tag/sle_server/sle_server_adv.c` 里硬编码的那段广播数据也只有按
`[type][length][value]` 才能解析通（`01 01 01` = 发现等级/TLV长1/值1，
`0B 0A "sle_server"` = 完整本地名/TLV长10）。

**但原 `sle_uart_server_adv.c` 的本地名称函数写反了**：

```c
/* 原代码（错误示范） */
adv_data[index++] = local_name_len + 1;                 /* 把“长度”写在了 type 位置 */
adv_data[index++] = SLE_ADV_DATA_TYPE_COMPLETE_LOCAL_NAME; /* 把 type 写在了 length 位置 */
```

它生成的是 BLE 风格 `[name_len+1][0x0B][name...]`。手机星闪调试助手是按 SLE TLV 解析的，
会把 `name_len+1` 当成 type、把 `0x0B` 当成 length，于是 name 只被读走 11 个字节，
剩下几个字节又被当成下一条 TLV 的头，**名称乱码，后续 TLV 解析错位**。如果助手按设备名过滤，
就直接“扫不到”。正确写法是：

```c
adv[index++] = SLE_ADV_DATA_TYPE_COMPLETE_LOCAL_NAME; /* type */
adv[index++] = (uint8_t)strlen(name);                  /* value 字节数 */
memcpy(&adv[index], name, strlen(name));
```

> 注意：SDK 自带 client 用 `strstr(data, SERVER_NAME)` 找名字，不解析 TLV，所以老样例“看起来能用”；
> 手机助手是严格解析 TLV 的，移植到 OHOS 后必须按规范改对。

### 2. `struct sle_adv_common_value` 的字段顺序 = 线上字节顺序

原代码把结构体直接 `memcpy` 进广播缓冲区，所以**字段声明顺序就是广播线上的顺序**。
`products/sle_uart/.../sle_uart_server_adv.h` 是 `{type, length, value}`（恰好正确），
但 `products/sle_measure_dis/.../sle_measure_dis_server_adv.c` 里同名结构是
`{length, type, value}`（反的）。移植时如果不小心复制了后者，整段 TLV 会整体反序。
最稳的做法是**不要用这个结构体，直接逐字节写**（见下方代码）。

### 3. `length` 的取值，各样例互相矛盾，必须只填 value 的真实字节数

| 来源 | 单值 TLV 的 length | 名称 TLV |
|---|---|---|
| `sle_uart_server_adv.c` | `.length = sizeof(struct)-2` = 1 ✅ | `name_len+1` ❌ |
| `sle_measure_dis_server_adv.c` | `.length = sizeof(struct)-1` = 2 ❌ | `name_len+1` ❌ |
| `ws63 .../sle_uuid_server` | `.length = sizeof(struct)-1` = 2 ❌ | `name_len+1` ❌ |
| 权威 `service_common.c` | `data_len = value 实际长度` ✅ | — |

单字节 value（发现等级、接入能力、发射功率）的 `length` 必须是 `1`。
填成 `2` 会把下一条 TLV 的第一个字节当成本条 value，导致后面全部错位。

### 4. 名称长度不要用 `sizeof(array)-1`

原代码 `NAME_MAX_LENGTH 16` 配 `"sle_uart_server"`（15 字符）刚好等于 `sizeof-1`，
一旦改名或换缓冲区，`sizeof-1` 会把数组里的 `\0`/残留数据算进去。
用 `strlen()`；若用字符串字面量初始化，则 `sizeof(str)-1` 才可靠。

### 5. 广播数据 vs 扫描响应数据放错位置

原 SDK 的布局是：`announce_data` 放“发现等级 + 接入层能力”，
`seek_rsp_data` 放“发射功率 + 完整本地名”。手机通常要**主动扫描**才拿得到 seek response。
如果只填 `announce_data`、`seek_rsp_data_len` 留 0，或手机只显示地址不显示名字，
可以把本地名也放进 `announce_data`，或者调用协议栈 `sle_set_local_name()` 让栈自己带。
（`dis/dis_server.c` 现在就是用 `sle_set_local_name(dev_name, len)`，不再手搓 0x0B TLV。）

### 6. 缓冲区生命周期

原代码用函数栈上的 `uint8_t announce_data[251]`，把指针赋给 `sle_announce_data_t` 后调用
`sle_set_announce_data()`。若协议栈是异步持有该指针，函数返回后就是悬空指针，广播内容变随机。
移植后**用 `static`/全局缓冲区**。

### 7. 调用时序：先使能，再设参数/数据，最后 start

`enable_sle()` 是异步的，要在 `sle_enable_cb` 置位后（任务上下文）再
`sle_set_announce_param` → `sle_set_announce_data` → `sle_start_announce`。
不要在 SLE service 回调线程里直接做这些耗时/阻塞动作（原 `sle_enable_cbk` 直接
`sle_enable_server_cbk()` 的写法在 OHOS 里要改成“置标志 + 任务轮询”）。

### 8. 本端地址（影响手机能否“扫描到/连接”）

不要像原代码那样把 `param.own_addr` 留全 0 又不设置地址。模组没烧有效地址时手机上可能
看不到或连不上。先 `sle_set_local_addr()` 一个合法地址，再 `sle_set_announce_param()`。

### 9. 其它小事

- 结构体 `{uint8_t,uint8_t,uint8_t}` 正好 3 字节无 padding，别随手加字段/换 `uint16_t`。
- 长度统一用 `uint16_t`（原代码有些是 `uint8_t`，虽然 251 不溢出）。
- 日志用 OHOS 的 `soc_osal.h` / `osal_printk`；`osal_debug.h`、`product.h` 是 LiteOS SDK 专有，别 include。
- `sle_adv_put_tlv` 里做容量检查，防止 `max_len - index` 下溢。

---

## 二、可直接使用的构造代码

将下面内容替换/合并进 `applications/demo/ohos_bs21e/sle_server/src/sle_server_adv.c`。
（`SLE_ADV_HANDLE_DEFAULT`、`SLE_ADV_CHANNEL_MAP_DEFAULT` 等宏沿用本 demo 头文件即可。）

```c
#include <string.h>
#include "securec.h"
#include "sle_common.h"
#include "sle_device_discovery.h"
#include "sle_errcode.h"
#include "soc_osal.h"

/* ---- 广播数据类型（与 sle_server_adv.h 的枚举保持一致） ---- */
#define SLE_ADV_TYPE_DISCOVERY_LEVEL        0x01
#define SLE_ADV_TYPE_ACCESS_MODE            0x02
#define SLE_ADV_TYPE_COMPLETE_LOCAL_NAME    0x0B
#define SLE_ADV_TYPE_TX_POWER_LEVEL         0x0C

#define SLE_ADV_HANDLE_DEFAULT              1
#define SLE_ADV_DATA_LEN_MAX                251
#define SLE_ANNOUNCE_LEVEL_NORMAL           0x01
#define SLE_ADV_TX_POWER                    6

/* 星闪调试助手看到的设备名，按需修改 */
static const uint8_t g_sle_local_name[] = "sle_server";

#define SLE_ADV_LOG_TAG "[sle adv]"
#define sle_adv_log(fmt, ...) osal_printk(fmt, ##__VA_ARGS__)

/*
 * 写入一条 SLE 广播 TLV。
 * SLE 广播数据格式（对齐 service_common.c / ble_sle_tag）：
 *     +--------+----------+-------------------+
 *     |  type  |  length  |       value       |
 *     |  1Byte |  1Byte   |    length Byte    |
 *     +--------+----------+-------------------+
 * length = value 的字节数，不含 type/length 自身。
 */
static uint16_t sle_adv_put_tlv(uint8_t *buf, uint16_t buf_len, uint16_t off,
                                uint8_t type, const uint8_t *value, uint8_t value_len)
{
    if ((uint32_t)off + 2u + value_len > (uint32_t)buf_len) {
        sle_adv_log("%s TLV(0x%02x) overflow off=%u len=%u cap=%u\r\n",
                    SLE_ADV_LOG_TAG, type, off, value_len, buf_len);
        return off;
    }
    buf[off++] = type;
    buf[off++] = value_len;
    if (value_len > 0 && value != NULL) {
        if (memcpy_s(&buf[off], buf_len - off, value, value_len) != EOK) {
            return (uint16_t)(off - 2); /* 回滚，不产生半条 TLV */
        }
    }
    return (uint16_t)(off + value_len);
}

/* 主广播数据：发现等级 + 接入层能力（保证能被扫描到） */
static uint16_t sle_build_announce_data(uint8_t *adv_data, uint16_t max_len)
{
    uint16_t idx = 0;
    uint8_t disc_level = SLE_ANNOUNCE_LEVEL_NORMAL; /* 0x01 */
    uint8_t access_mode = 0x00;                     /* 接入层能力，透传填 0 */

    idx = sle_adv_put_tlv(adv_data, max_len, idx,
                          SLE_ADV_TYPE_DISCOVERY_LEVEL, &disc_level, sizeof(disc_level));
    idx = sle_adv_put_tlv(adv_data, max_len, idx,
                          SLE_ADV_TYPE_ACCESS_MODE, &access_mode, sizeof(access_mode));
    return idx;
}

/* 扫描响应数据：发射功率 + 完整本地名（手机显示的名字来自这里） */
static uint16_t sle_build_scan_rsp_data(uint8_t *rsp_data, uint16_t max_len)
{
    uint16_t idx = 0;
    int8_t tx_power = SLE_ADV_TX_POWER;

    idx = sle_adv_put_tlv(rsp_data, max_len, idx,
                          SLE_ADV_TYPE_TX_POWER_LEVEL,
                          (const uint8_t *)&tx_power, sizeof(tx_power));
    idx = sle_adv_put_tlv(rsp_data, max_len, idx,
                          SLE_ADV_TYPE_COMPLETE_LOCAL_NAME,
                          g_sle_local_name,
                          (uint8_t)(sizeof(g_sle_local_name) - 1)); /* 不含结尾 '\0' */
    return idx;
}

/* 配置广播参数 + 广播数据并启动。必须在本端地址有效、SLE 使能完成后调用。 */
errcode_t sle_server_adv_init(void)
{
    /* ---------- 1. 设置本端地址（模组未烧录地址时尤其重要） ---------- */
    static const uint8_t local_addr[SLE_ADDR_LEN] = { 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 };
    sle_addr_t addr = {0};
    addr.type = 0; /* public */
    if (memcpy_s(addr.addr, SLE_ADDR_LEN, local_addr, SLE_ADDR_LEN) != EOK) {
        return ERRCODE_SLE_FAIL;
    }
    (void)sle_set_local_addr(&addr);

    /* ---------- 2. 广播参数：必须 Connectable + Scannable 手机才能连 ---------- */
    sle_announce_param_t param = {0};
    param.announce_mode = SLE_ANNOUNCE_MODE_CONNECTABLE_SCANABLE;
    param.announce_handle = SLE_ADV_HANDLE_DEFAULT;
    param.announce_gt_role = SLE_ANNOUNCE_ROLE_T_CAN_NEGO;
    param.announce_level = SLE_ANNOUNCE_LEVEL_NORMAL;
    param.announce_channel_map = SLE_ADV_CHANNEL_MAP_DEFAULT;
    param.announce_interval_min = 0xC8; /* 25ms, 单位125us */
    param.announce_interval_max = 0xC8;
    param.conn_interval_min = 0x64;     /* 12.5ms, 单位125us */
    param.conn_interval_max = 0x64;
    param.conn_max_latency = 0x1F3;
    param.conn_supervision_timeout = 0x1F4;
    param.own_addr.type = 0;
    if (memcpy_s(param.own_addr.addr, SLE_ADDR_LEN, local_addr, SLE_ADDR_LEN) != EOK) {
        return ERRCODE_SLE_FAIL;
    }
    errcode_t ret = sle_set_announce_param(param.announce_handle, &param);
    if (ret != ERRCODE_SLE_SUCCESS) {
        sle_adv_log("%s set_announce_param fail:0x%x\r\n", SLE_ADV_LOG_TAG, ret);
        return ret;
    }

    /* ---------- 3. 广播数据：用 static 缓冲区，别把栈上数组交给协议栈 ---------- */
    static uint8_t s_announce_data[SLE_ADV_DATA_LEN_MAX];
    static uint8_t s_seek_rsp_data[SLE_ADV_DATA_LEN_MAX];
    (void)memset_s(s_announce_data, sizeof(s_announce_data), 0, sizeof(s_announce_data));
    (void)memset_s(s_seek_rsp_data, sizeof(s_seek_rsp_data), 0, sizeof(s_seek_rsp_data));

    sle_announce_data_t data = {0};
    data.announce_data = s_announce_data;
    data.announce_data_len = sle_build_announce_data(s_announce_data, sizeof(s_announce_data));
    data.seek_rsp_data = s_seek_rsp_data;
    data.seek_rsp_data_len = sle_build_scan_rsp_data(s_seek_rsp_data, sizeof(s_seek_rsp_data));

    sle_adv_log("%s announce_data(%u): ", SLE_ADV_LOG_TAG, data.announce_data_len);
    for (uint16_t i = 0; i < data.announce_data_len; i++) {
        sle_adv_log("%02x ", data.announce_data[i]);
    }
    sle_adv_log("\r\n%s seek_rsp_data(%u): ", SLE_ADV_LOG_TAG, data.seek_rsp_data_len);
    for (uint16_t i = 0; i < data.seek_rsp_data_len; i++) {
        sle_adv_log("%02x ", data.seek_rsp_data[i]);
    }
    sle_adv_log("\r\n");

    ret = sle_set_announce_data(SLE_ADV_HANDLE_DEFAULT, &data);
    if (ret != ERRCODE_SLE_SUCCESS) {
        sle_adv_log("%s set_announce_data fail:0x%x\r\n", SLE_ADV_LOG_TAG, ret);
        return ret;
    }

    /* ---------- 4. 启动广播 ---------- */
    ret = sle_start_announce(SLE_ADV_HANDLE_DEFAULT);
    if (ret != ERRCODE_SLE_SUCCESS) {
        sle_adv_log("%s start_announce fail:0x%x\r\n", SLE_ADV_LOG_TAG, ret);
    }
    return ret;
}
```

### 自检：用默认名 `"sle_server"`(10 字节) 时，串口应打印

```
announce_data(6):   01 01 01  02 01 00
seek_rsp_data(15):  0c 01 06  0b 0a 73 6c 65 5f 73 65 72 76 65 72
                    └tx power┘ └0x0B,len=10,"sle_server"┘
```

如果打印出来的名称段前面是 `0b <name_len>` 就对了；若是 `<name_len+1> 0b`，说明还在用老的
BLE 风格写法，手机助手里名称会乱码。

拿到广播后，再确认：`announce_mode` 是 `SLE_ANNOUNCE_MODE_CONNECTABLE_SCANABLE`、
SLE 是在 `sle_enable_cb` 置位后才启动广播、本端地址非全 0，这样手机星闪调试助手即可扫描并连接。
