# WS53（fbb_ws53）迁移到 OpenHarmony 环境的注意事项

> 本文档最初基于对 `fbb_ws53`、`fbb_ws63`、`ohos_ws63`（含 `device/soc/hisilicon/ws63v100` 集成层）三边的只读对比分析整理；后续已在 `ohos_mini` 树中实际执行迁移并完成构建验证。
> 所有相对路径默认基于 `ohos_ws63` 代码树根目录。
>
> **✅ 当前状态：WS53 迁移接入、普通产品与 XTS 产品构建均已完成；S1–S6 全部完成。芯片实机运行、外设功能回归、许可复核和镜像参数确认仍待后续验证，详见文末「7. 执行状态与遗留事项」。**
>
> **✅ 复核（2026-09-08 21:41）：`nearlink_dk_3853` 普通产品在 `ohos_mini` 树内再次完整构建通过；迁移产物、残留检查与文档声明一致。期间环境出现新变化（`~/ohos_sdk`、工具链指向回退），详见「7.4 环境备注」与「8. 复核记录」。**

## 1. 结论先行：基础比想象的好

WS53 与 WS63 是**同一 FBB 平台、同一代 SDK**，不是平行的两套代码：

- 同为 RISC-V `rv32imc`（OHOS 侧 WS63 按 `rv32imfc` 配置）+ musl 工具链，同为 **Huawei LiteOS v208.5.0**；
- `kernel/`、`include/`、`build/config/target_config/` 结构完全同构；
- **WS53 SDK 出厂已内置 `kernel/liteos/ohos_adapt`（`cmsis_adapt.c`）**，与 OHOS 里 WS63 SDK 的文件同名同结构（仅 license 头不同）——内核/CMSIS 层面的 OHOS 钩子无需从零写；
- WS53 SDK 已带 `ws53_liteos_app` / `ws53_liteos_xts` 两个构建 target、`build_ws53_update.py`、`output/ws53`、`interim_binary/ws53` 骨架。

因此迁移的本质是：**复刻 `ohos_ws63` 里那层"接插件"（SoC 仓 + 板级仓 + vendor 产品仓 + manifest），逐文件替换硬编码的 `ws63` 标识与路径**，而非移植内核或驱动逻辑。

## 2. 纯字符串/路径替换清单（7 个文件）— ✅ 已全部落地（S1–S4）

### 2.1 `device/soc/hisilicon/ws53v100/BUILD.gn` — ✅

| 行 | 现状 | 改为 |
|---|---|---|
| L14 | `group("ws63v100")` | `group("ws53v100")`（board 的 `ohos.build` 引用此 target 名，须联动） |

### 2.2 `device/soc/hisilicon/ws53v100/sdk/BUILD.gn` — ✅ 已新建

| 行 | 现状 | 改为 |
|---|---|---|
| L17 | `build_ws63_sdk_open` | `build_ws53_sdk_open` |
| L28 | `command = "sh hm_build.sh $outdir $build_ws63_sdk_open"` | 联动变量名 |
| L51-53 | `//device/soc/hisilicon/ws63v100/adapter/hals/communication/{ble_lite,sle_lite,wifi_lite/wifiservice}` | `ws53v100` 路径 |
| L55 | 注释掉的 `//device/soc/hisilicon/ws63v100/adapter/kal` | 联动 |
| L30 | 注释 `ws63-liteos-app` | 可选联动 |

### 2.3 `device/soc/hisilicon/ws53v100/sdk/hm_build.sh` — ✅ 已新建（发布分支已删）

| 行 | 现状 | 改为 |
|---|---|---|
| L4 | `build_ws63_sdk_open="$2"` | `build_ws53_sdk_open` |
| L8 | `output/ws63/fwpkg` | `output/ws53/fwpkg` |
| L11-12 | `interim_binary/ws63/libs/ohos/ws63-liteos-app` / `ws63-liteos-xts` | 对应 `ws53` |
| L32/34 | `build.py -c ws63-liteos-xts` / `ws63-liteos-app` | `ws53-liteos-xts` / `ws53-liteos-app` |
| L48-66 | 约 19 处写死的 `device/soc/hisilicon/ws63v100/src/...` 旧布局路径 | **已整段删除**（原建议重写或删除） |

### 2.4 `device/board/hihope/nearlink_dk_3853/liteos_m/config.gni` — ✅ 已落地（新板名 `nearlink_dk_3853`）

| 位置 | 现状 | 改为 |
|---|---|---|
| L50 | `-DCHIP_WS63=1` | `-DCHIP_WS53=1` |
| include 列表 | 全部 `${ohos_root_path}device/soc/hisilicon/ws63v100/${sdk}/...` | `ws53v100` |
| 芯片目录 | `middleware/chips/ws63/{update,partition,littlefs}/include` | `middleware/chips/ws53/...` |
| 芯片目录 | `drivers/chips/ws63/include`、`drivers/boards/ws63/evb/memory_config/include/product` | `ws53` 对应路径（**ws53 无 `evb` 层，已实测修正**） |
| 内核目录 | `kernel/liteos/.../targets/ws63/include` | `targets/ws53/include` |
| L84 | `board_adapter_dir = "//device/soc/hisilicon/ws63v100/adapter"` | `ws53v100` |

> 追加决策（超出 ws63 模板）：`board_arch = "rv32imc"`、`-mabi=ilp32`（见 4.2）；include 另补 `chips/ws53/include/acore` 与 `chips/ws53/porting/include`（见 7.3 实测差异）。

### 2.5 `device/board/hihope/nearlink_dk_3853/ohos.build` — ✅

- `"device_nearlink_dk_3863"` → `"device_nearlink_dk_3853"`；
- `//device/soc/hisilicon/ws63v100:ws63v100` → `//device/soc/hisilicon/ws53v100:ws53v100`。

### 2.6 `vendor/hihope/nearlink_dk_3853/` 与 `vendor/hihope/nearlink_dk_3853_xts/` — ✅（`ws63_sample` 未迁移）

每个目录下 `config.json`、`ohos.build`、`BUILD.gn` 三件套已落地：

| 字段 | 处理 |
|---|---|
| `config.json` | `product_name`→`nearlink_dk_3853[_xts]`、`device_build_path`/`board` 联动、`third_party_dir`→`//device/soc/hisilicon/ws53v100/sdk/open_source`（**顺带修正 `sdkv100` 笔误**）、`product_adapter_dir` 联动 |
| `ohos.build` | `product_nearlink_dk_3853[_xts]`、module_list 联动 |
| `BUILD.gn` | `group("nearlink_dk_3853[_xts]")` |
| `hals/` | `utils/sys_param`、`utils/token` 已复制；`vendor.para` 产品名改 `WS53E`（占位） |

XTS 变体的 `huks_dependency_mbedtls_path` → `//device/soc/hisilicon/ws53v100/sdk/open_source/mbedtls/mbedtls_v3.6.0`（**ws53 SDK 为 v3.6.0，非 ws63 的 v3.1.0**）。

> `vendor/hihope/nearlink_dk_3863/ws63_sample/`（24 组样例 + paho_mqtt）**未迁移**：不被任何构建引用、且样例代码与 ws63 板级外设强绑定，留待后续按需移植。

### 2.7 `adapter/hals/communication/wifi_lite/wifiservice/` — ✅ 已落地

`include/` 下 10 个 `ws63_` 前缀头已改名 `ws53_*`（`ws53_wifi_device.h`、`ws53_wifi_hotspot.h`、`ws53_wifi_event.h` 等），并联动 `#include` 与 BUILD.gn。（注：实测残留为 10 个头文件，非原记 12 个。）

## 3. WS63 集成层自身存在的坑（迁移时不要照抄）— ✅ 已全部处理

| 位置 | 问题 | 处理 |
|---|---|---|
| `vendor/.../config.json` L83 | `third_party_dir` 写成 `.../ws63v100/**sdkv100**/open_source` | ws53 版已直接写正确路径 `.../ws53v100/sdk/open_source` |
| `config.gni` L14 | `enable_soc_his_sdkv100 = true` 全树无消费方 | 死开关，ws53 版已删除 |
| `config.gni` include 列表 | `ws63v100//${sdk}` 双斜杠、漏 `${sdk}` 混排 | 已统一为 `${ohos_root_path}device/soc/hisilicon/ws53v100/${sdk}/...` |
| `config.gni` L96 | `${ohos_root_path}/kernel/liteos_m/utils/` 首段多一个 `/` | 已顺手修正 |

## 4. 需要人工决策的芯片差异点 — 状态见各条

1. **工具链** — ✅ 已决策并执行：config.gni 沿用 `board_toolchain = "riscv32-linux-musl"`（前缀与 SDK 自带 `cc_riscv32_musl_b010` 同名兼容）；已将 `~/.bashrc` 的 PATH 前置 ws53 SDK 自带 `cc_riscv32_musl_b010/.../bin`（ws63 的 `cc_riscv32_musl_100` 链保留在第二位，备份 `~/.bashrc.bak-ohos53`）。
2. **`board_arch`** — ✅ 已决策为 `rv32imc` / `-mabi=ilp32`：ws53 SDK 无 `fp_flags` 注入（对比 ws63 的 `fp_flags = {ilp32f/rv32imfc}`），`ws53_liteos_app` 的 `arch='riscv31'` 即 `rv32imc/ilp32`，OHOS 侧须与固件 ABI 一致。⚠️ 待固件实际链接验证。
3. **双内核头文件混排** — ✅ 宏/路径已对齐（`__LITEOS__`、`CMSIS_OS_VER=2`、`CHIP_WS53`、`LWIP_CONFIG_FILE`），普通产品与 XTS 产品均已完成 OHOS/SDK 编译及链接。
4. **外设差异**（CAN/IR/keyscan/QDEC/PDM 自建 HAL）— 🟡 当前接入的 GPIO/I2C/PWM/SFC/UART/Watchdog/reset、BLE、SLE、Wi-Fi service 已通过普通产品和 XTS 编译；CAN/IR/keyscan/QDEC/PDM 尚未进行实机功能验证或按需扩展。
5. **LiteOS `targets/` 方案目录** — ✅ 已确认集成走 `ws53_liteos_app`（`targets/ws53`），未混入 `aiot/hq/shc` 等其它方案。
6. **合规与再分发**（许可头 Apache-2.0 替换、商业组件裁剪）— ⬜ 未开始（SDK 内仍为海思版权头）。
7. **镜像/芯片配置**（flash 分区、NV、fota、memory map、协议固件）— ⬜ 未开始。

## 5. 建议执行顺序（将来真正动手时）— 状态见各步

1. 复制 `device/soc/hisilicon/ws63v100` → `ws53v100`，并将 sdk 子树整体替换为 `fbb_ws53/src` 内容 — ✅（实际：先平铺后重排为 `ws53v100/{BUILD.gn, adapter/, sdk/}`，sdk 子树 9541 文件）
2. 修改 `hm_build.sh` + `sdk/BUILD.gn` + `ws53v100/BUILD.gn`（第 2.1-2.3 节）— ✅
3. 新建板级目录 `nearlink_dk_3853`（参考 `nearlink_dk_3863`），修改 `config.gni` / `ohos.build`，处理第 3 节既有 bug 与第 4 节工具链/arch 决策 — ✅
4. vendor 产品目录复制改名（`nearlink_dk_3853` / `_xts`），XTS 变体照做 — ✅（`ws63_sample` 除外，见 2.6）
5. `hb set -p` 选择新产品试编译，按报错反查漏改的 `ws63` 字面量 — ✅ 完成；普通产品和 XTS 产品均已构建通过（见 7.2）
6. 验证 WS53 SDK 固件构建及完整 OHOS 镜像 — ✅ `ws53_liteos_app`、`ws53_liteos_xts` 和两个 OHOS 产品构建均已通过

**兜底验证命令**（未来执行迁移后运行）：

```bash
# 在 adapter / board / vendor 三层检查残留（sdk 子树整体替换后不应再出现 ws63/3863）
cd <ohos 树根>
grep -rn "ws63\|3863" \
  device/soc/hisilicon/ws53v100/adapter \
  device/board/hihope/<新板名> \
  vendor/hihope/<新产品名> || echo "clean"
```

> 已对 `ohos_mini` 的 adapter / `nearlink_dk_3853` / vendor 3853 两仓执行：**输出 clean**。注意 `WS63`（大写）与 `ws63_sample` 目录名不在兜底命令的匹配内但会干扰 grep，实际检查需大小写都查。

## 6. 一句话总结

迁移不是移植芯片底层（WS53 与 WS63 同框架同内核，SDK 内部甚至已预留 OHOS 钩子），而是**复刻 OHOS 侧那层"接插件"**：新建 `ws53v100` SoC 仓 + 板级仓 + vendor 产品仓，逐文件替换硬编码 `ws63` 标识与路径，重点核对工具链命名、`rv32imfc` vs `rv32imc`、以及芯片专属镜像/外设配置。工作量主体在集成脚本、许可头与 repo 清单，而非内核或驱动逻辑本身。

---

## 7. 执行状态与遗留事项（基于 `ohos_mini` 实际迁移，截至 2026-09-08）

### 7.1 已完成的迁移步骤

| 步骤 | 产物 | 验证 |
|---|---|---|
| S1 结构重排 | `device/soc/hisilicon/ws53v100/` = `{BUILD.gn, adapter/(55f), sdk/(9541f 来自 fbb_ws53)}` | 文件数一致、ws63v100 未动 |
| S2 SoC 接插件 | 顶层 `BUILD.gn`(group ws53v100)、`sdk/BUILD.gn`、`sdk/hm_build.sh`（删发布分支） | 三文件无 ws63 残留；`bash -n` 通过 |
| S3 板级仓 | `device/board/hihope/nearlink_dk_3853/`（`config.gni` + `ohos.build`） | 31 条 include 全存在；rv32imc/ilp32、CHIP_WS53 生效 |
| S4 vendor 仓 | `vendor/hihope/nearlink_dk_3853/` + `_xts/`（三件套 + hals） | 残留 clean；mbedtls_v3.6.0 存在 |
| adapter ws53 化 | 6 个 BUILD.gn + wifiservice 10 头改名 + 内容联动 | 全树无 ws63/WS63 残留 |
| 工具链切换 | `~/.bashrc` PATH 前置 `cc_riscv32_musl_b010`（备份 `.bashrc.bak-ohos53`） | `which riscv32-linux-musl-gcc` 命中 b010，版本 ver105.010 |
| S5 API/配置适配 | WS53 BLE/SLE/Wi-Fi/HUKS/mbedTLS 接口及构建配置修正 | 普通产品与 XTS 产品相关目标编译通过 |
| S6 完整构建 | `nearlink_dk_3853`、`nearlink_dk_3853_xts`，以及 `ws53_liteos_app` / `ws53_liteos_xts` | 两个 `hb build` 均成功，XTS 最近一次 369/369 完成 |

### 7.2 当前构建状态

- 普通产品 `nearlink_dk_3853`：OHOS 侧 492 个目标、WS53 SDK `ws53_liteos_app` 和完整 `hb build` 均已通过。
- XTS 产品 `nearlink_dk_3853_xts`：`hb set -p`、GN 配置、HUKS、mbedTLS、adapter、WS53 SDK `ws53_liteos_xts`、链接、打包和镜像生成均已通过；最近一次 Ninja 为 369/369。
- 已解决的主要问题包括：WS53 target 名称、工具链/ABI、memory/linker include、`syschannel_host_ko` 错误依赖、mbedTLS GN 接入，以及 HUKS X25519 对 mbedTLS 3.x ECDH 嵌套上下文的字段访问。
- XTS mbedTLS 配置中已移除与硬件 ECP alternative 冲突的 `MBEDTLS_ECP_RESTARTABLE` / legacy ECDH 配置；HUKS 代码保留 legacy 和新上下文两种访问分支。
- 当前没有编译阻塞。尚未完成的是实机烧录启动、BLE/SLE/Wi-Fi 等外设功能回归、完整镜像参数（分区/NV/FOTA/memory map）核对，以及许可和可再分发审查。
- **复核构建（2026-09-08 21:38–21:41）**：`nearlink_dk_3853` 普通产品在 `ohos_mini` 树内再次执行完整 `hb build` 并通过（GN `ohos_build_datetime="2026-09-08 21:38:48"`，Ninja 收尾无 `FAILED`；日志 `out/nearlink_dk_3853/nearlink_dk_3853/build.1788874787.226952.log`）。XTS 产品自 15:07 后未再重建。

### 7.3 实际迁移中发现的结构差异（均已在代码中处理，记录备查）

1. **`platform_core.h` 按核分层**：ws63 在 `chips/ws63/include/`（单层）；ws53 在 `chips/ws53/include/{acore,control_core}/`。OHOS/LiteOS 跑 `acore` → include 需含 `chips/ws53/include/acore`。
2. **porting 头集中式**：ws63 分散于 `chips/ws63/porting/{gpio,i2c,uart}/*.h`；ws53 集中在 `chips/ws53/porting/include/*.h`（`i2c_porting.h`/`gpio_porting.h`/`arch_port.h` 等），例外 `uart_porting.h` 仍在 `chips/ws53/porting/uart/`。config.gni 与 `wifiiot_lite/BUILD.gn` 均需适配。
3. **`drivers/boards/ws53` 无 `evb` 层**：ws63 为 `drivers/boards/ws63/evb/memory_config/...`，ws53 为 `drivers/boards/ws53/memory_config/...`。
4. **mbedtls 版本不同**：ws63 `mbedtls_v3.1.0` vs ws53 `mbedtls_v3.6.0`（XTS 的 `huks_dependency_mbedtls_path` 联动）。
5. **OHOS 编译命令中 `ws63v100` include 的来源**：来自 adapter 各 `BUILD.gn` 的 include_dirs（如 `wifiiot_lite/BUILD.gn` 13 条），而非 `config.gni`——adapter 是残留重灾区。
6. **BLE API（ws63 vs ws53）**：`gap_ble_callbacks_t` 成员与 enable/disable 函数命名存在差异，已在 WS53 adapter 中完成适配并通过普通/XTS 编译。
7. **HUKS/mbedTLS ECDH 上下文**：WS53 使用 mbedTLS v3.6.0 新式嵌套上下文；`hks_mbedtls_x25519.c` 已增加条件访问分支，并移除会与硬件 ECP alternative 冲突的 restartable 配置。

### 7.4 环境备注

- 编译命令：`hb build`（在 `ohos_mini` 根，`PATH` 需含 `~/.local/bin`(hb) 与 ws53 b010 工具链）；产物位于 `out/nearlink_dk_3853/` 下的普通/XTS 产品目录。
- 迁移前的对比树 `/home/woulding/ohos_ws63` 仍保留（含 ws63 工具链），勿在迁移中改动。
- 当前修改未改动 `device/soc/hisilicon/ws63v100` 及 WS63 vendor/board 路径；HUKS X25519 的公共代码改动采用 mbedTLS 上下文条件分支，旨在兼容 WS63 的 mbedTLS 3.1.0 配置。
- **环境新变化（2026-09-08 晚，文档撰写后）**：
  - 新出现第三棵树 `~/ohos_sdk`（含 `device/soc/hisilicon/ws63v100` 与 WS63 `cc_riscv32_musl_100` 工具链；其 `out/` 下仅有 `nearlink_dk_3863`，无 3853 产物），顶层 21:39 有写入活动；与 3853 迁移无直接关系。
  - **工具链指向已回退**：当前 shell 生效的 `riscv32-linux-musl-gcc` 指向 `~/ohos_sdk/.../cc_riscv32_musl_100`（ver102.010），不再是本文 4.1 所述的 b010（ver105.010）前置；且 `~/.bashrc` 中三条工具链 export（L126 ws63-100、L127 ws53-b010、L129 ohos_sdk-100）现均处于注释状态，当前 PATH 中的工具链来自父会话注入。**重新构建 3853 前应先恢复 b010 前置或验证 100 链等效，避免工具链漂移影响增量产物。**
  - `~/.bashrc.bak-ohos53` 备份仍在。
- **版本管理盲区**：`ohos_mini` 的 `device/soc/hisilicon`、`device/board/hihope`、`vendor/hihope` 下均无独立 `.git`（repo 展开未带仓元数据）——迁移改动没有提交记录、无法 git 追溯，建议尽快在对应仓初始化并提交基线。

---

## 8. 复核记录（2026-09-08 21:41，基于磁盘实况核对）

本小节记录对本文档声明的独立复核结果，供后续追溯。

### 8.1 与文档一致（复核通过）

| 项 | 复核结果 |
|---|---|
| 迁移产物存在性 | `device/soc/hisilicon/ws53v100/`（`BUILD.gn` + `adapter/` + `sdk/`）、`device/board/hihope/nearlink_dk_3853/`（`liteos_m/` + `ohos.build`）、`vendor/hihope/nearlink_dk_3853/` 与 `_xts/`（三件套 + `hals/`）均存在 |
| adapter 文件数 | 55 个文件，与 7.1 记录一致 |
| 构建产物 | `out/nearlink_dk_3853/{nearlink_dk_3853, nearlink_dk_3853_xts}/` 均存在；普通/XTS 产品的 `ws53_liteos_app`/`ws53_liteos_xts` 的 `fwpkg` 齐备 |
| 残留检查 | 对 adapter、`nearlink_dk_3853`、vendor 3853 两仓复跑 `grep ws63\|3863`（小写）与 `WS63`（大写）：**无命中**（clean） |
| 工具链 b010 | `ohos_mini/.../ws53v100/sdk/tools/.../cc_riscv32_musl_b010/` 存在，gcc 为 `ver105.010 2024-06-18 (GCC 7.3.0)` |
| 备份文件 | `~/.bashrc.bak-ohos53` 仍在 |

### 8.2 文档撰写后的新变化（已更新入 7.4）

1. **复构建确认**：`nearlink_dk_3853` 普通产品于 09-08 21:38–21:41 在 `ohos_mini` 树内再次完整 `hb build` 通过（见 7.2）。
2. **第三棵树 `~/ohos_sdk` 出现**：含 WS63 `cc_riscv32_musl_100` 工具链与 `nearlink_dk_3863` 产物，无 3853 相关内容。
3. **工具链指向回退**：生效的 `riscv32-linux-musl-gcc` 现为 `~/ohos_sdk` 的 100 链（ver102.010），非 b010；`.bashrc` 三条工具链 export 均被注释。此状态与 4.1/7.1 所述"b010 前置"不同，是当前唯一可能影响**增量构建**的漂移点（对已生成产物无影响）。
4. **版本管理盲区**：迁移相关三仓无 `.git`，改动无提交。

### 8.3 口径修正备注

- 7.1 记录的 sdk 子树"9541 文件"是迁移时点口径；由于 SDK 自带构建在树内 `sdk/output/ws53/` 直接产出（fwpkg/bin/nv 等），当前 `sdk/` 子树文件数已增至约 2.7 万（`ws53v100` 全树 27019）。**打包/归档时应排除 `sdk/output` 等构建产物**，避免与源码混淆。
- 复核未改变 7.2 所列待办（实机烧录启动、外设功能回归、镜像参数核对、许可复核）——尚无新进展。
