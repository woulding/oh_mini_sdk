# WS53 迁移到 ohos_sdk 记录（从 ohos_mini 复制已验证成果）

> 本文档记录将 WS53 从 `ohos_mini`（已完成迁移并构建通过）复制迁移到 `ohos_sdk` 的过程与验证结果。
> 时间：2026-09-08 22:0x；基线与两树均为 `OpenHarmony-6.1-Release`（version 6.1.0.31）。

## 1. 复制范围（第二步，变体 B：排除可再生产物）

| 单元 | 目标路径 | 文件数 |
|---|---|---|
| SoC 仓 | `device/soc/hisilicon/ws53v100/` | 9661（sdk 源码 + adapter 55，已排除 `sdk/output`、`interim_binary/.../libs/ohos`、`__pycache__`、`*.pyc`） |
| 板级 | `device/board/hihope/nearlink_dk_3853/` | 2 |
| vendor | `vendor/hihope/nearlink_dk_3853/` | 8 |
| vendor XTS | `vendor/hihope/nearlink_dk_3853_xts/` | 3 |

校验：源/目标同口径 sha256 diff 差异仅为有意排除的 `libs/ohos/*.a`；残留 `ws63|3863|WS63` 命中 0。

## 2. 构建验证（第三步，三级全通过）

| 级别 | 内容 | 结果 |
|---|---|---|
| L1 | `python3 build.py ws53_liteos_app`（SDK 固件） | success（28.6s）；工具链自动用 sdk 内自带 `cc_riscv32_musl_b010`（ver105.010），无需 export/PATH 干预 |
| L2 | `hb build`（`nearlink_dk_3853` 普通产品） | build success（540/540，含 run_sdk_build 联动，1:17） |
| L3 | `hb build`（`nearlink_dk_3853_xts` XTS 产品） | 首次失败→修复→build success（389/389，1:28） |

产物：
- `out/nearlink_dk_3853/nearlink_dk_3853/pack_all_core/ws53_liteos_app/*.fwpkg`
- `out/nearlink_dk_3853/nearlink_dk_3853_xts/pack_all_core/{ws53_liteos_app,ws53_liteos_xts}/*.fwpkg`

## 3. 修复项（L3 唯一阻塞，公共仓补丁）

- 现象：`hks_mbedtls_x25519.c` 以 mbedTLS 3.6.0 新式嵌套 ECDH 上下文编译失败（`private_z/Qp/d` 不存在）。
- 处理：合入 ohos_mini 已验证的兼容补丁（`MBEDTLS_ECDH_LEGACY_CONTEXT` 双分支宏，兼容 mbedTLS 3.1 legacy 与 3.6 嵌套上下文），单文件合入、非整仓覆盖。

## 4. 提交（第四步）

| 仓 | commit | 说明 |
|---|---|---|
| `device/soc/hisilicon` | `43fd6e34` | ws53v100 SoC SDK + adapter（含 `ws53v100/.gitignore` 忽略 sdk 产物） |
| `device/board/hihope` | `facbbdb` | nearlink_dk_3853 板级配置 |
| `vendor/hihope` | `5b10d12` | nearlink_dk_3853 普通/XTS 产品配置 |
| `base/security/huks` | `df0fbbb4` | hks_mbedtls_x25519 mbedTLS 3.6 兼容补丁 |

> 提交前终检：复制三仓无既有文件改动；soc 仓内 `ws63v100` 的 untracked 为迁移前既有噪音，未纳入提交。ws53v100 提交中 4 个含 `.../rom_config/.../output/` 路径为 SDK 源文件（链接脚本/CMake），非产物。

## 5. 遗留事项（与 ohos_mini 一致，未验证）

- 实机烧录启动、BLE/SLE/Wi-Fi 外设功能回归；
- 完整镜像参数（分区/NV/FOTA/memory map）核对；
- 许可与可再分发审查（SDK 内仍为海思版权头）；
- `ws63_sample` 样例未迁移（不被构建引用）。
