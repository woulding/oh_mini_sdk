# Case study: WS53 (Lierda DB35 1.10.106) → OpenHarmony 7.0

A complete worked example of this skill. Target tree: `~/oh_sdk_mini` (OpenHarmony 7.0 Release,
`sdk_version 26.0.0.39`, `api_version 26`). SDK source: `~/Downloads/Lierda_DB35_1.10.106.tar.gz`
(Lierda-customized HiSilicon FBB WS53 SDK, `SDK_VERSION="1.10.106"`).

## Phase 0 recon result

| Item | Value |
|---|---|
| Sibling template in tree | `device/soc/hisilicon/ws63v100` (has `adapter/`, `sdk/`, evolved link machinery) |
| Chip / SoC dir | `ws53`, repo dir `ws53v106` |
| Build targets | `ws53_liteos_app`, `ws53_liteos_xts` (underscores!) |
| Toolchain | `tools/bin/compiler/riscv/cc_riscv32_musl_b010/cc_riscv32_musl/bin`, gcc ver105.010 |
| Arch/ABI | `arch='riscv31'` → `rv32imc` / `-mabi=ilp32` |
| mbedtls | SDK `open_source/mbedtls/mbedtls_v3.6.0`; OHOS `third_party/mbedtls` 3.6.5 |
| OHOS hooks | `kernel/liteos/ohos_adapt/src/cmsis_adapt.c` present |
| Link hook | `protocol/CMakeLists.txt` already had the `libs_url/<chip>/cmake/ohos.cmake` include |
| Include quirks | `chips/ws53/include/{acore,control_core}`; centralized `porting/include` (+ `porting/uart/` exception); `drivers/boards/ws53` has **no** `evb/` layer |
| Lierda vs upstream | Same SDK; differences are mostly CRLF line endings + copyright placeholder + LFS/AT menuconfig defaults. No vendor-specific include layout changes. |

## Artifacts created

```
device/soc/hisilicon/ws53v106/                 # SoC
  BUILD.gn                                     # group("ws53v106") deps sdk:run_sdk_build
  .gitignore
  adapter/                                     # 55 files, copied from ws63v100 and ws53-ized
  sdk/                                         # Lierda SDK source (outputs excluded)
    BUILD.gn                                   # build_ext_component run_sdk_build
    hm_build.sh                                # copies OHOS .a -> interim_binary/ws53/libs/ohos/<target>
    libs_url/ws53/cmake/ohos.cmake             # link closure (direct-link style)
    build/config/target_config/ws53/config.py  # app ram_component additions
    kernel/liteos/liteos_v208.5.0/Huawei_LiteOS/tools/build/config/ws53.config   # POSIX/VFS/joinable
    kernel/liteos/liteos_v208.5.0/Huawei_LiteOS/open_source/CMSIS/.../cmsis_os2.h # __NO_RETURN
    build/config/target_config/ws53/menuconfig/acore/ws53_liteos_app.config       # LFS

device/board/hisilicon/fbb_ws53/               # Board
  liteos_m/config.gni                          # rv32imc/ilp32, ws53v106 includes
  ohos.build                                   # part device_fbb_ws53 -> ws53v106

vendor/hisilicon/fbb_ws53/                     # Product (hb set -> mini -> fbb_ws53)
  config.json  ohos.build  BUILD.gn
  hals/utils/{sys_param,token}/
```

Naming notes:
- SoC GN target/group: `ws53v106`; board part forced to `device_fbb_ws53`; vendor product part `product_fbb_ws53`; product/GN group `fbb_ws53`.
- The user originally wanted the board part named `fbb_ws53`, but OHOS 7.0's preloader hard-codes `device_<board>`, so it had to be `device_fbb_ws53`.

## SDK-side changes applied (all mirror ws63's integration)

1. `build/config/target_config/ws53/config.py`, app target `ram_component`:
   - **added** `ohos_adapt`, `printf_adapt`, `little_fs`, `littlefs_adapt_ws53`;
   - **removed** `syschannel_host_ko` (Linux kernel-module component) and the unused `cjson` (duplicate of OHOS `cjson_static`).
2. `kernel/.../tools/build/config/ws53.config` (LiteOS app config):
   - `LOSCFG_COMPAT_POSIX=y`, `LOSCFG_FS_COMPAT_NUTTX=y`, `LOSCFG_FS_VFS=y`;
   - `LOSCFG_LIB_VENDORNAME="vendor"`, `LOSCFG_TASK_JOINABLE=y`.
3. `build/config/target_config/ws53/menuconfig/acore/ws53_liteos_app.config`:
   - `CONFIG_MIDDLEWARE_SUPPORT_LFS=y`, `CONFIG_LFS_PARTITION_ID=0x26` (taken from the SDK's XTS config).
4. `kernel/.../CMSIS/RTOS2/Include/cmsis_os2.h`: commented out `__NO_RETURN` on `osThreadExit`.
5. `libs_url/ws53/cmake/ohos.cmake`: created; `EXISTS` guard on `libs/ohos/<target>`; per-target component list; skips absent libs; `target_link_libraries(${TARGET_NAME} ... --whole-archive ...)`.
6. `BUILD.gn` top: `deps = [ "sdk:run_sdk_build" ]`.

## Board `config.gni` additions beyond the ws63 template

- `board_arch = "rv32imc"`, `-mabi=ilp32` (ws63 is `rv32imfc`/`ilp32f`).
- Toolchain path to `.../cc_riscv32_musl_b010/cc_riscv32_musl/bin`.
- Includes: `drivers/chips/ws53/include/acore`, `drivers/chips/ws53/porting/include`,
  `drivers/boards/ws53/memory_config/include`, `drivers/boards/ws53/memory_config/include/product`,
  `drivers/boards/ws53/linker/ws53_app_linker` (for `memory_config.h`), `targets/ws53/include`.

## Build verification

- L0: `hb set -p fbb_ws53` → `fbb_ws53@hisilicon`.
- L1: `cd device/soc/hisilicon/ws53v106/sdk && python3 build.py -c ws53_liteos_app` → success + `fwpkg`.
- L2: `hb build` → **build success**; produced
  `out/fbb_ws53/fbb_ws53/pack_all_core/ws53_liteos_app/{all_in_one,load_only}.fwpkg`.
- Link-closure proof: firmware `application.elf` / `.map` contains OHOS symbols
  (`SAMGR_*`, `Hks*`, `Ble*`, `HiLogPrintf`, `HalFileOpen`, `fs_adapt_close`) and map references
  `interim_binary/ws53/libs/ohos/ws53_liteos_app/lib*.a`.
- Public repos: **zero changes**. `base/security/huks/.../hks_mbedtls_x25519.c` compiles against
  mbedtls 3.6.5 because `MBEDTLS_ECP_RESTARTABLE` is defined → `MBEDTLS_ECDH_LEGACY_CONTEXT` active
  → `ctx.MBEDTLS_PRIVATE(Qp/d/grp/z)` valid. No 6.1-era patch needed.

## Key difference from the older (6.1) migration

The earlier 6.1 WS53 "success" had built the SDK and the OHOS side separately but **never linked
the OHOS `.a`s into the firmware** — `nm` on its `application.elf` showed no OHOS symbols. This 7.0
migration added the `libs_url/ws53/cmake/ohos.cmake` link closure, so the firmware now genuinely
contains the OHOS lite components. Always verify the link closure on the ELF/map, not just the
build exit code.
