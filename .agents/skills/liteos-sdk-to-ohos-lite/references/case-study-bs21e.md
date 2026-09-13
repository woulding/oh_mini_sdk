# Case study: BS2X / bs21e → OpenHarmony 7.0 (prebuilt-library SDK)

A worked example of the **prebuilt-library** variant of this skill (Phase 2.5). Target tree:
`~/oh_sdk_mini` (OpenHarmony 7.0 Release, `sdk_version 26.0.0.39`). SDK placed at
`device/soc/hisilicon/bs2xv107/sdk/` (HiSilicon FBB BS2X SDK, ~8400 files).

Contrast with the ws53 case study: ws53 is a **source** SDK (protocol `.c` present) with POSIX and
mbedtls; bs21e is a **prebuilt-library** SDK (protocol/kernel as `.a`, no POSIX, no littlefs, no
mbedtls, no pthread). That difference is why bs21e needs the startup bridge, linker zinitcall
sections, symbol stubs and flash-space fitting.

## Phase 0 recon result

| Item | Value |
|---|---|
| Sibling template | `device/soc/hisilicon/ws63v100` (also prebuilt-lib, rv32imfc) |
| Chip / SoC dir | `bs21e` (family `bs2x`), repo dir `bs2xv107` |
| Target key | **`standard-bs21e-1100e`** (hyphens, unlike ws53's underscores) |
| `pkg_chip` | `bs21e-1100e` |
| Toolchain | `tools/bin/compiler/riscv/cc_riscv32_musl_b010/cc_riscv32_musl_fp/bin`, gcc ver107.010 |
| Arch/ABI | `-march=rv32imfc -mabi=ilp32f` (FP variant) |
| Kernel | `kernel/liteos/liteos_v208.6.0_b017/` with per-target prebuilt `standard-bs21e-1100e/{libc,libm,libriscv,libinterrupt}.a` |
| Protocol | `protocol/{bt,nfc,slp}` — **prebuilt `.a` only, 0 `.c`** |
| open_source | only 7-zip / GmSSL3.1.1 / libboundscheck — **no mbedtls, no lwip, no littlefs** |
| OHOS link hook | `protocol/CMakeLists.txt` **already had** `libs_url/${_CHIP}/cmake/ohos.cmake` |
| `libs_url/` | did not exist → created `libs_url/bs21e/cmake/ohos.cmake` |
| `ohos_adapt` | **missing** → created |
| Startup bridge | **missing** (no `OHOS_SystemInit` call) → added |
| Linker zinitcall | only `__zinitcall_app_run_*` → added the full set |

## Artifacts created

```
device/soc/hisilicon/bs2xv107/
  BUILD.gn                     # group("bs21e") deps sdk:run_sdk_build
  .gitignore
  adapter/                     # 40 files: ble_lite, sle_lite, iot_hardware/wifiiot_lite,
                               #   update, utils/file, kal/{cmsis,posix} (no wifi_lite)
  sdk/
    BUILD.gn                   # build_bs21e_sdk_open; enable_oh_device_lite_auth = false
    hm_build.sh                # build.py -c standard-bs21e-1100e
    libs_url/bs21e/cmake/ohos.cmake
    kernel/liteos/ohos_adapt/{CMakeLists.txt, src/cmsis_adapt.c, src/ohos_stub.c}
    drivers/chips/bs2x/main_init/app_os_init.c        # + ohos_start bridge
    drivers/chips/bs21e/board/linker/standard/linker.prelds  # + __zinitcall_* blocks
    build/config/target_config/bs21e/config.py        # + CONFIG_SUPPORT_OHOS_SUPPORT, ohos_adapt
    kernel/.../CMSIS/RTOS2/Include/cmsis_os2.h        # __NO_RETURN commented
    build/config/target_config/bs21e/flash_sector_config/bs21e-standard.json  # app partition enlarged

device/board/hisilicon/fbb_bs21e/{liteos_m/config.gni, ohos.build}
vendor/hisilicon/fbb_bs21e/{config.json, ohos.build, BUILD.gn, hals/utils/{sys_param,token}}
```

## SDK-side changes

1. **`build/config/target_config/bs21e/config.py`**, `standard-bs21e-1100e`:
   - `defines += ['CONFIG_SUPPORT_OHOS_SUPPORT']`;
   - `ram_component += ['ohos_adapt']`.
2. **`drivers/chips/bs2x/main_init/app_os_init.c`** (guarded by `CONFIG_SUPPORT_OHOS_SUPPORT`):
   ```c
   __attribute__((weak)) void OHOS_SystemInit(void) { return; }
   static void ohos_start(void *unused)
   {
       (void)unused;
       PRINT("OHOS START\r\n");
       osal_msleep(3000);
       OHOS_SystemInit();
   }
   ```
   plus an `{"ohos_start", NULL, APP_STACK_SIZE, TASK_PRIORITY_APP, ...}` entry in `g_app_tasks[]`.
3. **`drivers/chips/bs21e/board/linker/standard/linker.prelds`**: added the OHOS `__zinitcall_*`
   blocks (bsp/device/core/sys_service/sys_feature/run/app_service/app_feature/test/exit).
4. **`kernel/liteos/ohos_adapt/`**: copied `cmsis_adapt.c` from ws63, added `src/ohos_stub.c`
   (POSIX + `UtilsFile*` + `pthread_create` stubs) and listed it in `CMakeLists.txt`.
5. **`cmsis_os2.h`**: commented `__NO_RETURN` on `osThreadExit`.
6. **`ohos.cmake`**: direct-link style, target match `standard-bs21e-1100e`, `EXISTS` guard,
   skips absent libs, whole-archive onto `${TARGET_NAME}`.
7. **`hm_build.sh`**: `TARGET=standard-bs21e-1100e`, `interim_binary/bs21e/libs/ohos/${TARGET}`,
   `REQUIRED_LIBS` (no `hal_file_static`/`native_file`/`huks`/`hichain`/`blackbox`/`hidumper`).
8. **`flash_sector_config/bs21e-standard.json`**: app partition `0x23` `0x88000 → 0x90000`,
   FOTA `0x26` `0x9D000/0x61000 → 0xA5000/0x59000`.

## Board-side change

`device/board/hisilicon/fbb_bs21e/liteos_m/config.gni`:
- `board_arch = "rv32imfc"`, `-mabi=ilp32f`;
- toolchain path to the SDK's `cc_riscv32_musl_b010/cc_riscv32_musl_fp/bin`;
- `-DCHIP_BS21E=1`; **no** `LWIP_CONFIG_FILE` (no lwip); added `-Wno-error=undef`;
- includes for the shared `drivers/chips/bs2x/include` + `.../arch/include` +
  `.../porting/arch/riscv`, and the board at `drivers/chips/bs21e/board/{memory_config/include,
  memory_config/include/product, linker/standard}` (there is no `drivers/boards/` dir).

## Product trimming (bs21e-specific)

The standard mini component set was reduced to fit flash and match the SDK's capabilities:
- **dropped** `security:huks` (no mbedtls), `applications:wifi_iot_sample_app`,
  `updater:sys_installer_lite`, `hiviewdfx:blackbox_lite`, `hiviewdfx:hidumper_lite`;
- `utils_lite` without `utils_lite_feature_file` (no littlefs);
- `sdk/BUILD.gn` `enable_oh_device_lite_auth = false` (hichain pulls huks);
- surviving set: iothardware, hiviewdfx(hilog_lite,hievent_lite), systemabilitymgr, startup,
  commonlibrary, developtools.

## Build verification

- L0: `hb set -p fbb_bs21e` → `fbb_bs21e@hisilicon`.
- L1: `python3 build.py -c standard-bs21e-1100e` → success + fwpkg (with the OHOS libs dir absent).
- L2: `hb build` → **build success**; `out/fbb_bs21e/fbb_bs21e/standard-bs21e-1100e/*.fwpkg`.
- **Link closure proof**: `application.elf` contains `OHOS_SystemInit`@0x90188fb4,
  `SAMGR_AddInterface`, `HiLogPrintf`, `Ble*` (2329), `Bootstrap`, `osThreadGetArgument`; the map
  references `interim_binary/bs21e/libs/ohos/standard-bs21e-1100e/lib*.a` **with addresses**
  (i.e. retained, not under `Discarded input sections`).

## On-target bring-up: runtime heap exhaustion

First flash got through `APP|OHOS START` → `hilog will init` → `hievent init success` and then
hung with `No mem to alloc 0x100c Bytes at pool_addr=0x20002d80` (the LiteOS heap start).
The RAM account from the map: DTCM 63.8 KB total = `.stacks` 7.5K + `.data` 3.9K +
**`.heap` 52.4 KB**; the heap already funds the six SDK task stacks (15.5 KB), the BT stack
and the OHOS components. `0x100c` = param DAC workspace (`sizeof(WorkSpace)` + 4096 file),
allocated at the end of `OHOS_SystemInit` by `LiteParamService` through the weak
`GetSysParamMem` → `malloc`. Fix: `kernel/liteos/ohos_adapt/src/ohos_param_mem.c` provides a
strong `GetSysParamMem`/`FreeSysParamMem` over an 11.5 KB static `.bss` bump pool
(`.bss.g_paramMemPool` 0x2e00, ITCM had 21 KB spare), moving all three param workspaces
(DAC 5K + BASE 5K + SIZE 1K) off the heap. After re-flashing, the system boots through
`OHOS_SystemInit`, runs `APP_FEATURE_INIT` and the hello_world demo prints
`[ohos_bs21e] hello world demo start.`

## The three "states" of OHOS not being in the firmware

1. **Compiled but not linked** — no `libs_url/.../ohos.cmake` hook (ws53 6.1-era symptom).
2. **Linked but garbage-collected** — hook present, but the firmware never references the OHOS
   cluster (no startup bridge). Map lists the libs, ELF has no symbols. (bs21e first attempts.)
3. **Linked and retained** — startup bridge + zinitcall sections present; symbols have addresses.
   This is the only acceptable end state; verify on the map, not on the build exit code.
