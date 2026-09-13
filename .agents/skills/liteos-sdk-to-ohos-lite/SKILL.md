---
name: liteos-sdk-to-ohos-lite
description: >-
  Migrate / integrate a vendor LiteOS SoC SDK (e.g. HiSilicon FBB WS53/WS63/BS2X,
  "fbb_*", Lierda DB35, module-vendor tarballs) into an OpenHarmony lightweight
  (mini/small, liteos_m) tree so that `hb set` lists a new product and `hb build`
  produces a firmware image with the OHOS lite components actually linked in. Use
  this skill whenever the user wants to port a chip SDK into OpenHarmony, add a
  custom board/product under device/board + vendor, make a LiteOS SDK work under
  liteos_m, "把 SDK 合并进 OpenHarmony 轻量系统", "迁移 WS53/WS63/BS21E 到 OHOS",
  "新增一个 mini 产品", or debug link errors where OHOS libs
  (samgr/hilog/huks/ble_lite) are missing from the firmware. Also use it when a
  previous migration "built successfully" but the firmware ELF has no OHOS
  symbols, or when migrating a *prebuilt-library* SDK (BS2X/bs21e style: no
  protocol/kernel source, no POSIX/littlefs) where OHOS init hooks, linker
  zinitcall sections and flash-space fitting need explicit handling.
---

# Migrating a LiteOS SoC SDK into an OpenHarmony lightweight (mini) tree

## Mental model (read this first)

A LiteOS SDK (HiSilicon FBB style: `src/{application,bootloader,build,drivers,kernel,middleware,open_source,protocol,tools}`) and OpenHarmony's `liteos_m` mini system are **not two kernels to merge**. They are:

- the **SDK** = chip firmware + its own `build.py`/cmake build system + LiteOS kernel;
- **OHOS lite** = a set of small components (samgr, hilog, huks, bootstrap, ble_lite, wifiservice, …) built by GN, plus a board/product/SoC "integration layer".

Migration = **replicating the integration layer** (SoC repo + board repo + vendor product) and making the SDK build system **link the OHOS `.a` files into the firmware image**. Do not port drivers or the kernel; they are shared already (both are Huawei LiteOS, often the same `liteos_v208.5.0`).

The three layers you create (company/product names are free-form, chip/board naming has hard constraints):

| Layer | Path | What it is |
|---|---|---|
| SoC | `device/soc/<company>/<chip>/` | `{BUILD.gn, adapter/, sdk/}` — the SDK source + OHOS HAL adapters + the build/link glue |
| Board | `device/board/<company>/<board>/liteos_m/config.gni` + `ohos.build` | arch, ABI, toolchain, global include dirs, device part |
| Vendor | `vendor/<company>/<product>/` | `config.json`, `ohos.build`, `BUILD.gn`, `hals/` — what `hb set` shows |

**Golden rule:** find the *existing working* SoC integration in the same OHOS tree (e.g. `device/soc/hisilicon/ws63v100/`) and mirror it. Do **not** trust older migration docs from a different OHOS release — the integration layer evolves (part naming, XTS overlay, mbedtls source-switch, extra product variants).

## Phase 0 — Recon (do not skip; assumptions here cause 80% of later pain)

Extract the SDK to a scratch dir and record a difference sheet. The things that decide every later path/macro:

1. **OHOS release & tree**: read `build/version.gni` (`sdk_version`, `api_version`) and note whether `device/soc/<company>/` already has a sibling chip to use as template.
2. **Chip name / version**: the SDK's chip dir (`drivers/chips/<chip>`, `middleware/chips/<chip>`, `kernel/liteos/.../targets/<chip>`). Pick the SoC repo dir name (often `<chip>v<version>`, e.g. `ws53v106`).
3. **Toolchain**: `tools/bin/compiler/riscv/cc_riscv32_musl_*` — exact directory nesting and gcc version. The toolchain may be bundled in the SDK (preferred: no `~/.bashrc` PATH dependency).
4. **Arch / ABI**: the SDK target config's `arch` (`riscv31` → `rv32imc`/`-mabi=ilp32`; if there is an `_fp` toolchain variant → `rv32imfc`/`-mabi=ilp32f`). OHOS board `config.gni` **must match the SDK firmware ABI**.
5. **Build target names**: the keys in `build/config/target_config/<chip>/config.py`. `TARGET_COMMAND` (used for output dirs) equals the string passed to `build.py -c`. Note whether keys use `_` (ws53: `ws53_liteos_app`) or `-` (ws63: `ws63-liteos-app`) — **this affects every `libs/ohos/<target>/` path**.
6. **Include layout quirks**: is there an `acore`/`control_core` split (`chips/<chip>/include/acore`)? Are porting headers centralized (`porting/include`) or scattered (`porting/{gpio,i2c}/`)? Is there a board `evb/` layer? These change the board include list.
7. **mbedtls version** in `open_source/mbedtls/` and in the OHOS `third_party/mbedtls`.
8. **OHOS hooks already in the SDK**: `kernel/liteos/ohos_adapt/src/cmsis_adapt.c`, and whether `protocol/CMakeLists.txt` already has a `libs_url/<chip>/cmake/ohos.cmake` include hook.
9. **Link mechanism in the template**: how does the working sibling chip link OHOS `.a`s? (In 7.0 ws63: `hm_build.sh` copies GN `.a`s to `interim_binary/<chip>/libs/ohos/<target>/`, then `protocol/CMakeLists.txt` includes `libs_url/<chip>/cmake/ohos.cmake` which links them whole-archive.)
10. **Source vs prebuilt-lib SDK** (decides how much extra work Phase 2.5 is): does `protocol/` contain `.c` sources, or only prebuilt `.a`? Is `kernel/liteos/.../<target>/*.a` prebuilt? Does `open_source/` contain `mbedtls`/`lwip`, or almost nothing? A prebuilt-lib SDK (BS2X/bs21e) will usually be missing the OHOS startup hook, the linker `__zinitcall_*` sections, POSIX/VFS, littlefs and pthread — all of which Phase 2.5 handles.
11. **OHOS startup bridge**: does the SDK app call `OHOS_SystemInit()` (weak) from a startup task? If not, the OHOS components will be linked but garbage-collected (see Phase 2.5).

Write the sheet down (chip, toolchain, arch, target names, include list, mbedtls versions). It becomes the source of truth for Phases 1–3.

## Phase 1 — SoC layer `device/soc/<company>/<chip>/`

1. **Place the SDK source** at `sdk/`, excluding build outputs: `output/`, `interim_binary/<chip>/libs/`, `temp/`, `__pycache__/`, `*.pyc`. Keep the rest of `interim_binary/` (e.g. prebuilt HSO database) if the SDK needs it.
2. **Top `BUILD.gn`**: a group named after the chip that depends on the SDK build target:
   ```gn
   group("<chip>") {
     deps = [ "sdk:run_sdk_build" ]
   }
   ```
   (Match the template — ws63 uses `sdk:run_sdk_build`, not `:sdk`.)
3. **`sdk/BUILD.gn`**: mirror the template. It declares `build_<chip>_sdk_open`, `build_<chip>_mode`, and a `build_ext_component("run_sdk_build")` whose `command` is `env <env> bash hm_build.sh $outdir $build_<chip>_sdk_open`, with deps on `//build/lite:ohos`, hichainsdk, and devattest (the devattest deps prevent an intermittent "No rule to make target libdevattest_sdk.a" race). A `lite_component("sdk")` lists the adapter libs (ble_lite, sle_lite, wifiservice).
4. **`sdk/hm_build.sh`**: mirror the template, changing:
   - `output/<chip>/fwpkg`, `interim_binary/<chip>/libs/ohos/<target>`;
   - `python3 build.py -c <target_key>`;
   - `REQUIRED_LIBS` (the libs the SDK link will demand) — keep a sanity check that fails loudly if a lib is missing before cmake runs.
5. **`adapter/`**: copy the sibling chip's `adapter/` and replace `ws63v100`→`<chip-dir>`, `ws63_`→`<chip>_`, `WS63_`→`<CHIP>_`. Then fix API drift against the new SDK headers (see the error cookbook for the BLE callback-struct case).
6. **`sdk/libs_url/<chip>/cmake/ohos.cmake`**: the link closure — see Phase 2.

## Phase 2 — Link closure (the crux; do this consciously)

OHOS components are compiled by GN into `out/<product>/libs/*.a`. They must end up **inside the firmware ELF**. The template mechanism (7.0):

1. `hm_build.sh` copies `out/<product>/libs/*.a` → `interim_binary/<chip>/libs/ohos/<target>/`.
2. The SDK's `protocol/CMakeLists.txt` has a hook:
   ```cmake
   if(EXISTS ${ROOT_DIR}/libs_url/${_CHIP}/cmake/ohos.cmake)
       include(${ROOT_DIR}/libs_url/${_CHIP}/cmake/ohos.cmake)
   endif()
   ```
3. `ohos.cmake` links the OHOS libs into the firmware target with `--whole-archive` (so `--gc-sections` does not drop service-registration sections).

Two working styles for `ohos.cmake`:

- **Template style (ws63)**: register each OHOS component into the SDK's `TARGET_COMPONENT` list and call `build_component()`. This requires adding the OHOS component names to the SDK's `ram_component` in `config.py`. It is fragile: adding those names makes every SDK component's `TARGETS_INTERFACES` reference undefined `<name>_interface` targets, which breaks standalone SDK builds.
- **Direct-link style (simpler, recommended)**: skip `build_component()` and attach the libs straight to the firmware executable:
  ```cmake
  if(NOT EXISTS ${BIN_DIR}/${CHIP}/libs/ohos/${TARGET_COMMAND})
      return()   # standalone SDK build: nothing to link
  endif()
  # build OHOS_LINK_LIBS from a per-target component list, skipping libs that
  # are not produced by this product (some entries are vestigial)
  target_link_libraries(${TARGET_NAME} PRIVATE
      -Wl,--whole-archive ${OHOS_LINK_LIBS} -Wl,--no-whole-archive)
  ```
  The `EXISTS` guard is what lets `build.py -c <target>` still work standalone (L1). Let `hm_build.sh`'s `REQUIRED_LIBS` be the strict gate; `ohos.cmake` should skip absent libs, not hard-fail (the ws63 component list contains a `product` entry that does not exist in a normal build).

**Do not forget**: if the SDK does not already have the `libs_url/.../ohos.cmake` hook in `protocol/CMakeLists.txt`, add it — otherwise the file is never included and the link silently never happens.

**mbedtls source-switch**: newer templates add a `mbedtls_ohos_switch.cmake` dual-gate that links an OHOS-built `libmbedtls_ohos.a` into the SDK. Only port it if the working template's normal product uses it (`mbedtls_ohos_switch = false` by default means you can omit it and let the SDK link its own mbedtls).

## Phase 2.5 — Prebuilt-library SDKs (BS2X / bs21e style): the link closure is not enough

Some SDKs ship the protocol stack, kernel and crypto as prebuilt `.a` (no `protocol/*.c`, `open_source/` almost empty, `kernel/liteos/<ver>/<target>/*.a` prebuilt). For these, `--whole-archive` + `--gc-sections` has a nasty consequence: **the OHOS `.a`s get linked and then immediately discarded**, because nothing in the standalone chip firmware references them. `nm`/`map` then show no OHOS symbols even though the link "succeeded". The ws53 lesson ("compiled but not linked") has a third state here: "linked but garbage-collected". You must give the linker a live reference to the OHOS cluster and provide everything the OHOS libs expect but the SDK lacks.

Work through these, verifying each with the map (a retained symbol has an address; a discarded one appears only under `Discarded input sections`):

1. **Add the OHOS startup bridge.** The firmware's own `main` must reach `OHOS_SystemInit()`. In a source SDK this is often already present (e.g. ws53's `app_os_init.c` has an `ohos_start` task + a weak `OHOS_SystemInit`, guarded by `CONFIG_SUPPORT_OHOS_SUPPORT`). In a prebuilt SDK it is usually absent. Add to the SDK's app-init file:
   ```c
   #ifdef CONFIG_SUPPORT_OHOS_SUPPORT
   __attribute__((weak)) void OHOS_SystemInit(void) { return; }   /* overridden by bootstrap_lite */
   static void ohos_start(void *unused)
   {
       (void)unused;
       PRINT("OHOS START\r\n");
       osal_msleep(3000);          /* let the platform finish init first */
       OHOS_SystemInit();
   }
   #endif
   ```
   and register `ohos_start` as a task in the SDK's task table. Then define `CONFIG_SUPPORT_OHOS_SUPPORT` in the target's `defines` in `build/config/target_config/<chip>/config.py`. Without this, `OHOS_SystemInit` is undefined (link error) or unreferenced (everything GC'd). `OHOS_SystemInit` is defined by `base/startup/bootstrap_lite/services/source/system_init.c`.
2. **Add the OHOS linker sections.** Prebuilt SDK linker scripts often define only `__zinitcall_app_run_*`. `bootstrap_lite`/`inithook` also need `__zinitcall_{bsp,device,core,sys_service,sys_feature,run,app_service,app_feature,test,exit}_{start,end}` around `KEEP(*(.zinitcall.*.init))`. Copy the block from the working sibling's `linker.prelds` into the new chip's app linker script (the one in `drivers/boards/<chip>/linker/<app>_linker/` or `drivers/chips/<chip>/board/linker/<app>/`). Missing them → `undefined reference to __zinitcall_*`.
3. **Add the missing `ohos_adapt` component.** Prebuilt SDKs may not ship `kernel/liteos/ohos_adapt/src/cmsis_adapt.c`; copy it from a sibling and add `ohos_adapt` to the target's `ram_component`. Some kernels already have `add_subdirectory_if_exist(ohos_adapt)` waiting.
4. **Stub what the OHOS libs need but the SDK lacks.** A prebuilt SDK with no POSIX/VFS/littlefs/pthread will fail to link `hiview_lite` (POSIX `open/close/read/write/lseek/fsync/unlink`), `blackbox_lite` (`UtilsFile*`, `pthread_create`) and `param_client_lite` (`UtilsFile*`). Add a small stub source (e.g. `kernel/liteos/ohos_adapt/src/ohos_stub.c`) returning `-1`/`ENOSYS`, and drop `utils_lite_feature_file` from the product config so `hal_file_static` (which needs littlefs `fs_adapt_*`) is not pulled. Remove `hal_file_static`/`native_file` from `hm_build.sh REQUIRED_LIBS` and `ohos.cmake`.
5. **`-Werror=undef`.** Unpatched musl/kernel headers use `#if __ARMEB__` etc., which HUKS turns into errors via `-Werror`. Add `-Wno-error=undef` to `board_cflags` (the sibling SDKs fixed the headers; you don't have to patch dozens of files).
6. **`cmsis_os2.h` `__NO_RETURN`.** Comment out `__NO_RETURN` on `osThreadExit` (the OHOS adapter body is empty → `-Werror`).
7. **Flash space.** OHOS adds ~40 KB+; a chip sized for a non-OHOS app may overflow `FLASH_PROGRAM`. First try trimming the product (see Phase 4 notes: drop `huks` if there is no mbedtls, drop `blackbox_lite`/`hidumper_lite`, `applications`, `updater`). If core components are still over, enlarge the app partition in `build/config/target_config/<chip>/flash_sector_config/<sector>.json` (`param_info` id `0x23` len; move/shrink FOTA id `0x26`) — the partition macros (`APPLICATION_IMAGE_LEN/OFFSET`) are generated from that JSON.
8. **Beware stale OHOS libs.** After removing product components, stale `.a` remain in `out/<product>/<product>/libs/` and get copied into `interim_binary/.../libs/ohos/` and linked (the `EXISTS` check in `ohos.cmake` still finds them). `rm -rf out/<product>/<product>/libs interim_binary/<chip>/libs/ohos` before rebuilding, and keep `hm_build.sh`/`ohos.cmake` component lists in sync with the product config.
9. **Runtime heap exhaustion (`No mem to alloc 0x100c Bytes`).** After `OHOS START` + `hilog/hievent init`, the LiteOS heap may run out at `LiteParamService`: the param service allocates three workspaces (DAC ~5K + BASE ~5K + SIZE ~1K, per `base/startup/init/services/param/include/param_osadp.h`) via the **weak `GetSysParamMem`** hook, which defaults to `malloc` from the LiteOS heap. Small-RAM chips (bs21e: 64K DTCM total, 52K heap shared with the BT stack) die here. Diagnosis: sum the RAM account from `application.map` (`MEMORY` regions + `.heap` + task stacks allocated from the heap). Fix: define a strong `GetSysParamMem`/`FreeSysParamMem` over a static `.bss` pool (bump allocator, never freed) in the SDK's `ohos_adapt` component — the workspaces are init-once and never freed, so a static pool is safe and moves ~11K off the heap. Hardcode the mirrored macros (the SDK build cannot include OHOS headers). Template: `references/file-templates.md`. If still short: shrink SDK task stacks in `app_os_init.c`, or move the heap to a larger RAM region.

For BT/NFC/SLP-only chips (no Wi-Fi), also drop `wifiservice`/`wifi_lite` from the adapter and the `ohos.cmake` list.

## Phase 3 — Board layer `device/board/<company>/<board>/`

Files: `liteos_m/config.gni` + `ohos.build` (that is the whole minimum).

**`config.gni`** (mirror the sibling board):
- `board_arch` / `board_cflags -mabi` matching the SDK ABI (Phase 0).
- `board_toolchain_path` pointing at the SDK-bundled toolchain (avoids PATH drift).
- Defines: `-D<CHIP>=1` (e.g. `-DCHIP_WS53=1`), `-D__LITEOS__`, `-DCMSIS_OS_VER=2`, `-DLWIP_CONFIG_FILE="lwip/lwipopts_default.h"` (verify the file exists).
- `board_include_dirs`: start from the sibling board and add the new SDK's quirks. Common additions beyond the sibling: `drivers/chips/<chip>/include/acore`, `drivers/chips/<chip>/porting/include`, `drivers/boards/<chip>/memory_config/include`, `drivers/boards/<chip>/memory_config/include/product`, and the app linker dir `drivers/boards/<chip>/linker/<app>_linker` (this last one is where `memory_config.h` lives; `interrupt.h → arch_port.h → memory_config.h` makes it mandatory for OHOS adapter files that include SDK `core.h`).
- `board_adapter_dir = "//device/soc/<company>/<chip>/adapter"`.

**`ohos.build`** — part naming is constrained by the build system:
```json
{
  "parts": { "device_<board>": { "module_list": [ "//device/soc/<company>/<chip>:<chip>" ] } },
  "subsystem": "device_<board>"
}
```
The preloader derives the device subsystem/part as `device_<board>` and validates it against `out/preloader/<product>/parts.json`. You **cannot** rename the device part to an arbitrary name in OHOS 7.0.

## Phase 4 — Vendor product layer `vendor/<company>/<product>/`

Files: `config.json`, `ohos.build`, `BUILD.gn`, `hals/utils/{sys_param,token}/`.

**`config.json`** (what makes `hb set` show the product):
- `product_name`, `type: "mini"`, `device_company`, `board`, `device_build_path: "device/board/<company>/<board>"`, `kernel_type: "liteos_m"`, `kernel_is_prebuilt: true`.
- `subsystems`: pick components from the sibling product. For a normal mini product the usual set is applications(`wifi_iot_sample_app`), iothardware(`peripheral`), hiviewdfx(`hilog_lite`,`hievent_lite`,`blackbox_lite`,`hidumper_lite`), systemabilitymgr(`samgr_lite`), security(`huks`), startup(`bootstrap_lite`,`init`), updater(`sys_installer_lite`), commonlibrary(`utils_lite`), developtools(`syscap_codec`). **Verify every component exists** by grepping the OHOS tree's `bundle.json` files.
- **Trim for the chip**: if the SDK has no mbedtls, drop `security:huks` (and set `enable_oh_device_lite_auth = false` in `sdk/BUILD.gn`, since `hichainsdk` pulls huks). If flash is tight, drop `applications`, `updater`, `blackbox_lite`, `hidumper_lite`. If the SDK has no littlefs, omit `utils_lite_feature_file` (otherwise `hal_file_static` needs `fs_adapt_*`). Keep `hm_build.sh`/`ohos.cmake` component lists in sync with whatever survives.
- `third_party_dir: "//device/soc/<company>/<chip>/sdk/open_source"`, `product_adapter_dir: "//vendor/<company>/<product>/hals"`.
- If an XTS product is wanted, add a second `vendor/.../<product>_xts/` and set `huks_dependency_mbedtls_path` to the **SDK's actual mbedtls version dir**.

**`ohos.build`**: `product_<product>` part → `//vendor/<company>/<product>:<product>`. **`BUILD.gn`**: `group("<product>") {}`.

**`hals/`**: copy `sys_param` and `token` from the sibling vendor; fix the SDK include path (`.../<chip>/sdk/include/driver`). `vendor.para` product strings are cosmetic.

## Phase 5 — Public-repo check (usually zero changes)

Check whether OHOS public repos need patches for the new SDK:
- **HUKS / mbedTLS ECDH context**: `base/security/huks/.../hks_mbedtls_x25519.c` accesses `ctx.MBEDTLS_PRIVATE(Qp/d)`. This compiles when `MBEDTLS_ECDH_LEGACY_CONTEXT` is active, which happens when the OHOS mbedtls config defines `MBEDTLS_ECP_RESTARTABLE`. Check `third_party/mbedtls/include/mbedtls/mbedtls_config.h`; if RESTARTABLE is defined, **no patch is needed**. Only if the config removed RESTARTABLE do you need the legacy/new-context dual branch. Confirm empirically by finding the compiled object `.../libhuks_3.0_sdk.hks_mbedtls_x25519.o` and checking it defines `HksMbedtlsX25519KeyAgreement`.
- `git -C <repo> status` each touched public repo; do not silently absorb pre-existing tree modifications.

## Phase 6 — Build verification ladder

Never jump straight to `hb build`. Isolate failures:

- **L0 discovery**: `hb set -p <product>` → must resolve to `<product>@<company>`. Failure here is a vendor `config.json` problem.
- **L1 SDK standalone**: `cd device/soc/<company>/<chip>/sdk && python3 build.py -c <target_key>` → the SDK firmware must build and pack with **no OHOS libs present**. This validates the SDK/toolchain/menuconfig changes in isolation. The `ohos.cmake` `EXISTS` guard makes this possible.
- **L2 full OHOS**: `hb build` (or `hb build -f` for a clean build). This runs GN + the SDK via `hm_build.sh`.
- **Link-closure proof** (the whole point): inspect the firmware ELF/map and confirm OHOS symbols are present **and retained** (have addresses). The map lists both included and discarded sections, so a symbol appearing in the map is not proof:
  ```bash
  nm <sdk>/output/<chip>/acore/<target>/application.elf | grep -icE 'samgr|Hks|Ble|HiLog'
  # retained = has an address; discarded = only under "Discarded input sections"
  grep -m1 'Discarded input sections' application.map
  grep -m2 -E '0x[0-9a-f]+ +(SAMGR_AddInterface|HiLogPrintf|OHOS_SystemInit)' application.map
  grep -oE 'libs/ohos/<target>/lib[a-z0-9_]+\.a' application.map | sort -u
  ```
  If the ELF has no OHOS symbols, or the symbols only appear in the discarded list, go back to Phase 2 (hook missing) or Phase 2.5 (startup bridge missing → everything GC'd).

### Iterating on L2 failures

Read the *real* log, not the wrapper summary:
- `out/<product>/<product>/error.log` — ninja-level failure and the exact failing command;
- `out/<product>/<product>/obj/device/soc/<company>/<chip>/sdk/build.log` — the SDK-side (`hm_build.sh`/cmake) output;
- `<sdk>/output/<chip>/acore/<target>/CMakeFiles/CMakeError.log` or re-run `build.py` standalone to see cmake errors directly.

Most L2 failures are one of a small set: a missing include dir (board `config.gni`), an SDK kernel/menuconfig option that OHOS components require (POSIX/VFS, littlefs, task-joinable, vendor-name), an adapter API mismatch, or a duplicate/undefined symbol. See `references/build-error-cookbook.md` for the signature → root cause → fix table.

## Verification checklist

- [ ] `hb set -p <product>` resolves `<product>@<company>`.
- [ ] L1 `python3 build.py -c <target>` succeeds standalone.
- [ ] L2 `hb build` succeeds.
- [ ] `out/<product>/<product>/pack_all_core/<target>/*.fwpkg` exists.
- [ ] Firmware ELF/map contains OHOS symbols and `libs/ohos/<target>/lib*.a`.
- [ ] Residual check clean: `grep -rn "<old_chip>\|<old_board>\|<OLD_CHIP>" device/soc/<...>/adapter device/board/<...> vendor/<...>` (only comments may remain).
- [ ] `scripts/verify_migration.sh` passes.

## Reference files

- `references/file-templates.md` — copy-paste templates for `BUILD.gn`, `hm_build.sh`, `ohos.cmake`, board `config.gni`, vendor `config.json`/`ohos.build`/`BUILD.gn`, `.gitignore`, plus the OHOS startup bridge and `__zinitcall_*` linker block.
- `references/build-error-cookbook.md` — error signature → root cause → fix, drawn from real migrations.
- `references/case-study-ws53.md` — the full WS53 (Lierda DB35 1.10.106, source SDK) → OpenHarmony 7.0 migration as a worked example.
- `references/case-study-bs21e.md` — the BS21E (prebuilt-library SDK, BT/NFC/SLP, no mbedtls/POSIX/littlefs) → OpenHarmony 7.0 migration, including the startup bridge, zinitcall sections, stubs and flash-fitting.
- `scripts/verify_migration.sh` — residual + include-path + link-closure checker.
