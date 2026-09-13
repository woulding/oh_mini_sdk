# Build error cookbook

Signature → root cause → fix. Most of these came from real WS53/WS63 migrations; the pattern generalizes to any LiteOS SDK.

## Debugging entry points

When `hb build` fails, the wrapper only says "build failed". The real messages are in:

- `out/<product>/<product>/error.log` — the failing Ninja command and compiler/linker output.
- `out/<product>/<product>/obj/device/soc/<company>/<chip>/sdk/build.log` — SDK-side (`hm_build.sh`/cmake) output.
- Re-run the SDK build directly for cmake errors: `cd device/soc/<company>/<chip>/sdk && python3 build.py -c <target>`.

Classify by which stage fails: **preloader/loader** (config naming), **GN** (dependency graph), **OHOS compile**, **SDK cmake configure**, **SDK compile**, **link**.

---

## Preloader / loader (config naming)

| Error | Root cause | Fix |
|---|---|---|
| `subsystem name config incorrect in .../ohos.build, build file subsystem name is X, configured subsystem name is device_<board>` | OHOS 7.0 preloader hard-codes the device subsystem to `device_<board>`. | Set the board `ohos.build` `subsystem` to `device_<board>`. |
| `find component device_<board> failed, please check .../out/preloader/<product>/parts.json` | Same mechanism applies to the **part name**; the device part must equal `device_<board>`. | Set the board `ohos.build` part name to `device_<board>` too. Do not try to use a custom part name for the device layer. |
| Product not listed by `hb set` | `vendor/<company>/<product>/config.json` missing/invalid, or `type` isn't `mini`. | Ensure `type: "mini"`, valid JSON, `device_build_path` exists. |

## GN

| Error | Root cause | Fix |
|---|---|---|
| `Unresolved dependencies. //device/soc/...:<chip-dir> needs //device/soc/...:sdk` | Top SoC `BUILD.gn` depends on `:sdk` but the target is `run_sdk_build` in `sdk/BUILD.gn`. | `deps = [ "sdk:run_sdk_build" ]`. |
| `//vendor/...:<product> not found` / missing target | Vendor `BUILD.gn` group name must equal the module_list target name. | `group("<product>")` and module_list `//vendor/<company>/<product>:<product>`. |
| Component not found in `config.json` subsystems | The component name doesn't exist in this OHOS release. | Grep the tree's `bundle.json` for the component name + subsystem; use names that exist. |

## SDK cmake configure

| Error | Root cause | Fix |
|---|---|---|
| `No rule to make target ... libdevattest_sdk.a` (intermittent) | GN archiving races the `hm_build.sh` copy step. | Add explicit deps on devattest targets in `sdk/BUILD.gn` (template already does). |
| `M=<...>/syschannel_host: No such file or directory` (from a `syschannel_host_ko` custom command) | That component builds a **Linux kernel module** (`make -C $KDIR M=...`); it is irrelevant to the liteos_m firmware. | Remove `syschannel_host_ko` from the target's `ram_component` in `build/config/target_config/<chip>/config.py`. |
| `ohos.cmake: missing .../libproduct.a` | Some entries in the ws63 OHOS component list (e.g. `product`) are vestigial and not produced by a normal product. | In `ohos.cmake`, skip absent libs instead of `FATAL_ERROR`; keep the strict gate in `hm_build.sh REQUIRED_LIBS`. |
| `find_library` finds a prebuilt `.a` in `<dir>/<TARGET_COMMAND>` | The SDK expects a per-target prebuilt dir (`kernel/liteos/.../<target>/*.a`) that the vendor package may not ship. | Either build those libs from source via config, or rely on OHOS-provided libs (see POSIX/VFS below). |

## SDK compile (kernel/menuconfig options)

These appear only once OHOS adapter/components are pulled in; the SDK's own app config often has them disabled.

| Error | Root cause | Fix (match the working sibling chip) |
|---|---|---|
| `undefined reference to fs_adapt_close/read/write/stat` | OHOS `hal_file_static` (`littlefs_xts_adapt.c`) needs the SDK littlefs adapt. | Add `little_fs`, `littlefs_adapt_<chip>` to `ram_component`; enable `CONFIG_MIDDLEWARE_SUPPORT_LFS=y` + `CONFIG_LFS_PARTITION_ID=<id>` in the SDK menuconfig (copy the value from the SDK's XTS config). |
| `undefined reference to open/read/write/close/lseek/fsync/unlink` (e.g. from `hiview_util.c`) | OHOS hiview uses POSIX file APIs; the SDK LiteOS config disabled them. | In the LiteOS `.config` (`kernel/liteos/liteos_v208.5.0/Huawei_LiteOS/tools/build/config/<chip>.config`): set `LOSCFG_COMPAT_POSIX=y`, `LOSCFG_FS_COMPAT_NUTTX=y`, `LOSCFG_FS_VFS=y` (mirror the sibling's app config). |
| `'LOSCFG_LIB_VENDORNAME' undeclared` in `libc/misc/misc.c` | POSIX enablement pulls in code that reads the vendor-name macro. | Add `LOSCFG_LIB_VENDORNAME="vendor"` to the LiteOS `.config`. |
| `'LosTaskCB' has no member named 'threadJoinRetval'` in `pthread.c` | POSIX pthread needs task-join support in the kernel struct. | Add `LOSCFG_TASK_JOINABLE=y` to the LiteOS `.config`. |
| `'CONFIG_LFS_PARTITION_ID' undeclared` in `littlefs_adapt.c` | LFS enabled as a component but not configured in the SDK menuconfig. | Enable `CONFIG_MIDDLEWARE_SUPPORT_LFS=y` and set `CONFIG_LFS_PARTITION_ID` (use the SDK's XTS value). |
| `'noreturn' function does return [-Werror]` at `cmsis_adapt.c` `osThreadExit` | `cmsis_os2.h` declares `osThreadExit` as `__NO_RETURN` but the OHOS adapter body is empty. | Comment out `__NO_RETURN` in the SDK's `cmsis_os2.h` (the sibling integration does exactly this). |
| `undefined reference to osThreadGetArgument` | The OHOS CMSIS hook component isn't built. | Add `ohos_adapt` (and usually `printf_adapt`) to `ram_component`. |

## Link

| Error | Root cause | Fix |
|---|---|---|
| `multiple definition of cJSONUtils_*` (OHOS `libcjson_static.a` vs SDK `libcjson.a`) | Both define cJSON. | Remove the SDK `cjson` from `ram_component` (OHOS `cjson_static` supplies it). Confirm no SDK source uses `cJSON_` first. |
| `cannot find -l<name>_interface` for every OHOS component | You added OHOS component names to the SDK `ram_component`, so `TARGETS_INTERFACES` propagates undefined `<name>_interface` targets, and `build_component()` never created them. | Don't add OHOS names to `ram_component`. Use the direct-link `ohos.cmake` style and attach libs to `${TARGET_NAME}`. |
| OHOS libs missing from the firmware ELF (but they compiled) | The `libs_url/.../ohos.cmake` hook is absent from `protocol/CMakeLists.txt`, or the `EXISTS` guard returned because `interim_binary/<chip>/libs/ohos/<target>` was empty. | Add the include hook; ensure `hm_build.sh` populates `libs/ohos/<target>` before `build.py` runs. Verify with `nm`/`map`. |
| Link succeeds but `--gc-sections` drops service registration | OHOS libs linked without `--whole-archive`. | Link them inside `-Wl,--whole-archive ... -Wl,--no-whole-archive`. |

## Prebuilt-library SDK / OHOS bring-up (BS2X / bs21e style)

A prebuilt-library SDK links the OHOS `.a`s and then `--gc-sections` throws them away because nothing references them. These are the signatures seen on bs21e, in the order they appear.

| Error / symptom | Root cause | Fix |
|---|---|---|
| `undefined reference to __zinitcall_bsp_start` / `__zinitcall_sys_service_*` / `__zinitcall_device_*` / `__zinitcall_core_*` / `__zinitcall_run_*` / `__zinitcall_app_service_*` / `__zinitcall_app_feature_*` / `__zinitcall_test_*` / `__zinitcall_exit_*` | The SDK linker script defines only `__zinitcall_app_run_*`; `bootstrap_lite`/`inithook` reference the full OHOS set. | Add the missing `__zinitcall_*` blocks (`__x_start = .; KEEP(*(.zinitcall.x*.init)); __x_end = .;`) to the app linker script (`drivers/boards/<chip>/linker/<app>_linker/linker.prelds` or `drivers/chips/<chip>/board/linker/<app>/linker.prelds`). Copy them from the working sibling. |
| Link succeeds, map lists OHOS libs, but `nm` on `application.elf` shows **no** OHOS symbols (or symbols appear only under `Discarded input sections` with no address) | `--whole-archive` included the libs, but `--gc-sections` discarded them because the firmware's `main` never references the OHOS cluster. | Add the **OHOS startup bridge**: an `ohos_start` task that calls `OHOS_SystemInit()` (weak in the SDK, overridden by `bootstrap_lite`). Guard with a config (e.g. `CONFIG_SUPPORT_OHOS_SUPPORT`) and add it to the target `defines`. See `file-templates.md`. |
| `undefined reference to open/close/read/write/lseek/fsync/unlink` (from `hiview_lite`) | The prebuilt SDK has no POSIX/VFS and the kernel libs are prebuilt, so enabling `LOSCFG_COMPAT_POSIX` does not rebuild anything. | Add stubs (return `-1`/`ENOSYS`) in an SDK-side component (e.g. `ohos_adapt/src/ohos_stub.c`) that is in `ram_component`. Real file logging will not work. |
| `undefined reference to UtilsFileOpen/Close/Read/Write/Stat`, `pthread_create` (from `blackbox_lite`, `param_client_lite`) | OHOS utils_lite file API + pthread missing; `utils_lite_feature_file` was dropped (no littlefs), and the SDK has no pthread. | Stub `UtilsFile*` and `pthread_create` in the same stub file; or drop `blackbox_lite`/`hidumper_lite` from the product to remove the `pthread_create` consumer. |
| `fatal error: crypto/ecx.h: No such file` / `hilog/log.h: No such file` while compiling `libhuks_3.0_sdk.*` **after removing `security:huks` from the product** | Something still pulls huks. `//base/security/device_auth/...:hichainsdk` (added by `enable_oh_device_lite_auth = true` in `sdk/BUILD.gn`) depends on huks, whose deps (mbedtls, hilog) are no longer in the product. | Set `enable_oh_device_lite_auth = false` in `sdk/BUILD.gn` and remove `hichainsdk` from `hm_build.sh REQUIRED_LIBS` / `ohos.cmake`. |
| `error: "__ARMEB__" is not defined, evaluates to 0 [-Werror=undef]` (and `__cplusplus`, …) in `open_source/musl/include/bits/alltypes.h` or kernel headers | Unpatched vendor musl headers use `#if __ARMEB__` instead of `defined(__ARMEB__)`; HUKS compiles with `-Wall -Werror` and the board adds `-Wundef`. The sibling SDKs patched the headers; you do not have to. | Add `-Wno-error=undef` to `board_cflags` (it overrides `-Werror` for that warning regardless of order). |
| `region 'FLASH_PROGRAM' overflowed by N bytes` (firmware link) | OHOS adds ~40 KB+ of retained code; the chip's app partition was sized for a non-OHOS app. | First trim the product (drop `huks` if no mbedtls, `applications`, `updater`, `blackbox_lite`, `hidumper_lite`; see Phase 4). If core components are still over, enlarge the app partition in `build/config/target_config/<chip>/flash_sector_config/<sector>.json`: `param_info` id `0x23` (app) length, move/shrink id `0x26` (FOTA). `APPLICATION_IMAGE_LEN/OFFSET` are generated from that JSON. |
| Overflow is unchanged (byte-for-byte) after removing product components | Stale `.a` files remain in `out/<product>/<product>/libs/` and are copied into `interim_binary/<chip>/libs/ohos/`; `ohos.cmake`'s `EXISTS` check still finds them. | `rm -rf out/<product>/<product>/libs <soc>/sdk/interim_binary/<chip>/libs/ohos` before rebuilding; keep `hm_build.sh`/`ohos.cmake` component lists in sync with the product config. |
| `undefined reference to fs_adapt_*` after enabling `utils_lite_feature_file` on a no-littlefs chip | The file feature pulls the littlefs adapter. | Omit `utils_lite_feature_file` from the product's `utils_lite` features (there is no filesystem on this chip). |
| **Runtime**: boot log reaches `APP|OHOS START` → `hilog will init` → `hievent init success` then stops with `No mem to alloc 0x100c Bytes at pool_addr=0x2000...` | LiteOS heap exhausted during `LiteParamService` (end of `OHOS_SystemInit`): the param service mallocs three workspaces (DAC ~5K + BASE ~5K + SIZE ~1K) via the weak `GetSysParamMem`, defaulting to heap `malloc`. Small-RAM chips whose heap is shared with the protocol stack run out here. Diagnose by summing the RAM account from `application.map` (MEMORY regions, `.heap` size, task stacks allocated from the heap). | Override the weak hook with a static `.bss` bump-allocator pool (`ohos_param_mem.c` in the `ohos_adapt` component, ~11.5 KB) — see `file-templates.md`. The workspaces are init-once and never freed, so a static pool is safe. If still short: shrink SDK task stacks in `app_os_init.c`, or move the heap region. |


| `undefined reference to __zinitcall_{bsp,device,core,sys_service,sys_feature,run,app_service,app_feature,test,exit}_{start,end}` | The chip linker script only defines `__zinitcall_app_run_*`; `bootstrap_lite`/`inithook` need the full OHOS set. | Copy the full `__zinitcall_*` block (with `KEEP(*(.zinitcall.*.init))`) from the sibling's `linker.prelds` into the new chip's app linker script. |
| Link succeeds, but `nm application.elf` has **no** OHOS symbols; they only appear under the map's `Discarded input sections` | `--whole-archive` included the OHOS objects, but `--gc-sections` discarded them because nothing references them — the SDK firmware never calls the OHOS entry. | Add the OHOS startup bridge: an `ohos_start` task calling `OHOS_SystemInit()` (weak), guarded by a config; register it in the SDK task table. See `case-study-bs21e.md`. |
| `undefined reference to open/close/read/write/lseek/fsync/unlink` (from `hiview_util.c`) | SDK has no POSIX/VFS. | Enable POSIX/VFS in a source SDK's LiteOS `.config`; for a prebuilt SDK, add stubs (`ohos_stub.c`). |
| `undefined reference to UtilsFile*` (from `blackbox_lite`/`param_client_lite`) | SDK has no littlefs, so `utils_lite_feature_file` was dropped. | Add `UtilsFile*` stubs, or drop the components. |
| `undefined reference to pthread_create` (from `blackbox_core.c`) | SDK has no pthread. | Add a stub, or drop `blackbox_lite`. |
| `region FLASH_PROGRAM overflowed by N bytes` | OHOS code exceeds the app partition sized for a non-OHOS app. | Trim the product (drop huks if no mbedtls; drop applications/updater/blackbox/hidumper), or enlarge the app partition in `flash_sector_config/<sector>.json` (id `0x23` len, move/shrink FOTA id `0x26`). |
| Still `missing OHOS libs: libhuks_3.0_sdk.a libblackbox_lite.a ...` after removing components from the product | Stale `.a` remain in `out/<product>/<product>/libs/` and are copied into `interim_binary/.../libs/ohos/`, and `ohos.cmake`/`hm_build.sh` still list them. | `rm -rf out/<product>/<product>/libs interim_binary/<chip>/libs/ohos`, and remove the components from both `REQUIRED_LIBS` and the `ohos.cmake` list. |
| `'__ARMEB__' is not defined ... [-Werror=undef]` in musl/kernel headers | Unpatched SDK headers use `#if __ARMEB__`; HUKS adds `-Werror`. | Add `-Wno-error=undef` to `board_cflags` (the sibling SDKs patched the headers instead). |
| `'noreturn' function does return [-Werror]` at `cmsis_adapt.c` | `cmsis_os2.h` declares `osThreadExit` `__NO_RETURN`; OHOS adapter body is empty. | Comment out `__NO_RETURN` in the SDK's `cmsis_os2.h`. |

## Adapter API drift (compile errors in `adapter/`)

| Error | Root cause | Fix |
|---|---|---|
| `gap_ble_callbacks_t` has no member `ble_enable_cb`/`ble_disable_cb` | Newer SDKs move `enable_ble()/disable_ble()` to `bts/common/bts_device_manager.h` as synchronous calls and drop the callbacks. | Remove those two designated initializers from the adapter's callback struct; add `bts/common` to include dirs if the header moved. Keep any now-unused callback stubs (they're harmless) or delete them. |
| Missing `ws63_*` / wrong-prefixed headers | Vendor-specific header renames. | Rename the adapter's copied headers consistently and update `#include`s and `BUILD.gn` paths. |
| `platform_core.h` not found | Chip splits headers per core (`chips/<chip>/include/{acore,control_core}`). | Add `.../include/acore` to board includes. |

## Toolchain

| Symptom | Root cause | Fix |
|---|---|---|
| Build picks the wrong gcc / version drift between runs | Reliance on `~/.bashrc` PATH. | Point `board_toolchain_path` at the SDK-bundled toolchain; the SDK side already uses its own `tools/`. |
| ABI mismatch (link errors, bad code) | Board arch/ABI doesn't match the SDK firmware (`rv32imc/ilp32` vs `rv32imfc/ilp32f`). | Match `board_arch` and `-mabi` to the SDK target's `arch`/toolchain variant. |
