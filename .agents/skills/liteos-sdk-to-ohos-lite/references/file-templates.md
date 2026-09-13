# File templates

Placeholders: `<company>`, `<chip>` (SDK chip name, e.g. `ws53`), `<chip-dir>` (SoC repo dir, e.g. `ws53v106`),
`<board>`, `<product>`, `<TARGET_KEY>` (build.py target key, e.g. `ws53_liteos_app`),
`<APP_LINKER>` (e.g. `ws53_app_linker`), `<TOOLCHAIN>` (e.g. `cc_riscv32_musl_b010/cc_riscv32_musl/bin`).
Adapt to the *sibling working integration in the same OHOS tree*; these are illustrative.

## SoC top `device/soc/<company>/<chip-dir>/BUILD.gn`

```gn
import("//build/lite/config/component/lite_component.gni")

group("<chip-dir>") {
  deps = [ "sdk:run_sdk_build" ]
}
```

## SoC `.gitignore` (`device/soc/<company>/<chip-dir>/.gitignore`)

```
sdk/output/
sdk/interim_binary/<chip>/libs/
sdk/temp/
__pycache__/
*.pyc
```

## `sdk/BUILD.gn` (mirror the sibling's; the XTS bits are harmless if unused)

```gn
import("//build/lite/config/component/lite_component.gni")
import("//test/xts/tools/lite/hctest/hctest_opt_args.gni")

declare_args() {
  build_<chip>_sdk_open = false
  enable_hos_vendor_wifiiot_xts = false
  enable_oh_device_lite_auth = true
  build_<chip>_mode = "normal"
  enable_product_config_patch = false
}

build_env = "BUILD_<CHIP>_MODE=${build_<chip>_mode} ENABLE_PRODUCT_CONFIG_PATCH=${enable_product_config_patch}"
if (build_xts) {
  build_env += " BUILD_XTS=1"
}
build_env += " XTS_OVERLAY_ARG=${xts_overlay} HCTEST_RODATA_OPT_ARG=${hctest_rodata_opt}"

group("nearllink_sdk") {
  deps = [ ":sdk" ]
}

build_ext_component("run_sdk_build") {
  exec_path = rebase_path(".", root_build_dir)
  outdir = rebase_path(root_out_dir)
  command = "env $build_env bash hm_build.sh $outdir $build_<chip>_sdk_open"
  deps = [
    ":sdk",
    "//build/lite:ohos"
  ]
  if (enable_oh_device_lite_auth) {
    deps += [ "//base/security/device_auth/frameworks/deviceauth_lite:hichainsdk" ]
  }
  if (enable_hos_vendor_wifiiot_xts) {
    deps += [ "//build/lite/config/subsystem/xts:xts" ]
  }
  # Explicit deps avoid an intermittent GN/Ninja race where the OHOS libs are
  # copied before archiving finishes ("No rule to make target libdevattest_sdk.a").
  if (ohos_kernel_type == "liteos_m") {
    deps += [
      "//test/xts/device_attest_lite/framework:devattest_sdk",
      "//test/xts/device_attest_lite/services/core:devattest_core",
    ]
  }
}

lite_component("sdk") {
  features = []
  deps = [
    "//build/lite/config/component/cJSON:cjson_static",
    "//device/soc/<company>/<chip-dir>/adapter/hals/communication/ble_lite",
    "//device/soc/<company>/<chip-dir>/adapter/hals/communication/sle_lite",
    "//device/soc/<company>/<chip-dir>/adapter/hals/communication/wifi_lite/wifiservice",
  ]
}
```

## `sdk/hm_build.sh`

```bash
#!/bin/bash
set -e
product_out_dir="$1"
build_<chip>_sdk_open="$2"

if [ "$XTS_OVERLAY_ARG" = "true" ]; then
    export XTS_OVERLAY_ENABLE=true
fi
if [ "$XTS_OVERLAY_ARG" = "true" ] || [ "$HCTEST_RODATA_OPT_ARG" = "true" ]; then
    export HCTEST_NEW_RUNNER=true
fi

CROOT=$(pwd)
OUTPUT_SRC_DIR=$CROOT/output/<chip>/fwpkg
OUTPUT_DST_DIR=$1
OHOS_LIBS_DIR=$CROOT/interim_binary/<chip>/libs/ohos/<TARGET_KEY>
OHOS_LIBS_XTS_DIR=$CROOT/interim_binary/<chip>/libs/ohos/<TARGET_KEY_XTS>

rm -rf $OHOS_LIBS_DIR $OHOS_LIBS_XTS_DIR
mkdir -p $OHOS_LIBS_DIR $OHOS_LIBS_XTS_DIR
find $OUTPUT_DST_DIR/libs/ -name '*.a' -exec cp "{}" $OHOS_LIBS_XTS_DIR \;
find $OUTPUT_DST_DIR/libs/ -name '*.a' -exec cp "{}" $OHOS_LIBS_DIR \;

# Strict gate: these must exist before cmake links them.
REQUIRED_LIBS="begetutil bootstrap hal_file_static hal_sys_param hal_sysparam hal_update_static hichainsdk hilog_lite_static hilog_static hiview_lite_static hievent_lite_static huks_3.0_sdk init_log init_utils inithook samgr samgr_adapter samgr_source cjson_static blackbox_lite hidumper_mini ble_lite sle_lite wifiservice native_file udidcomm param_client_lite hota hal_iothardware"
MISSING_LIBS=""
for lib in $REQUIRED_LIBS; do
    [ -f "$OHOS_LIBS_DIR/lib${lib}.a" ] || MISSING_LIBS="$MISSING_LIBS lib${lib}.a"
done
if [ -n "$MISSING_LIBS" ]; then
    echo "[ERROR] hm_build.sh: missing OHOS libs in $OHOS_LIBS_DIR:$MISSING_LIBS"
    exit 1
fi

echo "build <chip> sdk = $build_<chip>_sdk_open"
if [ "$build_<chip>_sdk_open" = "true" ]; then
    export build_<chip>_sdk_open=true
fi

if [[ "$product_out_dir" == *xts* ]]; then
    python3 build.py -c <TARGET_KEY_XTS>
else
    python3 build.py -c <TARGET_KEY>
fi

[ -d $OUTPUT_DST_DIR ] || mkdir $OUTPUT_DST_DIR
cp $OUTPUT_SRC_DIR/* $OUTPUT_DST_DIR/ -rf
```

## `sdk/libs_url/<chip>/cmake/ohos.cmake` (direct-link style)

```cmake
# Included by protocol/CMakeLists.txt when it exists.
# TARGET_COMMAND == the build.py target key; directory names use that exact string.

if(NOT EXISTS ${BIN_DIR}/${CHIP}/libs/ohos/${TARGET_COMMAND})
    return()   # standalone SDK build (L1): nothing to link
endif()

if(${TARGET_COMMAND} MATCHES "<TARGET_KEY>")
    set(OHOS_COMPONENT_LIST
        "begetutil" "hilog_lite_static" "samgr_adapter" "bootstrap" "hal_update_static"
        "hilog_static" "inithook" "samgr_source" "broadcast" "hal_file_static" "init_log"
        "native_file" "udidcomm" "cjson_static" "hal_sys_param" "hichainsdk" "hota"
        "init_utils" "param_client_lite" "hiview_lite_static" "hal_sysparam"
        "hievent_lite_static" "huks_3.0_sdk" "samgr" "blackbox_lite" "hal_iothardware"
        "wifiservice" "hidumper_mini" "ble_lite" "sle_lite" "product")
endif()

set(OHOS_LIB_DIR ${BIN_DIR}/${CHIP}/libs/ohos/${TARGET_COMMAND})
foreach(COMPONENT ${OHOS_COMPONENT_LIST})
    if(EXISTS ${OHOS_LIB_DIR}/lib${COMPONENT}.a)
        list(APPEND OHOS_LINK_LIBS ${OHOS_LIB_DIR}/lib${COMPONENT}.a)
    else()
        message(STATUS "ohos.cmake: lib${COMPONENT}.a not present, skipped")
    endif()
endforeach()

if(OHOS_LINK_LIBS)
    target_link_libraries(${TARGET_NAME} PRIVATE
        -Wl,--whole-archive ${OHOS_LINK_LIBS} -Wl,--no-whole-archive)
endif()
```

## Board `device/board/<company>/<board>/liteos_m/config.gni`

```gn
kernel_type = "liteos_m"
kernel_version = ""
board_cpu = ""

# Must match the SDK firmware ABI. riscv31 + no FPU => rv32imc / -mabi=ilp32;
# an *_fp toolchain => rv32imfc / -mabi=ilp32f.
board_arch = "rv32imc"

board_toolchain = "riscv32-linux-musl"
board_toolchain_path =
    "${ohos_root_path}device/soc/<company>/<chip-dir>/sdk/tools/bin/compiler/riscv/<TOOLCHAIN>"
board_toolchain_prefix = "riscv32-linux-musl-"
board_toolchain_type = "gcc"

board_cflags = [
  "-mabi=ilp32",
  "-falign-functions=2", "-msave-restore", "-fno-optimize-strlen",
  "-freorder-blocks-algorithm=simple", "-fno-schedule-insns",
  "-fno-inline-small-functions", "-fno-inline-functions-called-once",
  "-mtune=size", "-mno-small-data-limit=0", "-fno-aggressive-loop-optimizations",
  "-std=c99", "-Wpointer-arith", "-Wstrict-prototypes",
  "-ffunction-sections", "-fdata-sections", "-fno-exceptions",
  "-fshort-enums", "-Wextra", "-Wundef", "-U", "PRODUCT_CFG_BUILD_TIME",
  "-D__LITEOS__", "-DCMSIS_OS_VER=2", "-DLOSCFG_COMPAT_CMSIS_VER_2",
  "-DCHIP_<CHIP_UPPER>=1",
  "-DLWIP_CONFIG_FILE=\"lwip/lwipopts_default.h\"",
]
board_cxx_flags = board_cflags
board_ld_flags = []

sdk = "sdk"
board_include_dirs = [
  "${ohos_root_path}commonlibrary/utils_lite/include",
  "${ohos_root_path}device/soc/<company>/<chip-dir>/${sdk}/include",
  "${ohos_root_path}device/soc/<company>/<chip-dir>/${sdk}/include/driver",
  "${ohos_root_path}device/soc/<company>/<chip-dir>/${sdk}/include/middleware/utils",
  # ... all sibling-board includes with <chip> substituted ...
  "${ohos_root_path}device/soc/<company>/<chip-dir>/${sdk}/drivers/chips/<chip>/include",
  "${ohos_root_path}device/soc/<company>/<chip-dir>/${sdk}/drivers/chips/<chip>/include/acore",
  "${ohos_root_path}device/soc/<company>/<chip-dir>/${sdk}/drivers/chips/<chip>/porting/include",
  "${ohos_root_path}device/soc/<company>/<chip-dir>/${sdk}/drivers/boards/<chip>/memory_config/include",
  "${ohos_root_path}device/soc/<company>/<chip-dir>/${sdk}/drivers/boards/<chip>/memory_config/include/product",
  "${ohos_root_path}device/soc/<company>/<chip-dir>/${sdk}/drivers/boards/<chip>/linker/<APP_LINKER>",
  # ... kernel/open_source/musl includes ...
  "${ohos_root_path}/kernel/liteos_m/utils/",
]

board_adapter_dir = "//device/soc/<company>/<chip-dir>/adapter"
board_configed_sysroot = ""
storage_type = ""
```

## Board `ohos.build`

```json
{
  "parts": {
    "device_<board>": {
      "module_list": [ "//device/soc/<company>/<chip-dir>:<chip-dir>" ]
    }
  },
  "subsystem": "device_<board>"
}
```

## Vendor `config.json`

```json
{
  "product_name": "<product>",
  "type": "mini",
  "version": "3.0",
  "ohos_version": "OpenHarmony <release>",
  "device_company": "<company>",
  "device_build_path": "device/board/<company>/<board>",
  "board": "<board>",
  "kernel_type": "liteos_m",
  "kernel_is_prebuilt": true,
  "kernel_version": "",
  "subsystems": [
    { "subsystem": "applications", "components": [ { "component": "wifi_iot_sample_app", "features": [] } ] },
    { "subsystem": "iothardware", "components": [ { "component": "peripheral", "features": [] } ] },
    { "subsystem": "hiviewdfx", "components": [
        { "component": "hilog_lite", "features": [] },
        { "component": "hievent_lite", "features": [] },
        { "component": "blackbox_lite", "features": [] },
        { "component": "hidumper_lite", "features": [] } ] },
    { "subsystem": "systemabilitymgr", "components": [ { "component": "samgr_lite", "features": [] } ] },
    { "subsystem": "security", "components": [ { "component": "huks", "features": [
        "huks_use_lite_storage = true",
        "huks_use_hardware_root_key = true",
        "huks_config_file = \"hks_config_lite.h\"" ] } ] },
    { "subsystem": "startup", "components": [
        { "component": "bootstrap_lite", "features": [] },
        { "component": "init", "features": [
            "init_feature_begetctl_liteos = true",
            "init_lite_use_thirdparty_mbedtls = true" ] } ] },
    { "subsystem": "updater", "components": [ { "component": "sys_installer_lite", "features": [] } ] },
    { "subsystem": "commonlibrary", "components": [ { "component": "utils_lite", "features": [ "utils_lite_feature_file = true" ] } ] },
    { "subsystem": "developtools", "components": [ { "component": "syscap_codec", "features": [] } ] }
  ],
  "third_party_dir": "//device/soc/<company>/<chip-dir>/sdk/open_source",
  "product_adapter_dir": "//vendor/<company>/<product>/hals"
}
```

## Vendor `ohos.build` / `BUILD.gn`

```json
{
  "parts": { "product_<product>": { "module_list": [ "//vendor/<company>/<product>:<product>" ] } },
  "subsystem": "product_<product>"
}
```

```gn
group("<product>") {
}
```

## OHOS startup bridge (for prebuilt-library SDKs)

Add to the SDK's app-init file (e.g. `drivers/chips/<chip>/main_init/app_os_init.c`), guarded by a config you add to the target `defines` (`build/config/target_config/<chip>/config.py`). Register `ohos_start` in the SDK task table too.

```c
#ifdef CONFIG_SUPPORT_OHOS_SUPPORT
__attribute__((weak)) void OHOS_SystemInit(void)
{
    return;                 /* overridden by bootstrap_lite's strong symbol */
}

static void ohos_start(void *unused)
{
    (void)unused;
    PRINT("OHOS START\r\n");
    osal_msleep(3000);      /* let the platform finish initializing first */
    OHOS_SystemInit();
}
#endif
```

## Linker `__zinitcall_*` block (add to the app linker script)

Prebuilt SDK linker scripts often only define `__zinitcall_app_run_*`. Add the rest (inside the app `.text` section) or you get `undefined reference to __zinitcall_*` / OHOS sections GC'd.

```ld
        __zinitcall_bsp_start = .;
        KEEP (*(.zinitcall.bsp0.init)) KEEP (*(.zinitcall.bsp1.init))
        KEEP (*(.zinitcall.bsp2.init)) KEEP (*(.zinitcall.bsp3.init)) KEEP (*(.zinitcall.bsp4.init))
        __zinitcall_bsp_end = .;
        __zinitcall_device_start = .;
        KEEP (*(.zinitcall.device0.init)) KEEP (*(.zinitcall.device1.init))
        KEEP (*(.zinitcall.device2.init)) KEEP (*(.zinitcall.device3.init)) KEEP (*(.zinitcall.device4.init))
        __zinitcall_device_end = .;
        __zinitcall_core_start = .;
        KEEP (*(.zinitcall.core0.init)) KEEP (*(.zinitcall.core1.init))
        KEEP (*(.zinitcall.core2.init)) KEEP (*(.zinitcall.core3.init)) KEEP (*(.zinitcall.core4.init))
        __zinitcall_core_end = .;
        __zinitcall_sys_service_start = .;
        KEEP (*(.zinitcall.sys.service0.init)) KEEP (*(.zinitcall.sys.service1.init))
        KEEP (*(.zinitcall.sys.service2.init)) KEEP (*(.zinitcall.sys.service3.init)) KEEP (*(.zinitcall.sys.service4.init))
        __zinitcall_sys_service_end = .;
        __zinitcall_sys_feature_start = .;
        KEEP (*(.zinitcall.sys.feature0.init)) KEEP (*(.zinitcall.sys.feature1.init))
        KEEP (*(.zinitcall.sys.feature2.init)) KEEP (*(.zinitcall.sys.feature3.init)) KEEP (*(.zinitcall.sys.feature4.init))
        __zinitcall_sys_feature_end = .;
        __zinitcall_run_start = .;
        KEEP (*(.zinitcall.run0.init)) KEEP (*(.zinitcall.run1.init))
        KEEP (*(.zinitcall.run2.init)) KEEP (*(.zinitcall.run3.init)) KEEP (*(.zinitcall.run4.init))
        __zinitcall_run_end = .;
        __zinitcall_app_service_start = .;
        KEEP (*(.zinitcall.app.service0.init)) KEEP (*(.zinitcall.app.service1.init))
        KEEP (*(.zinitcall.app.service2.init)) KEEP (*(.zinitcall.app.service3.init)) KEEP (*(.zinitcall.app.service4.init))
        __zinitcall_app_service_end = .;
        __zinitcall_app_feature_start = .;
        KEEP (*(.zinitcall.app.feature0.init)) KEEP (*(.zinitcall.app.feature1.init))
        KEEP (*(.zinitcall.app.feature2.init)) KEEP (*(.zinitcall.app.feature3.init)) KEEP (*(.zinitcall.app.feature4.init))
        __zinitcall_app_feature_end = .;
        __zinitcall_test_start = .;
        KEEP (*(.zinitcall.test0.init)) KEEP (*(.zinitcall.test1.init))
        KEEP (*(.zinitcall.test2.init)) KEEP (*(.zinitcall.test3.init)) KEEP (*(.zinitcall.test4.init))
        __zinitcall_test_end = .;
        __zinitcall_exit_start = .;
        KEEP (*(.zinitcall.exit0.init)) KEEP (*(.zinitcall.exit1.init))
        KEEP (*(.zinitcall.exit2.init)) KEEP (*(.zinitcall.exit3.init)) KEEP (*(.zinitcall.exit4.init))
        __zinitcall_exit_end = .;
```

## OHOS stub source (for SDKs with no POSIX/littlefs/pthread)

Place in the SDK's `ohos_adapt` component and add it to its `CMakeLists.txt` `SOURCES`.

```c
#include <stddef.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>

int open(const char *path, int oflag, ...) { (void)path; (void)oflag; errno = ENOSYS; return -1; }
int close(int fd) { (void)fd; errno = ENOSYS; return -1; }
ssize_t read(int fd, void *buf, size_t count) { (void)fd; (void)buf; (void)count; errno = ENOSYS; return -1; }
ssize_t write(int fd, const void *buf, size_t count) { (void)fd; (void)buf; (void)count; errno = ENOSYS; return -1; }
off_t lseek(int fd, off_t offset, int whence) { (void)fd; (void)offset; (void)whence; errno = ENOSYS; return (off_t)-1; }
int fsync(int fd) { (void)fd; errno = ENOSYS; return -1; }
int unlink(const char *path) { (void)path; errno = ENOSYS; return -1; }
int pthread_create(pthread_t *t, const pthread_attr_t *a, void *(*f)(void *), void *arg)
{ (void)t; (void)a; (void)f; (void)arg; return -1; }
int UtilsFileOpen(const char *path, int oflag, int mode) { (void)path; (void)oflag; (void)mode; return -1; }
int UtilsFileClose(int fd) { (void)fd; return -1; }
int UtilsFileRead(int fd, char *buf, unsigned int len) { (void)fd; (void)buf; (void)len; return -1; }
int UtilsFileWrite(int fd, const char *buf, unsigned int len) { (void)fd; (void)buf; (void)len; return -1; }
int UtilsFileStat(const char *path, unsigned int *fileSize) { (void)path; (void)fileSize; return -1; }
```

## Static param-memory pool (small-RAM chips: `No mem to alloc 0x100c`)

Drop-in override for the weak `GetSysParamMem`/`FreeSysParamMem` in
`base/startup/init/services/param/liteos/param_osadp.c`. Add as
`kernel/liteos/ohos_adapt/src/ohos_param_mem.c` and list it in the
`ohos_adapt` `CMakeLists.txt` `SOURCES`. The pool lands in `.bss` (ITCM/SRAM),
freeing ~11 KB of the LiteOS heap.

```c
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* Values mirrored from base/startup/init/services/param/include/param_osadp.h
 * (__LITEOS_M__ branch). Deliberately hardcoded: the SDK build cannot include
 * OHOS tree headers. Keep in sync when bumping the param component. */
#define PARAM_WORKSPACE_MAX   (1024 * 5)   /* PARAM_WORKSPACE_SMALL == MAX on liteos_m */
#define PARAM_WORKSPACE_MIN   (1024)

/* DAC 5K + BASE 5K + SIZE 1K, plus headroom for the WorkSpace headers. */
#define OHOS_PARAM_MEM_POOL_SIZE (PARAM_WORKSPACE_MAX + PARAM_WORKSPACE_MAX + \
                                  PARAM_WORKSPACE_MIN + 512)

static uint8_t g_paramMemPool[OHOS_PARAM_MEM_POOL_SIZE];
static uint32_t g_paramMemUsed;

void *GetSysParamMem(uint32_t spaceSize)
{
    void *mem = NULL;

    if (spaceSize == 0 || spaceSize > (OHOS_PARAM_MEM_POOL_SIZE - g_paramMemUsed)) {
        return NULL;
    }
    /* 4-byte aligned bump allocator; never freed by design. */
    g_paramMemUsed = (g_paramMemUsed + 3) & ~0x3U;
    mem = &g_paramMemPool[g_paramMemUsed];
    g_paramMemUsed += spaceSize;
    (void)memset(mem, 0, spaceSize);
    return mem;
}

void FreeSysParamMem(void *mem)
{
    /* Static pool: nothing to free. */
    (void)mem;
}
```
