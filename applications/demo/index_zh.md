# OpenHarmony WS53/WS63 Demo 接入说明

本文说明 `applications/demo` 的 demo 选择机制，以及新增开发板时需要调整的位置。

## 目标

当前工程里 `fbb_ws53` 和 `nearlink_dk_3863` 都启用了 `wifi_iot_sample_app`。如果所有 demo 都直接写在 `applications/sample/wifi-iot/app/BUILD.gn`，那么不同芯片会共用同一个 demo 选择结果。

新的接法把职责拆开：

- `applications/sample/wifi-iot/app/BUILD.gn` 只根据 `hb set` 选择的开发板分发到对应芯片目录。
- `applications/demo/ohos_ws63/BUILD.gn` 只负责选择 WS63 当前要编译的 demo。
- `applications/demo/ohos_ws53/BUILD.gn` 只负责选择 WS53 当前要编译的 demo。
- SDK 链接层固定识别 `ws63_demo` 和 `ws53_demo` 两个库名。

## 当前链路

产品配置启用应用组件：

```text
vendor/<product>/config.json
  -> applications:wifi_iot_sample_app
```

组件描述指向公共 app 入口：

```text
applications/sample/wifi-iot/app/bundle.json
  -> //applications/sample/wifi-iot/app:app
```

公共 app 入口根据 `device_name` 分流：

```gn
lite_component("app") {
  features = [ "startup" ]

  if (device_name == "nearlink_dk_3863") {
    features += [ "//applications/demo/ohos_ws63:ohos_ws63_demo" ]
  } else if (device_name == "fbb_ws53") {
    features += [ "//applications/demo/ohos_ws53:ohos_ws53_demo" ]
  }
}
```

`device_name` 来自 `hb set` 后生成的构建参数。当前对应关系是：

```text
nearlink_dk_3863 -> applications/demo/ohos_ws63
fbb_ws53         -> applications/demo/ohos_ws53
```

## 固定库名

WS63 当前 demo 选择器：

```gn
# applications/demo/ohos_ws63/BUILD.gn
group("ohos_ws63_demo") {
  deps = [ "hello_world:ws63_demo" ]
}
```

WS53 当前 demo 选择器：

```gn
# applications/demo/ohos_ws53/BUILD.gn
group("ohos_ws53_demo") {
  deps = [ "hello_world:ws53_demo" ]
}
```

每个具体 demo 对外暴露固定库名。例如：

```gn
# applications/demo/ohos_ws63/hello_world/BUILD.gn
static_library("ws63_demo") {
  sources = [ "hello_world.c" ]
  include_dirs = [ "//commonlibrary/utils_lite/include" ]
}
```

```gn
# applications/demo/ohos_ws53/hello_world/BUILD.gn
static_library("ws53_demo") {
  sources = [ "hello_world.c" ]
  include_dirs = [ "//commonlibrary/utils_lite/include" ]
}
```

这样后续切换 demo 时，只改对应芯片目录下的选择器：

```gn
group("ohos_ws63_demo") {
  deps = [ "00_thread:ws63_demo" ]
}
```

或者：

```gn
group("ohos_ws53_demo") {
  deps = [ "gpio_led:ws53_demo" ]
}
```

同一个芯片目录下，一次只选择一个固定库名 demo，避免多个 `libws63_demo.a` 或多个 `libws53_demo.a` 同时输出。

## SDK 链接层

GN 只负责把 demo 编译成 `.a` 并放到 `out/<product>/libs/`。最终固件由芯片 SDK 的 CMake 链接生成，所以固定库名还必须进入 SDK 链接闭环。

WS63 使用 `ram_component + COMPONENT_LIST` 方式：

```text
device/soc/hisilicon/ws63v100/sdk/build/config/target_config/ws63/config.py
  ws63-liteos-app / ram_component
    -> "ws63_demo"

device/soc/hisilicon/ws63v100/sdk/libs_url/ws63/cmake/ohos.cmake
  ws63-liteos-app / COMPONENT_LIST
    -> "ws63_demo"
```

WS53 使用直接链接 OHOS 静态库方式，不需要把 demo 加到 `ram_component`：

```text
device/soc/hisilicon/ws53v106/sdk/libs_url/ws53/cmake/ohos.cmake
  ws53_liteos_app / OHOS_COMPONENT_LIST
    -> "ws53_demo"
```

WS53 还需要在 `ws53_liteos_app` 的 SDK defines 中启用 `CONFIG_SUPPORT_OHOS_SUPPORT`。该宏会把 `ohos_start` 任务加入 WS53 的应用任务列表，`ohos_start` 再调用 `OHOS_SystemInit()`，最终触发 `APP_FEATURE_INIT` 注册的 demo 函数。如果没有该宏，`libws53_demo.a` 即使已经链接进固件，也不会执行。

两个芯片的 `hm_build.sh` 中也把固定 demo 库加入 `REQUIRED_LIBS`。这样如果 GN 没有生成对应 demo 库，SDK 构建会明确报缺少 `libws63_demo.a` 或 `libws53_demo.a`，不会静默漏链接。

## 新增 demo

以 WS63 新增 `00_thread` 为例：

```text
applications/demo/ohos_ws63/00_thread/
  BUILD.gn
  thread.c
```

`BUILD.gn` 对外仍然输出固定目标名：

```gn
static_library("ws63_demo") {
  sources = [ "thread.c" ]
  include_dirs = [
    "//commonlibrary/utils_lite/include",
    "//device/soc/hisilicon/ws63v100/adapter/kal/cmsis",
    "//device/soc/hisilicon/ws63v100/sdk/kernel/osal/include/debug",
  ]
}
```

然后修改 `applications/demo/ohos_ws63/BUILD.gn`：

```gn
group("ohos_ws63_demo") {
  deps = [ "00_thread:ws63_demo" ]
}
```

WS53 同理，只是固定目标名为 `ws53_demo`，include 路径按 WS53 SDK 调整。

## 新增开发板

新增开发板时，建议按下面顺序接入：

1. 在 `vendor/<company>/<product>/config.json` 中启用 `wifi_iot_sample_app`。
2. 确认 `hb set -p <product>` 后的 `device_name`，通常等于产品配置里的 `board`。
3. 在 `applications/sample/wifi-iot/app/BUILD.gn` 中增加一个分流分支。
4. 新建 `applications/demo/<board_or_chip>/BUILD.gn` 作为该开发板的 demo 选择器。
5. 为该开发板约定一个固定 demo 库名，例如 `wsXX_demo`。
6. 在对应 SoC SDK 的 `ohos.cmake` 中把固定库名加入链接列表。
7. 如果该 SoC 仍使用 `ram_component + COMPONENT_LIST` 风格，还要把固定库名加入目标 `config.py` 的 `ram_component`。
8. 在对应 `hm_build.sh` 的 normal `REQUIRED_LIBS` 中加入固定库名，作为缺库检查。

判断第 7 步是否需要，看该 SoC 的 `libs_url/<chip>/cmake/ohos.cmake`：

- 如果它调用 `build_component()` 并检查 `TARGET_COMPONENT`，通常需要同步 `ram_component`。
- 如果它直接 `target_link_libraries(... libxxx.a ...)`，通常不需要改 `ram_component`。

## 验证建议

修改 demo 选择后，建议按以下顺序验证：

```bash
hb set -p nearlink_dk_3863
hb build
```

或：

```bash
hb set -p fbb_ws53
hb build
```

构建成功后，再检查固件 map 或 ELF 中是否出现 demo 符号，确认 demo 不只是被 GN 编译，而是真的被 SDK 固件链接进去。
