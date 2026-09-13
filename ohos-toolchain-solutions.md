# OpenHarmony 多开发板工具链管理方案

> 目的：让 ohos_sdk / ohos_mini 在编译不同开发板时，明确选择正确的交叉工具链，避免全局 PATH 污染、同名编译器互相遮蔽，以及工具链版本和 ABI 不匹配。
>
> 当前结论：优先使用板级 board_toolchain_path 指定工具链；用工具链清单和校验脚本管理安装；用 Docker 固化 CI 和团队环境。
>
> 整理时间：2026-09-09，基于当前工作区源码检查。切换 OpenHarmony 分支后，应重新核对板级配置。

---

## 1. 快速结论

推荐采用三层结构：

1. **板级配置层**：在每块开发板的 config.gni 中填写 board_toolchain_path，让 GN/Ninja 直接使用指定工具链，不依赖当前 shell 的 PATH。
2. **工具链管理层**：维护工具链清单和安装/校验脚本，记录版本、目标三元组、ABI、sysroot、下载地址和 SHA256。
3. **环境复现层**：在 CI 或需要完全一致环境时使用固定版本的 Docker 镜像。

原方案中的“按产品激活脚本”仍有价值，但建议作为兼容旧配置的过渡方案，而不是主要正确性保障。

---

## 2. 当前问题和关键事实

### 2.1 两个源码仓库

| 仓库 | 路径 | 主要内容 |
|---|---|---|
| ohos_sdk | /home/woulding/ohos_sdk | 较完整的 OpenHarmony 源码，包含多种 SoC、QEMU 和厂商板卡 |
| ohos_mini | /home/woulding/ohos_mini | mini/small 系统及相应的板卡和 QEMU 目标 |

两个仓库内部可能存在不同版本的同名工具链。即使目录结构相同，也不能默认两个仓库的工具链版本、补丁和 sysroot 完全一致。

### 2.2 构建系统已经支持直接指定工具链目录

当前构建配置支持：

~~~gn
board_toolchain = "..."
board_toolchain_path = "..."
board_toolchain_prefix = "...-"
board_toolchain_type = "gcc"
~~~

build/config/BUILDCONFIG.gn 和 build/lite/config/BUILDCONFIG.gn 会将 board_toolchain_path 拼接到实际编译器命令前。

例如：

~~~gn
board_toolchain_path =
    "${ohos_root_path}/.toolchains/gcc-arm-none-eabi-10.3.1/bin"
board_toolchain_prefix = "arm-none-eabi-"
~~~

因此，当前不必通过全局 PATH 解决目标编译器选择问题。板级路径注入是现有构建系统支持的直接用法。

### 2.3 LiteOS-M 仍会探测工具链

kernel/liteos_m/BUILD.gn 中会执行类似：

~~~gn
exec_script("//build/lite/run_shell_cmd.py", [ "$cc -print-file-name=include" ])
~~~

如果板级配置没有指定 board_toolchain_path，编译器前缀就会依赖 PATH；指定路径后，生成命令会使用对应目录中的工具链。

### 2.4 当前已确认的工具链

WS63 工具链在两个仓库中都存在，典型路径为：

~~~text
device/soc/hisilicon/ws63v100/sdk/tools/bin/compiler/riscv/
  cc_riscv32_musl_100/cc_riscv32_musl/bin/
  cc_riscv32_musl_100/cc_riscv32_musl_fp/bin/
~~~

两个目录都包含 riscv32-linux-musl-gcc，但不是同一套编译选项：

- cc_riscv32_musl：普通 RISC-V 配置；
- cc_riscv32_musl_fp：带浮点 ABI 的配置。

当前 prebuilts/gcc/linux-x86 中可以看到：

~~~text
arm/gcc-linaro-7.5.0-arm-linux-gnueabi
aarch64/gcc-linaro-7.5.0-2019.12-x86_64_aarch64-linux-gnu
~~~

它们不能替代：

~~~text
arm-none-eabi-gcc
riscv32-unknown-elf-gcc
csky-elfabiv2-gcc
xtensa-esp32-elf-gcc
~~~

特别是：

- arm-linux-gnueabi 是 Linux 目标工具链；
- arm-none-eabi 是裸机工具链，适合 Cortex-M；
- riscv32-linux-musl 与 riscv32-unknown-elf 的 C 库、sysroot 和 ABI 不同。

---

## 3. 工具链选择原则

工具链不能只按 CPU 架构或命令名选择，应同时匹配：

1. 目标板；
2. 编译器前缀；
3. ABI；
4. C 库和 sysroot；
5. 编译参数；
6. 链接脚本和启动文件；
7. 工具链版本及厂商补丁。

| 目标 | 编译器前缀 | 典型 ABI/架构 | 工具链选择 |
|---|---|---|---|
| nearlink DK 3863 / WS63 | riscv32-linux-musl- | rv32imfc、ilp32f | WS63 cc_riscv32_musl_fp |
| nearlink DK 3853 | riscv32-linux-musl- | rv32imc、ilp32 | WS63 非 FP 版本或厂商对应版本 |
| QEMU arm_mps2_an386 | arm-none-eabi- | Cortex-M4、裸机 | ARM GNU Embedded 工具链 |
| QEMU riscv32_virt | riscv32-unknown-elf- | rv32imac | RISC-V 裸机工具链 |
| Linux ARM | arm-linux-gnueabi- | Linux 用户态 | ARM Linux GNU 工具链 |
| Linux ARM64 | aarch64-linux-gnu- | Linux 用户态 | AArch64 Linux GNU 工具链 |

**不能把 WS63 的 riscv32-linux-musl 直接当作所有 QEMU RISC-V 目标的工具链。**

---

## 4. 首选方案：板级 board_toolchain_path

### 4.1 配置位置和模板

通常在以下文件中配置：

~~~text
device/.../<board>/liteos_m/config.gni
device/.../<board>/liteos_a/config.gni
~~~

模板：

~~~gn
board_toolchain = "工具链名称"
board_toolchain_path = "工具链 bin 目录"
board_toolchain_prefix = "编译器前缀"
board_toolchain_type = "gcc"
~~~

board_toolchain_path 必须指向包含 gcc、g++、ar、objcopy、objdump、strip 等命令的 bin 目录，而不是上一级目录。

外部工具链建议放在仓库根目录的 .toolchains。二进制不提交到 Git，只提交安装脚本、版本清单和 SHA256。

### 4.2 nearlink DK 3863 / WS63

该板使用 riscv32-linux-musl-，并配置 rv32imfc 和 -mabi=ilp32f，应选择 WS63 的 FP 版本：

~~~gn
board_toolchain = "riscv32-linux-musl"
board_toolchain_path =
    "${ohos_root_path}/device/soc/hisilicon/ws63v100/sdk/tools/bin/compiler/riscv/cc_riscv32_musl_100/cc_riscv32_musl_fp/bin"
board_toolchain_prefix = "riscv32-linux-musl-"
board_toolchain_type = "gcc"
~~~

nearlink DK 3853 的 rv32imc / ilp32 配置应使用非 FP 版本或厂商明确提供的对应版本。

### 4.3 QEMU ARM

arm_mps2_an386 使用 Cortex-M4 裸机工具链：

~~~gn
board_toolchain = "arm-none-eabi-gcc"
board_toolchain_path =
    "${ohos_root_path}/.toolchains/gcc-arm-none-eabi-10.3.1/bin"
board_toolchain_prefix = "arm-none-eabi-"
board_toolchain_type = "gcc"
~~~

不能使用现有的 arm-linux-gnueabi，因为它是 Linux 目标工具链，不是裸机 newlib 工具链。

### 4.4 QEMU RISC-V

如果目标板配置为：

~~~gn
board_toolchain = "riscv32-unknown-elf"
board_toolchain_prefix = "riscv32-unknown-elf-"
~~~

就必须准备相同前缀的 RISC-V 裸机工具链：

~~~gn
board_toolchain_path =
    "${ohos_root_path}/.toolchains/riscv32-unknown-elf-<version>/bin"
~~~

不能直接复用 WS63 的 riscv32-linux-musl-，除非已确认 ABI、sysroot、C 库和链接脚本兼容。

### 4.5 修改后重新生成

GN/Ninja 会把编译器命令写入 out 目录中的生成文件。修改 board_toolchain_path、工具链前缀或 ABI 后执行：

~~~bash
hb build -f
~~~

若仍调用旧编译器，只删除当前目标对应的 out/<board>/<product> 目录后重新构建，不要删除其他产品的输出目录。

---

## 5. 工具链清单、安装和校验

板级配置负责“编译时使用哪一个目录”，工具链清单负责下载、安装和验证。建议维护 tools/toolchains.conf：

~~~text
# id|path|prefix|machine|version
ws63_riscv32|device/soc/hisilicon/ws63v100/sdk/tools/bin/compiler/riscv/cc_riscv32_musl_100/cc_riscv32_musl/bin|riscv32-linux-musl-|riscv32-linux-musl|gcc-7.3.0
ws63_riscv32_fp|device/soc/hisilicon/ws63v100/sdk/tools/bin/compiler/riscv/cc_riscv32_musl_100/cc_riscv32_musl_fp/bin|riscv32-linux-musl-|riscv32-linux-musl|gcc-7.3.0
arm_none_eabi_10_3|.toolchains/gcc-arm-none-eabi-10.3.1/bin|arm-none-eabi-|arm-none-eabi|10.3.1
riscv32_unknown_elf|.toolchains/riscv32-unknown-elf-<version>/bin|riscv32-unknown-elf-|riscv32-unknown-elf|<version>
~~~

外部下载工具链还应记录 download_url、sha256、许可证和源代码版本。不要只记录目录名。

### 5.1 最低校验项

~~~bash
<bin>/gcc --version
<bin>/gcc -dumpmachine
<bin>/gcc -print-file-name=include
test -x <bin>/gcc
test -x <bin>/ar
test -x <bin>/objcopy
test -x <bin>/objdump
test -x <bin>/strip
~~~

还要确认文件后缀和宿主机匹配，不能把 *_win/*.exe 当作 Linux 工具链使用。

### 5.2 建议的诊断命令

后续可以提供：

~~~bash
tc list
tc doctor nearlink_dk_3863
tc doctor arm_mps2_an386
tc version ws63_riscv32_fp
tc install arm_none_eabi_10_3
~~~

脚本可以负责安装和诊断，但不应通过修改全局 ~/.bashrc 来决定目标板使用哪一个编译器。

---

## 6. PATH 激活脚本：兼容方案

如果暂时不能修改板级 config.gni，可以保留：

~~~bash
tc use nearlink_dk_3863
hb build -f
tc reset
~~~

实现时需要注意：

1. tc 必须是 shell 函数，普通可执行文件无法修改调用它的父 shell 的 PATH；
2. 切换 PATH 后执行 hash -r，避免 Bash 使用旧命令缓存；
3. 只删除脚本自己注入的 PATH 段，不覆盖用户原始 PATH；
4. 记录并恢复原始 PATH，不要只做简单字符串替换；
5. 检查工具链版本和 -dumpmachine，不能只检查命令是否存在；
6. ~/.bashrc 中不要写死 /home/woulding/ohos_sdk；
7. 两个仓库要明确选择仓库内工具链，避免同名编译器互相覆盖。

更稳妥的临时方式是：

~~~bash
env PATH="<toolchain-bin>:$PATH" hb build -f
~~~

---

## 7. direnv 的适用范围

direnv 适合加载仓库级公共工具，例如 Python、GN、Ninja、Node 或公共 OpenHarmony 工具：

~~~bash
eval "$(direnv hook bash)"
~~~

不建议用仓库根目录的单个 .envrc 固定目标编译器，因为同一仓库可能同时存在 WS63、QEMU ARM、QEMU RISC-V 和 Linux ARM/ARM64 目标。direnv 不能自动知道当前 hb set 选择了哪个产品，除非另外编写产品级逻辑。

因此 direnv 只能作为便利层，不能取代板级工具链配置。

---

## 8. Docker 方案

Docker 适合：

- CI 编译和回归验证；
- 团队统一工具链版本；
- 新机器快速搭建环境；
- 排查宿主机环境污染问题。

当前仓库的 Docker 资料中包含 Ubuntu 18.04、gcc-arm-none-eabi 和 RISC-V 工具链安装逻辑，可以作为参考，但不建议原样作为长期标准：

- 基础系统和依赖版本较旧；
- 下载地址和工具链版本可能已经过时；
- 镜像中的通用 RISC-V 工具链不一定等于 WS63 专用版本；
- 构建过程依赖外部网络；
- 需要明确工具链许可证和 SHA256。

建议为每个 OpenHarmony 分支固定镜像标签，并在镜像内保留 GN/Ninja、对应版本 Clang、WS63 工具链、arm-none-eabi 工具链、Python/hb 依赖、QEMU（如需要）以及工具链校验值。

Docker 中也建议使用板级 board_toolchain_path，而不是把所有交叉编译器放进 PATH 后依赖顺序。

---

## 9. 常见问题排查

### 9.1 command not found

按顺序检查：

~~~bash
grep -n 'board_toolchain' device/.../<board>/liteos_m/config.gni
find <toolchain-bin> -maxdepth 1 -type f -name '*gcc*'
<toolchain-bin>/<prefix>gcc -dumpmachine
hb build -f
~~~

不要只在当前 shell 中临时追加一个不确定的 PATH，否则下一次重新生成构建目录时问题还会复现。

### 9.2 编译器找到了，但出现头文件或链接错误

这通常不是 PATH 问题，而是工具链不匹配。检查：

~~~bash
<compiler> -dumpmachine
<compiler> -print-file-name=include
<compiler> -print-sysroot
~~~

同时检查板级 ABI 参数，例如 -mabi=ilp32、-mabi=ilp32f、-mcpu=cortex-m4 和 -mthumb。

### 9.3 修改配置后仍调用旧编译器

原因通常是 out 中的 GN/Ninja 文件没有重新生成。执行 hb build -f；如果仍无效，再删除当前目标对应的输出目录并重新构建。

### 9.4 同名 riscv32-linux-musl-gcc 选错版本

不要通过调整 PATH 顺序解决。应在板级 config.gni 中明确填写具体目录，区分：

~~~text
cc_riscv32_musl/bin
cc_riscv32_musl_fp/bin
~~~

然后重新生成 out。

---

## 10. 新增开发板操作清单

1. 找到该板的 config.gni；
2. 确认 board_toolchain、board_toolchain_prefix 和 board_toolchain_type；
3. 确认 ABI、CPU、sysroot 和链接脚本；
4. 在工具链清单中新增记录；
5. 安装工具链并校验 SHA256；
6. 设置 board_toolchain_path；
7. 检查 gcc -dumpmachine 和 -print-file-name=include；
8. 使用 hb build -f 重新生成；
9. 保存编译器版本和构建结果；
10. 如果用于 CI，再把同一版本加入 Docker 镜像。

---

## 11. 最终推荐

本地开发：

~~~text
板级 config.gni
    ↓
board_toolchain_path
    ↓
指定版本的工具链 bin 目录
    ↓
hb build -f
~~~

团队和 CI：

~~~text
工具链清单 + SHA256
    ↓
固定 Docker 镜像
    ↓
板级 board_toolchain_path
    ↓
统一编译结果
~~~

方案优先级：

| 优先级 | 方案 | 用途 |
|---|---|---|
| 1 | board_toolchain_path | 解决实际编译时的工具链选择和同名冲突 |
| 2 | 工具链清单/安装校验脚本 | 解决版本、路径、下载和诊断问题 |
| 3 | 固定 Docker 镜像 | 解决 CI、团队协作和环境复现问题 |
| 4 | PATH 激活脚本 | 兼容暂时不能修改板级配置的旧目标 |
| 5 | direnv | 加载公共构建工具的便利层 |

最重要的原则是：**每个目标板必须有唯一、明确、可验证的工具链路径；不要依赖 PATH 顺序，也不要因为命令名相同就跨目标复用工具链。**

---

## 附：本方案的调查依据

- ohos_sdk/out/nearlink_dk_3863/nearlink_dk_3863/error.log：riscv32-linux-musl-gcc: command not found；
- QEMU ARM 报错：run_shell_cmd.py arm-none-eabi-gcc ... Returned 127；
- kernel/liteos_m/BUILD.gn:59-67：通过 $cc -print-file-name=include 探测编译器；
- ohos_mini/build/config/BUILDCONFIG.gn:932-939 和 build/lite/config/BUILDCONFIG.gn:71-78：支持 board_toolchain_path；
- nearlink DK 3863 配置：device/board/hihope/nearlink_dk_3863/liteos_m/config.gni；
- QEMU ARM 配置：device/qemu/arm_mps2_an386/liteos_m/config.gni；
- QEMU RISC-V 配置：device/qemu/riscv32_virt/liteos_m/config.gni；
- WS63 Docker 资料提供了 gcc-arm-none-eabi 和 RISC-V 工具链安装参考，但版本和基础镜像需要重新验证。

