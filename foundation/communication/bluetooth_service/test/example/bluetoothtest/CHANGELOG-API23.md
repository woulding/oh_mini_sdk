# bluetoothtest：API 23 适配变更说明

## API 26 当前状态（已恢复）

工程已使用 **`build-profile.json5`：`compileSdkVersion` / `compatibleSdkVersion` / `targetSdkVersion` 均为 26**。下列在 API 23 中被裁剪或占位的能力，**已从提交 `8d9dc4c`（API 23 之前基线）恢复源码**，并在当前 OpenHarmony 6.x / API 26 工具链下 **通过 `assembleHap` 编译**：

| 能力 | 恢复方式概要 |
|------|----------------|
| **OPP** | `btProfileModel` 重新接入 `@kit.ConnectivityKit` 的 `opp.createOppServerProfile()`；`oppSendScenarioTest` / `oppRecvScenarioTest` 恢复发送、接收与事件；`a2dpSinkProfileInterface` 恢复 OPP 相关导出。 |
| **截屏** | `mainPageTitle.ets`、`pageTitle.ets` 恢复 `@ohos.screenshot` + `MediaUtils.savePicture`。 |
| **取消配对** | 两处 `deviceFound.ets` 恢复 `bluetooth.cancelPairedDevice`。 |
| **权限** | `entry/src/main/module.json5` 恢复 `CAPTURE_SCREEN`、`WRITE_IMAGEVIDEO`、`MANAGE_BLUETOOTH` 等声明；`homePage.ets` 恢复含截屏等运行时申请列表。 |

**说明**：真机/开发板需系统与签名策略支持上述权限与 Profile；若安装阶段权限预授权失败，仍需按环境调整 `module.json5` 或换调试证书（与此前 API 23 设备侧问题相同）。

---

本文档下文仍保留 **API 23 适配当时** 的修改记录，便于对照历史。

## 构建配置

| 文件 | 变更 |
|------|------|
| `build-profile.json5` | `compileSdkVersion` / `compatibleSdkVersion` / `targetSdkVersion` 设为 **23**（原为 26）。恢复 API 26 时改回 **26** 并全量编译验证。 |

## 蓝牙 Profile 与 Manager（`entry/src/main/ets/MainAbility/model/`）

### `btProfileModel.ets`

- 移除对 `@kit.ConnectivityKit` / `opp` 的依赖。
- `profiles` 仅保留：A2DP Source、HFP Gateway、HID Host、PAN；**`PROFILE_OPP` 槽位为 `null`**，不再调用 `opp.createOppServerProfile()`。
- **恢复 API 26**：若 OPP 类型与 `createOppServerProfile()` 在目标 SDK 中可用，可恢复 OPP 初始化，并同步恢复所有引用 OPP 的页面与接口。

### `a2dpSinkProfileInterface.ets`

- **A2DP / HFP**：仍使用 `@ohos.bluetooth` 的 `connect` / `disconnect`、`getConnectionDevices()`、`getDeviceState()`。
- **HID / PAN**：当前 SDK 中 `hid.HidHostProfile` / `pan.PanProfile` 声明上无 `connect`/`disconnect`，改为 **Toast 提示在系统蓝牙中连接/断开**；列表与状态使用 `getConnectedDevices()`、`getConnectionState()`（与旧版 `getConnectionDevices`/`getDeviceState` 命名不同）。
- OPP 相关导出函数改为 **占位**（Toast 说明 API 23 未启用 OPP）。

**恢复 API 26**：若 HID/PAN 在更高 API 上重新声明了带地址的 `connect`/`disconnect`，可按 profile 类型恢复调用；OPP 相关函数可恢复为真实实现。

### `a2dpSinkProfileManagerInterface.ets`

- `connect` / `disconnect` 仅对 **A2DP Source、HandsFree Audio Gateway** 调用；**HID / PAN** 分支 Toast 提示，不调用连接 API。
- `getConnectionDevices` / `getDeviceState` 通过 **`btm.BaseProfile`** 统一调用（与 `btm` 声明一致）。

**恢复 API 26**：若 Manager 侧 HID/PAN 支持连接/断开，可补全分支逻辑。

## OPP 场景页（占位）

| 文件 | 变更 |
|------|------|
| `entry/.../pages/subScenarioTest/oppSendScenarioTest.ets` | 移除 `@kit.ConnectivityKit` 的 `opp`、`OppServerProfile`、`sendFile` 等；保留列表与 UI 骨架，发送为 **占位按钮 + 日志/Toast**。 |
| `entry/.../pages/subScenarioTest/oppRecvScenarioTest.ets` | 同上，接收流程、对话框与 `setIncomingFileConfirmation` 等已移除，改为 **占位说明**。 |

**恢复 API 26**：从版本管理历史或备份中恢复完整 OPP 逻辑，并确认 `ConnectivityKit` 与工程 `build-profile`、依赖一致。

## 截屏组件

| 文件 | 变更 |
|------|------|
| `entry/.../Component/mainPageTitle.ets` | 移除 `@ohos.screenshot` 的 `ScreenshotOptions`、`screenshot.save` 与 `MediaUtils.savePicture`；截屏按钮改为 **Logger + Toast**（说明 API 23 未接入截屏保存）。 |
| `entry/.../Component/pageTitle.ets` | 同上。 |

**恢复 API 26**：若目标 SDK 中 `screenshot` 模块 API 与类型完整，可恢复 `save`/`capture` 等与 `MediaUtils` 的集成（以当时 SDK 声明为准）。

## 取消配对（deviceFound）

| 文件 | 变更 |
|------|------|
| `entry/.../pages/subManualApiTest/subBrTest/deviceFound.ets` | 原 `bluetooth.cancelPairedDevice` / 后续尝试的 `bluetoothManager.cancelPairedDevice` 在当前使用的类型声明中不可用；点击「取消」改为 **Toast**，引导用户到 **系统设置 › 蓝牙** 操作。 |
| `entry/.../pages/subManualApiTestManager/subBrTestManager/deviceFound.ets` | 同上。 |

**恢复 API 26**：查阅目标 SDK 中 `@ohos.bluetooth` / `@ohos.bluetooth.connection` / `@ohos.bluetoothManager` 是否提供取消配对或解除绑定 API，再恢复调用并处理返回值/异常。

---

## 升级回 API 26 时的建议步骤

1. 在 `build-profile.json5`（及必要时 `entry/build-profile.json5`、`AppScope/app.json5`）中将 SDK 版本改回 **26**，与团队使用的 CLI/SDK 对齐。
2. 执行全量编译，按报错逐项恢复：优先 **OPP**、**截屏**、**取消配对**，再核对 **HID/PAN connect/disconnect** 是否可恢复。
3. 恢复后删除或缩减本文档中的占位说明，避免与真实行为不一致。

---

*文档随 API 23 适配提交添加；最后更新与 `build-profile.json5` 中 targetSdk 一致时可在此行注明日期。*
