/**
 * Copyright (C) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * UiTest / Hypium 通过 EntryAbility want.parameters.testTargetPage 导航时，
 * 跳过首页权限弹窗，避免遮挡控件；普通启动仍走正常授权流程。
 */
let skipBluetoothPermissionRequest: boolean = false;

export function setSkipBluetoothPermissionForAutomatedTest(value: boolean): void {
  skipBluetoothPermissionRequest = value;
}

export function shouldSkipBluetoothPermissionRequest(): boolean {
  return skipBluetoothPermissionRequest;
}
