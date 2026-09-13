/**
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <algorithm>
#include <string>

#include "bluetooth_dialog.h"
#include "classic/classic_defs.h"
#include "dialog_pair.h"
#include "double_wrapper.h"
#include "int_wrapper.h"
#include "ipc_skeleton.h"
#include "json/json.h"
#include "json/writer.h"
#include "log.h"
#include "raw_address.h"
#include "refbase.h"
#include "string_wrapper.h"

namespace OHOS {
namespace bluetooth {
constexpr int32_t PINCODE_SIZE = 6;
bool DialogPair::RequestBluetoothPairDialog(const RawAddress& device, int reqType, int number)
{
    HILOGI("Pair dialog");
    const std::string abilityName = "BluetoothPairDialog";
    const std::string bundleName = "com.ohos.settings";
    std::string connectStr = DialogPair::BuildStartCommand(device, reqType, number);
    if (!BluetoothDialog::DialogConnectExtension(connectStr, bundleName, abilityName)) {
        HILOGE("failed to connect dialog.");
        return false;
    }
    return true;
}

std::string DialogPair::BuildStartCommand(const RawAddress& device, int reqType, int number)
{
    Json::Value root;
    Json::FastWriter writer;
    std::string uiType = "sysDialog/common";
    std::string pinNum = std::to_string(number);
    while (pinNum.size() < PINCODE_SIZE) {
        pinNum = "0" + pinNum;
    }
    root["ability.want.params.uiExtensionType"] = uiType;
    root["deviceId"] = device.GetAddress();
    root["pinCode"] = pinNum;
    root["pinType"] = reqType;

    HILOGI("DialogPair::BuildStartCommand address:, pinCode: %{public}d, pinType: : %{public}d ", number, reqType);
    std::string cmdData = writer.write(root);
    return cmdData;
}

} // namespace bluetooth
} // namespace OHOS