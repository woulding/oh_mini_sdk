/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#include "bluetooth_socket_observer_proxy.h"
#include "bluetooth_log.h"

namespace OHOS {
namespace Bluetooth {
void BluetoothClientSocketObserverProxy::OnConnectionStateChanged(const CallbackParam &callbackParam)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    if (!data.WriteInterfaceToken(BluetoothClientSocketObserverProxy::GetDescriptor())) {
        HILOGE("WriteInterfaceToken error");
        return;
    }
    data.WriteParcelable(&callbackParam.dev);

    BluetoothUuid btUuid(callbackParam.uuid);
    data.WriteParcelable(&btUuid);
    data.WriteInt32(callbackParam.status);
    data.WriteInt32(callbackParam.result);
    data.WriteInt32(callbackParam.type);
    data.WriteInt32(callbackParam.psm);
    int32_t st = Remote()->SendRequest(static_cast<uint32_t>(BT_SOCKET_OBSERVER_CONNECTION_STATE_CHANGED),
        data, reply, option);
    if (st != ERR_NONE) {
        HILOGE("OnConnectionStateChanged failed, error code is %{public}d", st);
        return;
    }

    return;
}
}  // namespace Bluetooth
}  // namespace OHOS