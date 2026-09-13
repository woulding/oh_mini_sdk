/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_BLUETOOTH_STANDARD_SOCKET_SERVER_H
#define OHOS_BLUETOOTH_STANDARD_SOCKET_SERVER_H

#include <sys/socket.h>
#include <unistd.h>
#include "bluetooth_socket_stub.h"
#include "bt_uuid.h"
#include "bluetooth_raw_address.h"
#include "base_def.h"

namespace OHOS {
namespace Bluetooth {
class BluetoothSocketServer : public BluetoothSocketStub {
public:
    class SocketObserverList {
    public:
        struct SocketObserverApplication {
            SocketObserverApplication(int fd, const sptr<IRemoteObject> &remote) : fd(fd), remote(remote) {}

            int fd;
            wptr<IRemoteObject> remote;
        };
        class DeathRecipient : public IRemoteObject::DeathRecipient {
        public:
            explicit DeathRecipient(SocketObserverList &applications) : applications_(applications) {}
            ~DeathRecipient() = default;
            void OnRemoteDied(const wptr<IRemoteObject> &remote) override
            {
                applications_.OnRemoteDied(remote);
            }
        private:
            SocketObserverList &applications_;
        };

        SocketObserverList()
        {
            deathRecipient_ = new DeathRecipient(*this);
        }
        ~SocketObserverList() = default;
        void OnRemoteDied(const wptr<IRemoteObject> &remote)
        {
            std::lock_guard<std::mutex> lock(observerListLock_);
            auto iter = GetObserverApplication(remote);
            if (iter != observerList_.end()) {
                iter->remote->RemoveDeathRecipient(deathRecipient_);
                shutdown(iter->fd, SHUT_RD);
                shutdown(iter->fd, SHUT_WR);
                close(iter->fd);
                observerList_.erase(iter);
            }
        }

        void AddObserver(int fd, const sptr<IRemoteObject> &remote)
        {
            if (GetObserverApplication(remote) != observerList_.end()) {
                return;
            }
            SocketObserverApplication app(fd, remote);
            remote->AddDeathRecipient(deathRecipient_);
            observerList_.push_back(app);
        }

        void RemoveObserver(const sptr<IRemoteObject> &remote)
        {
            auto iter = GetObserverApplication(remote);
            if (iter != observerList_.end()) {
                iter->remote->RemoveDeathRecipient(deathRecipient_);
                observerList_.erase(iter);
            }
        }
    private:
        std::vector<SocketObserverApplication>::iterator GetObserverApplication(const wptr<IRemoteObject> &remote)
        {
            return std::find_if(observerList_.begin(), observerList_.end(),
                [remote](const auto &app) {return app.remote == remote; });
        }
    private:
        std::mutex observerListLock_;
        std::vector<SocketObserverApplication> observerList_;
        sptr<DeathRecipient> deathRecipient_;
    };
    BluetoothSocketServer() : socketObserverList_(std::make_unique<SocketObserverList>()) {}
    ~BluetoothSocketServer() {}

    int Connect(ConnectSocketParam &param, int &fd) override;
    int Listen(ListenSocketParam &param, int &fd) override;
    int DeregisterServerObserver(const sptr<IBluetoothServerSocketObserver> &observer) override;
    int RegisterClientObserver(const BluetoothRawAddress &addr, const bluetooth::Uuid uuid,
        const sptr<IBluetoothClientSocketObserver> &observer) override;
    int DeregisterClientObserver(const BluetoothRawAddress &addr, const bluetooth::Uuid uuid,
        const sptr<IBluetoothClientSocketObserver> &observer) override;
    int UpdateCocConnectionParams(const BluetoothSocketCocInfo &info) override;
    int IsAllowSocketConnect(int32_t socketType, const std::string &addr, bool &isAllowed) override;
private:
    std::unique_ptr<SocketObserverList> socketObserverList_;
};
}  // namespace Bluetooth
}  // namespace OHOS
#endif  // OHOS_BLUETOOTH_STANDARD_SOCKET_SERVER_H