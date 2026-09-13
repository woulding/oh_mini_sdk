/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "bluetooth_ble_filter_matcher.h"

namespace OHOS {
namespace Bluetooth {
using namespace OHOS::bluetooth;
MatchResult BluetoothBleFilterMatcher::MatchesScanFilters(
    const std::vector<bluetooth::BleScanFilterImpl> &bleScanFilters,
    const BluetoothBleScanResult &result)
{
    // no filters equals all result pass
    if (bleScanFilters.empty()) {
        return MatchResult::MATCH;
    }

    for (const auto &filter : bleScanFilters) {
        if (MatchesScanFilter(filter, result) == MatchResult::MATCH) {
            return MatchResult::MATCH;
        }
    }
    return MatchResult::MISMATCH;
}

MatchResult BluetoothBleFilterMatcher::MatchesScanFilter(
    const bluetooth::BleScanFilterImpl &filter,
    const BluetoothBleScanResult &result)
{
    if (MatchesAddress(filter, result) == MatchResult::MISMATCH) {
        return MatchResult::MISMATCH;
    }

    if (MatchesName(filter, result) == MatchResult::MISMATCH) {
        return MatchResult::MISMATCH;
    }

    if (MatchesServiceUuids(filter, result) == MatchResult::MISMATCH) {
        return MatchResult::MISMATCH;
    }

    if (MatchesManufacturerDatas(filter, result) == MatchResult::MISMATCH) {
        return MatchResult::MISMATCH;
    }

    if (MatchesServiceDatas(filter, result) == MatchResult::MISMATCH) {
        return MatchResult::MISMATCH;
    }

    return MatchResult::MATCH;
}

MatchResult BluetoothBleFilterMatcher::MatchesAddress(const bluetooth::BleScanFilterImpl &filter,
    const BluetoothBleScanResult &result)
{
    std::string filterAddress = filter.GetDeviceId();
    // no fiilter equals all result pass
    if (filterAddress.empty()) {
        return MatchResult::MATCH;
    }

    std::string resultAdderss = result.GetPeripheralDevice().GetAddress();
    if (resultAdderss.empty()) {
        return MatchResult::MISMATCH;
    }

    return filterAddress == resultAdderss ? MatchResult::MATCH : MatchResult::MISMATCH;
}

MatchResult BluetoothBleFilterMatcher::MatchesName(const bluetooth::BleScanFilterImpl &filter,
    const BluetoothBleScanResult &result)
{
    std::string filterName = filter.GetName();
    // no fiilter equals all result pass
    if (filterName.empty()) {
        return MatchResult::MATCH;
    }

    std::string resultName = result.GetName();
    if (resultName.empty()) {
        return MatchResult::MISMATCH;
    }

    return filterName == resultName ? MatchResult::MATCH : MatchResult::MISMATCH;
}

MatchResult BluetoothBleFilterMatcher::MatchesServiceUuids(const bluetooth::BleScanFilterImpl &filter,
    const BluetoothBleScanResult &result)
{
    // no fiilter equals all result pass
    if (!filter.HasServiceUuid()) {
        return MatchResult::MATCH;
    }
    bluetooth::Uuid filterUuid = filter.GetServiceUuid();

    std::vector<bluetooth::Uuid> resultUuids = result.GetServiceUuids();
    // if filter needs but result is empty means fail
    if (resultUuids.empty()) {
        return MatchResult::MISMATCH;
    }

    for (auto &uuid : resultUuids) {
        // mask means filter = result
        if (!filter.HasServiceUuidMask()) {
            if (filterUuid.operator == (uuid)) {
                return MatchResult::MATCH;
            }
        }

        // mask means filter&&mask = result&&mask
        if (filter.HasServiceUuidMask()) {
            bluetooth::Uuid uuidMask = filter.GetServiceUuidMask();
            if (MatchesUuidWithMask(filterUuid, uuid, uuidMask)) {
            return MatchResult::MATCH;
            }
        }
    }
    return MatchResult::MISMATCH;
}

MatchResult BluetoothBleFilterMatcher::MatchesManufacturerDatas(const bluetooth::BleScanFilterImpl &filter,
    const BluetoothBleScanResult &result)
{
    uint16_t filterManufacturerId = filter.GetManufacturerId();
    std::vector<uint8_t> filterData = filter.GetManufactureData();
    std::vector<uint8_t> fiilterDataMask = filter.GetManufactureDataMask();
    // no fiilter equals all result pass
    if (filterData.size() == 0) {
        return MatchResult::MATCH;
    }
    // if filter needs but result is empty means fail
    if (result.GetManufacturerData().empty()) {
        return MatchResult::MISMATCH;
    }

    for (auto &resultManufacturerData : result.GetManufacturerData()) {
        // if ManufacturerId same then check data
        if (filterManufacturerId == resultManufacturerData.first) {
            bool result = MatchesData(filterData, resultManufacturerData.second, fiilterDataMask);
            return result ? MatchResult::MATCH : MatchResult::MISMATCH;
        }
    }
    return MatchResult::MISMATCH;
}

MatchResult BluetoothBleFilterMatcher::MatchesServiceDatas(const bluetooth::BleScanFilterImpl &filter,
    const BluetoothBleScanResult &result)
{
    std::vector<uint8_t> filterData = filter.GetServiceData();
    std::vector<uint8_t> dataMask = filter.GetServiceDataMask();
    // no Filter equals all result pass
    if (filterData.size() == 0) {
        return MatchResult::MATCH;
    }
    // if filter needs but result is empty means fail
    if (result.GetServiceData().empty()) {
        return MatchResult::MISMATCH;
    }
    for (auto &serviceData : result.GetServiceData()) {
        std::string resultData = ParseServiceDataUUidToString(serviceData.first, serviceData.second);
        if (MatchesData(filterData, resultData, dataMask)) {
            return MatchResult::MATCH;
        }
    }
    return MatchResult::MISMATCH;
}

bool BluetoothBleFilterMatcher::MatchesUuidWithMask(bluetooth::Uuid filterUuid,
    bluetooth::Uuid uuid, bluetooth::Uuid uuidMask)
{
    HILOGI("enter");
    uint8_t uuid128[bluetooth::Uuid::UUID128_BYTES_TYPE];
    uint8_t uuidMask128[bluetooth::Uuid::UUID128_BYTES_TYPE];
    uint8_t resultUuid128[bluetooth::Uuid::UUID128_BYTES_TYPE];
    if (!filterUuid.ConvertToBytesLE(uuid128)) {
        HILOGE("Convert filter uuid faild.");
        return false;
    }
    if (!uuidMask.ConvertToBytesLE(uuidMask128)) {
        HILOGE("Convert uuid mask faild.");
        return false;
    }
    if (!uuid.ConvertToBytesLE(resultUuid128)) {
        HILOGE("Convert result uuid faild.");
        return false;
    }
    size_t maskLength = sizeof(uuidMask128);
    if (maskLength <= 0) {
        return false;
    }

    for (size_t i = 0; i < maskLength; i++) {
        if ((uuid128[i] & uuidMask128[i]) != (resultUuid128[i] & uuidMask128[i])) {
            return false;
        }
    }

    return true;
}

std::string BluetoothBleFilterMatcher::ParseServiceDataUUidToString(bluetooth::Uuid uuid, std::string data)
{
    std::string tmpServcieData;
    int uuidType = uuid.GetUuidType();
    switch (uuidType) {
        case bluetooth::Uuid::UUID16_BYTES_TYPE: {
            uint16_t uuid16 = uuid.ConvertTo16Bits();
            tmpServcieData = std::string(reinterpret_cast<char *>(&uuid16), BLE_UUID_LEN_16);
            break;
        }
        case bluetooth::Uuid::UUID32_BYTES_TYPE: {
            uint32_t uuid32 = uuid.ConvertTo32Bits();
            tmpServcieData = std::string(reinterpret_cast<char *>(&uuid32), BLE_UUID_LEN_32);
            break;
        }
        case bluetooth::Uuid::UUID128_BYTES_TYPE: {
            uint8_t uuid128[bluetooth::Uuid::UUID128_BYTES_TYPE];
            if (!uuid.ConvertToBytesLE(uuid128)) {
                HILOGE("Convert filter uuid faild.");
            }
            tmpServcieData = std::string(reinterpret_cast<char *>(&uuid128), BLE_UUID_LEN_128);
            break;
        }
        default:
            break;
    }
    return tmpServcieData + data;
}

bool BluetoothBleFilterMatcher::MatchesData(std::vector<uint8_t> fData,
    std::string rData, std::vector<uint8_t> dataMask)
{
    if (rData.empty()) {
        return false;
    }

    size_t length = fData.size();
    std::vector<uint8_t> vec(rData.begin(), rData.end());
    if (vec.size() < length) {
        return false;
    }

    if (dataMask.empty() || dataMask.size() != length) {
        for (size_t i = 0; i < length; i++) {
            if (fData[i] != vec[i]) {
                return false;
            }
        }
        return true;
    }
    for (size_t i = 0; i < length; i++) {
        if ((fData[i] & dataMask[i]) != (vec[i] & dataMask[i])) {
            return false;
        }
    }
    return true;
}
}  // namespace Bluetooth
}  // namespace OHOS