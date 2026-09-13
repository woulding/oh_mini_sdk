/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include <map>
#include <memory>
#include <string>
#include <vector>
#include "advanced_measure_format.h"
#include "advancedmeasureformat_fuzzer.h"
#include "number_format.h"

namespace OHOS {
namespace Global {
namespace I18n {
    void AdvancedMeasureFormatFuzzTest001(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags(1, input);
        std::map<std::string, std::string> configs;
        configs["style"] = "unit";
        configs["unit"] = "meter";
        std::shared_ptr<NumberFormat> numberFormat = std::make_shared<NumberFormat>(localeTags, configs);

        AdvancedMeasureFormatOptions options;
        options.unitUsage = UnitUsage::LENGTH_PERSON;
        AdvancedMeasureFormat formatter(numberFormat, options);
        formatter.FormatNumber(100.0);
        formatter.FormatNumber(1.0);
    }

    void AdvancedMeasureFormatFuzzTest002(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags(1, input);
        std::map<std::string, std::string> configs;
        std::shared_ptr<NumberFormat> numberFormat = std::make_shared<NumberFormat>(localeTags, configs);

        AdvancedMeasureFormatOptions options;
        options.unitUsage = UnitUsage::AREA_LAND_AGRICULT;
        AdvancedMeasureFormat formatter(numberFormat, options);
        formatter.FormatNumber(1000.0);
        formatter.FormatNumber(0.5);
    }

    void AdvancedMeasureFormatFuzzTest003(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags(1, input);
        std::map<std::string, std::string> configs;
        configs["style"] = "decimal";
        std::shared_ptr<NumberFormat> numberFormat = std::make_shared<NumberFormat>(localeTags, configs);

        UnitUsage unitUsages[] = {
            UnitUsage::LENGTH_RAINFALL,
            UnitUsage::LENGTH_SNOWFALL,
            UnitUsage::LENGTH_VEHICLE,
            UnitUsage::LENGTH_VISIBLTY
        };
        for (UnitUsage usage : unitUsages) {
            AdvancedMeasureFormatOptions options;
            options.unitUsage = usage;
            AdvancedMeasureFormat formatter(numberFormat, options);
            formatter.FormatNumber(50.0);
        }
    }

    void AdvancedMeasureFormatFuzzTest004(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags(1, input);
        std::map<std::string, std::string> configs;
        configs["style"] = "unit";
        configs["unit"] = "kilometer-per-hour";
        std::shared_ptr<NumberFormat> numberFormat = std::make_shared<NumberFormat>(localeTags, configs);

        AdvancedMeasureFormatOptions options;
        options.unitUsage = UnitUsage::SPEED_ROAD_TRAVEL;
        AdvancedMeasureFormat formatter(numberFormat, options);
        formatter.FormatNumber(60.0);
        formatter.FormatNumber(120.0);
        formatter.FormatNumber(0.0);
    }

    void AdvancedMeasureFormatFuzzTest005(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags(1, input);
        std::map<std::string, std::string> configs;
        std::shared_ptr<NumberFormat> numberFormat = std::make_shared<NumberFormat>(localeTags, configs);

        AdvancedMeasureFormatOptions options;
        options.unitUsage = UnitUsage::TEMPERATURE_WEATHER;
        AdvancedMeasureFormat formatter(numberFormat, options);
        formatter.FormatNumber(25.0);
        formatter.FormatNumber(-10.0);
        formatter.FormatNumber(100.0);
        formatter.FormatNumber(std::numeric_limits<double>::infinity());
        formatter.FormatNumber(std::numeric_limits<double>::quiet_NaN());
    }

    void AdvancedMeasureFormatFuzzTest006(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags(1, input);
        std::map<std::string, std::string> configs;
        std::shared_ptr<NumberFormat> numberFormat = std::make_shared<NumberFormat>(localeTags, configs);

        UnitUsage allUsages[] = {
            UnitUsage::AREA_LAND_AGRICULT,
            UnitUsage::AREA_LAND_COMMERCL,
            UnitUsage::AREA_LAND_RESIDNTL,
            UnitUsage::LENGTH_PERSON,
            UnitUsage::LENGTH_PERSON_SMALL,
            UnitUsage::LENGTH_RAINFALL,
            UnitUsage::LENGTH_ROAD,
            UnitUsage::LENGTH_ROAD_SMALL,
            UnitUsage::LENGTH_SNOWFALL,
            UnitUsage::LENGTH_VEHICLE,
            UnitUsage::LENGTH_VISIBLTY,
            UnitUsage::LENGTH_VISIBLTY_SMALL,
            UnitUsage::SPEED_ROAD_TRAVEL,
            UnitUsage::SPEED_WIND,
            UnitUsage::TEMPERATURE_PERSON,
            UnitUsage::TEMPERATURE_WEATHER,
            UnitUsage::VOLUME_VEHICLE_FUEL,
            UnitUsage::ELAPSED_TIME_SECOND,
            UnitUsage::SIZE_FILE_BYTE,
            UnitUsage::SIZE_SHORTFILE_BYTE
        };
        size_t size = provider.ConsumeIntegral<size_t>();
        for (UnitUsage usage : allUsages) {
            AdvancedMeasureFormatOptions options;
            options.unitUsage = usage;
            AdvancedMeasureFormat formatter(numberFormat, options);
            formatter.FormatNumber(static_cast<double>(size));
        }
    }

    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < 1) {
            return false;
        }

        FuzzedDataProvider provider(data, size);
        AdvancedMeasureFormatFuzzTest001(provider);
        AdvancedMeasureFormatFuzzTest002(provider);
        AdvancedMeasureFormatFuzzTest003(provider);
        AdvancedMeasureFormatFuzzTest004(provider);
        AdvancedMeasureFormatFuzzTest005(provider);
        AdvancedMeasureFormatFuzzTest006(provider);
        return true;
    }
}
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::Global::I18n::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}