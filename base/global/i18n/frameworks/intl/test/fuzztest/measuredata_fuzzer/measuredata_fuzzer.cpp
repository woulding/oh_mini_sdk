/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except", "in compliance with the License.
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
#include <string>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>
#include "measure_data.h"
#include "measuredata_fuzzer.h"

namespace OHOS {
namespace Global {
namespace I18n {

    void MeasureDataFuzzTest001(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        GetMask(input);
    }

    void MeasureDataFuzzTest002(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> units;
        units.push_back(input);
        GetDefaultPreferredUnit(input, input, units);
    }

    void MeasureDataFuzzTest003(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> units;
        units.push_back("kilometer");
        units.push_back("meter");
        GetFallbackPreferredUnit(input, input, units);
    }

    void MeasureDataFuzzTest004(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> units;
        units.push_back("liter");
        units.push_back("gallon");
        GetRestPreferredUnit(input, input, units);
    }

    void MeasureDataFuzzTest005(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> units;
        units.push_back(input);
        GetPreferredUnit(input, input, units);
    }

    void MeasureDataFuzzTest006(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        ComputeSIPrefixValue(input);
    }

    void MeasureDataFuzzTest007(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        double number = provider.ConsumeFloatingPoint<double>();
        std::vector<double> factors;
        factors.push_back(number);
        factors.push_back(number * 2);
        ComputeFactorValue(input, input, factors);
    }

    void MeasureDataFuzzTest008(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        double number = provider.ConsumeFloatingPoint<double>();
        std::vector<double> factors;
        factors.push_back(number);
        factors.push_back(number);
        ComputePowerValue(input, input, factors);
    }

    void MeasureDataFuzzTest009(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        double number = provider.ConsumeFloatingPoint<double>();
        std::vector<double> factors;
        factors.push_back(number);
        factors.push_back(1.0);
        ComputeValue(input, input, factors);
    }

    void MeasureDataFuzzTest010(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        double number = provider.ConsumeFloatingPoint<double>();
        ConvertByte(number, input);
    }

    void MeasureDataFuzzTest011(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        double number = provider.ConsumeFloatingPoint<double>();
        ConvertDate(number, input);
    }

    void MeasureDataFuzzTest012(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        double number = provider.ConsumeFloatingPoint<double>();
        Convert(number, input, input, input, input);
    }

    void MeasureDataFuzzTest013(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> units;
        units.push_back("kilometer");
        units.push_back("meter");
        units.push_back("centimeter");
        GetDefaultPreferredUnit(input, input, units);
        GetDefaultPreferredUnit("US", "length", units);
        GetDefaultPreferredUnit("CN", "length", units);
        GetDefaultPreferredUnit("GB", "length", units);
    }

    void MeasureDataFuzzTest014(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> units;
        units.push_back("kilogram");
        units.push_back("gram");
        GetFallbackPreferredUnit("US", "weight", units);
        GetFallbackPreferredUnit("CN", "weight", units);
    }

    void MeasureDataFuzzTest015(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> units;
        units.push_back("celsius");
        units.push_back("fahrenheit");
        GetPreferredUnit("US", "temperature", units);
        GetPreferredUnit("CN", "temperature", units);
    }

    void MeasureDataFuzzTest016(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        ComputeSIPrefixValue(input);
        ComputeSIPrefixValue("kilo");
        ComputeSIPrefixValue("mega");
        ComputeSIPrefixValue("giga");
        ComputeSIPrefixValue("milli");
        ComputeSIPrefixValue("micro");
    }

    void MeasureDataFuzzTest017(FuzzedDataProvider& provider)
    {
        double number = provider.ConsumeFloatingPoint<double>();
        std::string input = provider.ConsumeRandomLengthString();
        ConvertByte(number, input);
        number = 1024.0;
        input = "byte";
        ConvertByte(number, input);
        input = "kilobyte";
        ConvertByte(number, input);
        input = "megabyte";
        ConvertByte(number, input);
    }

    void MeasureDataFuzzTest018(FuzzedDataProvider& provider)
    {
        double number = provider.ConsumeFloatingPoint<double>();
        std::string input = provider.ConsumeRandomLengthString();
        ConvertDate(number, input);
        number = 365.0;
        input = "day";
        ConvertDate(number, input);
        input = "week";
        ConvertDate(number, input);
        input = "month";
        ConvertDate(number, input);
        input = "year";
        ConvertDate(number, input);
    }

    void MeasureDataFuzzTest019(FuzzedDataProvider& provider)
    {
        double value = provider.ConsumeFloatingPoint<double>();
        std::string input = provider.ConsumeRandomLengthString();
        Convert(value, input, input, input, input);
        value = 1000.0;
        Convert(value, "meter", "metric", "kilometer", "metric");
        Convert(value, "kilometer", "metric", "mile", "imperial");
        Convert(value, "liter", "metric", "gallon", "imperial");
    }

    void MeasureDataFuzzTest020(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        GetMask(input);
        GetMask("US");
        GetMask("CN");
        GetMask("GB");
        GetMask("JP");
    }

    void MeasureDataFuzzTest021(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> units;
        units.push_back(input);
        units.push_back("meter");
        units.push_back("kilometer");
        GetPreferredUnit(input, "road", units);
        GetPreferredUnit(input, "person-height", units);
    }

    void MeasureDataFuzzTest022(FuzzedDataProvider& provider)
    {
        double number = provider.ConsumeFloatingPoint<double>();
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<double> factors;
        factors.push_back(number);
        ComputeFactorValue(input, input, factors);
        factors.clear();
        factors.push_back(1000.0);
        factors.push_back(1.0);
        ComputeFactorValue("kilometer", "metric", factors);
        ComputeFactorValue("mile", "imperial", factors);
    }

    void MeasureDataFuzzTest023(FuzzedDataProvider& provider)
    {
        double number = provider.ConsumeFloatingPoint<double>();
        std::vector<double> factors;
        factors.push_back(number);
        ComputePowerValue("kilometer", "metric", factors);
        ComputePowerValue("meter", "metric", factors);
        ComputePowerValue("centimeter", "metric", factors);
    }

    void MeasureDataFuzzTest024(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<double> factors;
        factors.push_back(1.0);
        factors.push_back(1000.0);
        ComputeValue(input, "metric", factors);
        ComputeValue(input, "imperial", factors);
    }

    void MeasureDataFuzzTest025(FuzzedDataProvider& provider)
    {
        double value = provider.ConsumeFloatingPoint<double>();
        std::string input = provider.ConsumeRandomLengthString();
        ConvertByte(value, input);
        value = 0.0;
        input = "byte";
        ConvertByte(value, input);
        value = -1024.0;
        input = "byte";
        ConvertByte(value, input);
        value = 1e15;
        input = "byte";
        ConvertByte(value, input);
    }

    void MeasureDataFuzzTest026(FuzzedDataProvider& provider)
    {
        double value = provider.ConsumeFloatingPoint<double>();
        std::string input = provider.ConsumeRandomLengthString();
        ConvertDate(value, input);
        value = 0.0;
        input = "day";
        ConvertDate(value, input);
        value = -365.0;
        input = "day";
        ConvertDate(value, input);
        value = 1e9;
        input = "day";
        ConvertDate(value, input);
    }

    void MeasureDataFuzzTest027(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> emptyUnits;
        GetDefaultPreferredUnit(input, input, emptyUnits);
        GetPreferredUnit(input, input, emptyUnits);
    }

    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < 1) {
            return false;
        }
        FuzzedDataProvider provider(data, size);

        MeasureDataFuzzTest001(provider);
        MeasureDataFuzzTest002(provider);
        MeasureDataFuzzTest003(provider);
        MeasureDataFuzzTest004(provider);
        MeasureDataFuzzTest005(provider);
        MeasureDataFuzzTest006(provider);
        MeasureDataFuzzTest007(provider);
        MeasureDataFuzzTest008(provider);
        MeasureDataFuzzTest009(provider);
        MeasureDataFuzzTest010(provider);
        MeasureDataFuzzTest011(provider);
        MeasureDataFuzzTest012(provider);
        MeasureDataFuzzTest013(provider);
        MeasureDataFuzzTest014(provider);
        MeasureDataFuzzTest015(provider);
        MeasureDataFuzzTest016(provider);
        MeasureDataFuzzTest017(provider);
        MeasureDataFuzzTest018(provider);
        MeasureDataFuzzTest019(provider);
        MeasureDataFuzzTest020(provider);
        MeasureDataFuzzTest021(provider);
        MeasureDataFuzzTest022(provider);
        MeasureDataFuzzTest023(provider);
        MeasureDataFuzzTest024(provider);
        MeasureDataFuzzTest025(provider);
        MeasureDataFuzzTest026(provider);
        MeasureDataFuzzTest027(provider);
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