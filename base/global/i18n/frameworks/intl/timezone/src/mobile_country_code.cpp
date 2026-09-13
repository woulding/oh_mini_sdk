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

#include "mobile_country_code.h"
#include "i18n_hilog.h"
#include <cctype>
#include <cstdio>
#include <unistd.h>
#include <unordered_map>
#include "securec.h"
#include "utils.h"

#ifdef TEL_CORE_SERVICE_ENABLE
#include "core_service_client.h"
#endif
#ifdef TEL_CELLULAR_DATA_ENABLE
#include "cellular_data_client.h"
#endif

using namespace OHOS::Global::I18n;
extern "C" int GlobalI18nGetCountryCodeFromSimCard(char* res, const int resLength)
{
    std::string countryCode = GetTelephonyInfo(&GetCountryCodeFromSimCard);
    for (size_t i = 0; i < countryCode.length(); ++i) {
        countryCode[i] = toupper(countryCode[i]);
    }
    return strcpy_s(res, resLength, countryCode.c_str());
}

extern "C" int GlobalI18nGetCountryCodeFromNetwork(char* res, const int resLength)
{
    std::string mccCode = GetTelephonyInfo(&GetMccCodeFromNetwork);
    std::string countryCode = ConvertMccCodeToCountryCode(mccCode);
    return strcpy_s(res, resLength, countryCode.c_str());
}

namespace OHOS {
namespace Global {
namespace I18n {
static const size_t MCC_CODE_LENGTH = 3;
static const std::unordered_map<std::string, std::string> MCC_DATA {
    {"202", "GR"}, {"204", "NL"}, {"206", "BE"}, {"208", "FR"}, {"212", "MC"},
    {"213", "AD"}, {"214", "ES"}, {"216", "HU"}, {"218", "BA"}, {"219", "HR"},
    {"220", "RS"}, {"222", "IT"}, {"225", "VA"}, {"226", "RO"}, {"228", "CH"},
    {"230", "CZ"}, {"231", "SK"}, {"232", "AT"}, {"234", "GB"}, {"235", "GB"},
    {"238", "DK"}, {"240", "SE"}, {"242", "NO"}, {"244", "FI"}, {"246", "LT"},
    {"247", "LV"}, {"248", "EE"}, {"250", "RU"}, {"255", "UA"}, {"257", "BY"},
    {"259", "MD"}, {"260", "PL"}, {"262", "DE"}, {"266", "GI"}, {"268", "PT"},
    {"270", "LU"}, {"272", "IE"}, {"274", "IS"}, {"276", "AL"}, {"278", "MT"},
    {"280", "CY"}, {"282", "GE"}, {"283", "AM"}, {"284", "BG"}, {"286", "TR"},
    {"288", "FO"}, {"289", "GE"}, {"290", "GL"}, {"292", "SM"}, {"293", "SI"},
    {"294", "MK"}, {"295", "LI"}, {"297", "ME"}, {"302", "CA"}, {"308", "PM"},
    {"310", "US"}, {"311", "US"}, {"312", "US"}, {"313", "US"}, {"314", "US"},
    {"315", "US"}, {"316", "US"}, {"330", "PR"}, {"332", "VI"}, {"334", "MX"},
    {"338", "JM"}, {"340", "GP"}, {"342", "BB"}, {"344", "AG"}, {"346", "KY"},
    {"348", "VG"}, {"350", "BM"}, {"352", "GD"}, {"354", "MS"}, {"356", "KN"},
    {"358", "LC"}, {"360", "VC"}, {"362", "AI"}, {"363", "AW"}, {"364", "BS"},
    {"365", "AI"}, {"366", "DM"}, {"368", "CU"}, {"370", "DO"}, {"372", "HT"},
    {"374", "TT"}, {"376", "TC"}, {"400", "AZ"}, {"401", "KZ"}, {"402", "BT"},
    {"404", "IN"}, {"405", "IN"}, {"406", "IN"}, {"410", "PK"}, {"412", "AF"},
    {"413", "LK"}, {"414", "MM"}, {"415", "LB"}, {"416", "JO"}, {"417", "SY"},
    {"418", "IQ"}, {"419", "KW"}, {"420", "SA"}, {"421", "YE"}, {"422", "OM"},
    {"423", "PS"}, {"424", "AE"}, {"425", "IL"}, {"426", "BH"}, {"427", "QA"},
    {"428", "MN"}, {"429", "NP"}, {"430", "AE"}, {"431", "AE"}, {"432", "IR"},
    {"434", "UZ"}, {"436", "TJ"}, {"437", "KG"}, {"438", "TM"}, {"440", "JP"},
    {"441", "JP"}, {"450", "KR"}, {"452", "VN"}, {"454", "HK"}, {"455", "MO"},
    {"456", "KH"}, {"457", "LA"}, {"460", "CN"}, {"461", "CN"}, {"466", "TW"},
    {"467", "KP"}, {"470", "BD"}, {"472", "MV"}, {"502", "MY"}, {"505", "AU"},
    {"510", "ID"}, {"514", "TL"}, {"515", "PH"}, {"520", "TH"}, {"525", "SG"},
    {"528", "BN"}, {"530", "NZ"}, {"534", "MP"}, {"535", "GU"}, {"536", "NR"},
    {"537", "PG"}, {"539", "TO"}, {"540", "SB"}, {"541", "VU"}, {"542", "FJ"},
    {"543", "WF"}, {"544", "AS"}, {"545", "KI"}, {"546", "NC"}, {"547", "PF"},
    {"548", "CK"}, {"549", "WS"}, {"550", "FM"}, {"551", "MH"}, {"552", "PW"},
    {"553", "TV"}, {"555", "NU"}, {"602", "EG"}, {"603", "DZ"}, {"604", "MA"},
    {"605", "TN"}, {"606", "LY"}, {"607", "GM"}, {"608", "SN"}, {"609", "MR"},
    {"610", "ML"}, {"611", "GN"}, {"612", "CI"}, {"613", "BF"}, {"614", "NE"},
    {"615", "TG"}, {"616", "BJ"}, {"617", "MU"}, {"618", "LR"}, {"619", "SL"},
    {"620", "GH"}, {"621", "NG"}, {"622", "TD"}, {"623", "CF"}, {"624", "CM"},
    {"625", "CV"}, {"626", "ST"}, {"627", "GQ"}, {"628", "GA"}, {"629", "CG"},
    {"630", "CD"}, {"631", "AO"}, {"632", "GW"}, {"633", "SC"}, {"634", "SD"},
    {"635", "RW"}, {"636", "ET"}, {"637", "SO"}, {"638", "DJ"}, {"639", "KE"},
    {"640", "TZ"}, {"641", "UG"}, {"642", "BI"}, {"643", "MZ"}, {"645", "ZM"},
    {"646", "MG"}, {"647", "RE"}, {"648", "ZW"}, {"649", "NA"}, {"650", "MW"},
    {"651", "LS"}, {"652", "BW"}, {"653", "SZ"}, {"654", "KM"}, {"655", "ZA"},
    {"657", "ER"}, {"658", "SH"}, {"659", "SS"}, {"702", "BZ"}, {"704", "GT"},
    {"706", "SV"}, {"708", "HN"}, {"710", "NI"}, {"712", "CR"}, {"714", "PA"},
    {"716", "PE"}, {"722", "AR"}, {"724", "BR"}, {"730", "CL"}, {"732", "CO"},
    {"734", "VE"}, {"736", "BO"}, {"738", "GY"}, {"740", "EC"}, {"742", "GF"},
    {"744", "PY"}, {"746", "SR"}, {"748", "UY"}, {"750", "FK"}
};

std::string GetTelephonyInfo(GetCountryCodeInnerFunc func)
{
    if (func == nullptr) {
        HILOG_ERROR_I18N("GetTelephonyInfo: func is nullptr");
        return "";
    }
    std::string result;
#if defined(TEL_CORE_SERVICE_ENABLE) && defined(TEL_CELLULAR_DATA_ENABLE)
    int32_t slotId = Telephony::CellularDataClient::GetInstance().GetDefaultCellularDataSlotId();
    if (slotId < 0) {
        return "";
    }
    result = func(slotId);
    if (result.empty()) {
        return "";
    }
#endif
    return result;
}

std::string GetCountryCodeFromSimCard(int32_t slotId)
{
#if defined(TEL_CORE_SERVICE_ENABLE) && defined(TEL_CELLULAR_DATA_ENABLE)
    std::u16string isoCountryCode;
    int32_t errCode = DelayedRefSingleton<Telephony::CoreServiceClient>::GetInstance()
        .GetISOCountryCodeForSim(slotId, isoCountryCode);
    if (errCode != 0) {
        HILOG_ERROR_I18N("GetCountryCodeFromSimCard:: id:%{public}d, errCode:%{public}d.",
            slotId, errCode);
        return "";
    }
    return Str16ToStr8(isoCountryCode);
#else
    return "";
#endif
}

std::string GetMccCodeFromNetwork(int32_t slotId)
{
#if defined(TEL_CORE_SERVICE_ENABLE) && defined(TEL_CELLULAR_DATA_ENABLE)
    std::string result = DelayedRefSingleton<Telephony::CoreServiceClient>::GetInstance()
        .GetResidentNetworkNumeric(slotId);
    if (result.empty()) {
        HILOG_ERROR_I18N("GetMccCodeFromNetwork:: result is empty.");
    }
    return result;
#else
    return "";
#endif
}

std::string ConvertMccCodeToCountryCode(const std::string& mccStr)
{
    if (mccStr.length() < MCC_CODE_LENGTH) {
        HILOG_ERROR_I18N("ConvertMccCodeToCountryCode: invalid code: %{public}s", mccStr.c_str());
        return "";
    }
    std::string mccCode(mccStr);
    mccCode = mccCode.substr(0, MCC_CODE_LENGTH);
    if (MCC_DATA.find(mccCode) != MCC_DATA.end()) {
        return MCC_DATA.at(mccCode);
    }
    return "";
}
}
}
}