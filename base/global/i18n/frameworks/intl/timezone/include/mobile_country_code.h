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
#ifndef GLOBAL_I18N_MOBILE_COUNTRY_CODE_H
#define GLOBAL_I18N_MOBILE_COUNTRY_CODE_H

#include <string>

extern "C" int GlobalI18nGetCountryCodeFromSimCard(char* res, const int resLength);
extern "C" int GlobalI18nGetCountryCodeFromNetwork(char* res, const int resLength);

namespace OHOS {
namespace Global {
namespace I18n {
using GetCountryCodeInnerFunc = std::string (*)(int32_t);
std::string GetTelephonyInfo(GetCountryCodeInnerFunc func);
std::string GetCountryCodeFromSimCard(int32_t slotId);
std::string GetMccCodeFromNetwork(int32_t slotId);
std::string ConvertMccCodeToCountryCode(const std::string& mccStr);
}
}
}
#endif
