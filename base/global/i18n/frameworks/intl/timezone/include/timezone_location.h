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
#ifndef GLOBAL_I18N_TIMEZONE_LOCATION_H
#define GLOBAL_I18N_TIMEZONE_LOCATION_H

#include <string>
#include <tuple>
#include <map>
#include <vector>
#include "i18n_hilog.h"

namespace OHOS {
namespace Global {
namespace I18n {
using GetCountryCodeFunc = int (*)(char*, int);

struct QueryData {
    double top;
    double bottom;
    double left;
    double right;
    double midLat;
    double midLon;
};

struct OceanZone {
    std::string tzid;
    double left;
    double right;
};

struct Point {
    double x;
    double y;
};

enum class ParseJsonStrResult { INVALID, OBJECT, ARRAY };

class TimeZoneLocation {
public:
    TimeZoneLocation();
    ~TimeZoneLocation();
    std::vector<std::string> GetTimezoneByLocation(const double lon, const double lat);

private:
    static const size_t TIMEZONE_ID_LENGTH = 40;
    static const int DIVISOR_FOR_MEDIAN = 2;
    static constexpr double MIN_LONGITUDE = -180.0;
    static constexpr double MAX_LONGITUDE = 180.0;
    static const int POINT_BYTE_SIZE = 8;
    static const size_t POINT_VALUE_SIZE = 2;
    static const int KEY_POS_P_OFFSET = 6;
    static const int KEY_POS_O_OFFSET = 7;
    static const int JSONITEM_BEGIN_OFFSET = 4;
    static const size_t LOOP_STEP = 2;
    static const int32_t MAX_LOOKUP_STR_SIZE = 10485760;
    static const int32_t MIN_POLYGON_POINTS_COUNT = 4;
    static const int RECV_CHAR_LENGTH = 32;
    static const char *TIMEZONE_LOCATION_PATH;
    static const char *DISTRO_TIMEZONE_LOCATION_PATH;
    static const char *POLITICAL_DATA_PATH;
    static const char *DISTRO_POLITICAL_DATA_PATH;
    static const char *DLOPEN_SO_NAME;
    static const char *VENDOR_COUNTRY_KEY;
    static const std::vector<OceanZone> OCEAN_ZONES;

    std::vector<Point> GetPointVect(int32_t* points, size_t size);
    bool IsPointInPolygon(const Point& p, const std::vector<Point>& polygon);
    std::vector<std::string> GetTimezoneAtSea(double lon);
    bool IsPointInMultiPolygon(const std::vector<int32_t>& pointsInPolygon,
        double lon, double lat, FILE* file);
    std::string NextSquare(QueryData& quadData, double lon, double lat);
    bool MatchNextKey(char* str, int len, int& curPos, std::string prefix, std::string nextKey);
    std::tuple<ParseJsonStrResult, std::string> GetJsonObjectFromPosition(
        const char* lookupStr, int pos, int len);
    std::vector<std::string> ReadPolygonData(double lon, double lat, FILE* datFile,
        const std::string& jsonObjectStr, const std::vector<std::string>& tzidNames);
    bool GetAllTimezoneId(std::vector<std::string>& tzidNames, FILE* datFile, int32_t indexCount);
    void ReadDatFile(FILE* datFile, double lon, double lat,
        const std::vector<std::string>& tzidNames, std::vector<std::string>& tzidList);
    std::vector<std::string> GetTimezoneIdList(double lon, double lat,
        int32_t tzIndexCount, FILE* datFile, const std::vector<std::string>& tzidNames);
    void ReadJsonArray(const std::string& jsonArrayStr,
        const std::vector<std::string>& tzidNames, std::vector<std::string>& tzidList);
    bool IsPointOnSegment(const Point& p, const Point& before, const Point& after);
    std::string GetCountryCode();
    std::string GetISOCountryCode(const char* symbol);
    std::string GetCountryCodeFromVendorCountry();
    const char* GetPoliticalDataPath();
    const char* GetTimeZoneLocationDataPath();
    std::vector<std::string> ReadPoliticalData(const std::string& datPath,
        const double lon, const double lat);
    bool MatchPoliticalDataBlock(FILE* datFile, const double lon, const double lat);
    std::vector<std::string> GetPoliticalTimezone(const double lon, const double lat);
};

class TzLocationDatFile {
public:
    explicit TzLocationDatFile(const char* path)
    {
        file_ = fopen(path, "rb");
        if (file_ == nullptr) {
            HILOG_ERROR_I18N("TzLocationDatFile: open datFile failed");
        }
    }
    ~TzLocationDatFile()
    {
        if (file_ == nullptr) {
            HILOG_ERROR_I18N("~TzLocationDatFile: datFile is nullptr");
            return;
        }
        if (fclose(file_) != 0) {
            HILOG_ERROR_I18N("~TzLocationDatFile: close datFile failed");
        }
    }
    FILE* get() const
    {
        return file_;
    }
    explicit operator bool() const
    {
        return file_ != nullptr;
    }
private:
    FILE* file_;
};
} // namespace I18n
} // namespace Global
} // namespace OHOS
#endif
