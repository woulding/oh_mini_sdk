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

#include "hyphenation.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <fstream>
#include <map>
#include <string>
#include <vector>
#include <sys/stat.h>

namespace OHOS {
namespace I18N {

namespace {

constexpr uint32_t CHAR_HYPHEN_MINUS = 0x002D;
constexpr uint32_t CHAR_SOFT_HYPHEN = 0x00AD;
constexpr uint32_t CHAR_MIDDLE_DOT = 0x00B7;
constexpr uint32_t CHAR_ARMENIAN_HYPHEN = 0x058A;
constexpr uint32_t CHAR_MAQAF = 0x05BE;
constexpr uint32_t CHAR_UCAS_HYPHEN = 0x1400;
constexpr uint32_t CHAR_HYPHEN = 0x2010;
constexpr uint32_t CHAR_EN_DASH = 0x2013;
constexpr uint32_t CHAR_HYPHENATION_POINT = 0x2027;
constexpr uint32_t CHAR_DOUBLE_OBLIQUE_HYPHEN = 0x2E17;
constexpr uint32_t CHAR_DOUBLE_HYPHEN = 0x2E40;
constexpr size_t MAX_HYPHENATED_SIZE = 64;
constexpr size_t PRE_CHAR_OFFSET = 2;
constexpr size_t ADD_ARRAY_HEAD_TAIL = 2;
const static int DEFAULT_MIN_VAL = 2;
const static size_t MAX_BINARY_FILE_SIZE = 1048576;

const char* HYPHEN_PATH_PREFIX = "/system/i18n/hyphen-data/hyph-";
constexpr char SYSTEM_HYPHENATOR_SUFFIX[] = ".hyb";
const char* HYPHEN_STANDARD = "\xE2\x80\x90";
const char* HYPHEN_ARMENIAN = "\xD6\x8A";
const char* HYPHEN_HEBREW = "\xD6\xBE";
const char* HYPHEN_ZWJ_HYPHEN = "\xD9\x80";

enum HyphenationLocale {
    LOCALE_OTHER = 0,
    LOCALE_CATALAN = 1,
    LOCALE_POLISH = 2,
    LOCALE_SLOVENIAN = 3,
    LOCALE_PORTUGUESE = 4
};

enum class Script {
    LATIN,
    CYRILLIC,
    ARABIC,
    GREEK,
    HEBREW,
    ARMENIAN,
    DEVANAGARI,
    BENGALI,
    GUJARATI,
    GURMUKHI,
    TELUGU,
    KANNADA,
    MALAYALAM,
    TAMIL,
    KANA,
    HAN,
    CANADIAN_ABORIGINAL,
    UNKNOWN
};

bool IsLineBreakingHyphen(uint32_t c)
{
    return (c == CHAR_HYPHEN_MINUS ||
            c == CHAR_ARMENIAN_HYPHEN ||
            c == CHAR_MAQAF ||
            c == CHAR_UCAS_HYPHEN ||
            c == CHAR_HYPHEN ||
            c == CHAR_EN_DASH ||
            c == CHAR_HYPHENATION_POINT ||
            c == CHAR_DOUBLE_OBLIQUE_HYPHEN ||
            c == CHAR_DOUBLE_HYPHEN);
}

bool IsLatinRange(uint32_t codepoint)
{
    return (codepoint >= 0x0041 && codepoint <= 0x005A) ||
           (codepoint >= 0x0061 && codepoint <= 0x007A) ||
           (codepoint >= 0x00C0 && codepoint <= 0x024F);
}

bool IsCyrillicRange(uint32_t codepoint)
{
    return (codepoint >= 0x0400 && codepoint <= 0x04FF) ||
           (codepoint >= 0x0500 && codepoint <= 0x052F);
}

bool IsArabicRange(uint32_t codepoint)
{
    return (codepoint >= 0x0600 && codepoint <= 0x06FF) ||
           (codepoint >= 0x0750 && codepoint <= 0x077F);
}

bool IsGreekRange(uint32_t codepoint)
{
    return (codepoint >= 0x0370 && codepoint <= 0x03FF);
}

bool IsHebrewRange(uint32_t codepoint)
{
    return (codepoint >= 0x0590 && codepoint <= 0x05FF);
}

bool IsArmenianRange(uint32_t codepoint)
{
    return (codepoint >= 0x0530 && codepoint <= 0x058F);
}

bool IsDevanagariRange(uint32_t codepoint)
{
    return (codepoint >= 0x0900 && codepoint <= 0x097F);
}

bool IsBengaliRange(uint32_t codepoint)
{
    return (codepoint >= 0x0980 && codepoint <= 0x09FF);
}

bool IsGujaratiRange(uint32_t codepoint)
{
    return (codepoint >= 0x0A80 && codepoint <= 0x0AFF);
}

bool IsGurmukhiRange(uint32_t codepoint)
{
    return (codepoint >= 0x0A00 && codepoint <= 0x0A7F);
}

bool IsTeluguRange(uint32_t codepoint)
{
    return (codepoint >= 0x0C00 && codepoint <= 0x0C7F);
}

bool IsKannadaRange(uint32_t codepoint)
{
    return (codepoint >= 0x0C80 && codepoint <= 0x0CFF);
}

bool IsMalayalamRange(uint32_t codepoint)
{
    return (codepoint >= 0x0D00 && codepoint <= 0x0D7F);
}

bool IsTamilRange(uint32_t codepoint)
{
    return (codepoint >= 0x0B80 && codepoint <= 0x0BFF);
}

bool IsKanaRange(uint32_t codepoint)
{
    return (codepoint >= 0x3040 && codepoint <= 0x309F) ||
           (codepoint >= 0x30A0 && codepoint <= 0x30FF);
}

bool IsHanRange(uint32_t codepoint)
{
    return (codepoint >= 0x4E00 && codepoint <= 0x9FFF) ||
           (codepoint >= 0x3400 && codepoint <= 0x4DBF);
}

bool IsCanadianAboriginalRange(uint32_t codepoint)
{
    return (codepoint >= 0x1400 && codepoint <= 0x167F);
}

Script MatchScript(uint32_t codepoint)
{
    if (IsTeluguRange(codepoint)) {
        return Script::TELUGU;
    }
    if (IsKannadaRange(codepoint)) {
        return Script::KANNADA;
    }
    if (IsMalayalamRange(codepoint)) {
        return Script::MALAYALAM;
    }
    if (IsTamilRange(codepoint)) {
        return Script::TAMIL;
    }
    if (IsKanaRange(codepoint)) {
        return Script::KANA;
    }
    if (IsHanRange(codepoint)) {
        return Script::HAN;
    }
    if (IsCanadianAboriginalRange(codepoint)) {
        return Script::CANADIAN_ABORIGINAL;
    }
    return Script::UNKNOWN;
}

Script GetScript(uint32_t codepoint)
{
    if (IsLatinRange(codepoint)) {
        return Script::LATIN;
    }
    if (IsCyrillicRange(codepoint)) {
        return Script::CYRILLIC;
    }
    if (IsArabicRange(codepoint)) {
        return Script::ARABIC;
    }
    if (IsGreekRange(codepoint)) {
        return Script::GREEK;
    }
    if (IsHebrewRange(codepoint)) {
        return Script::HEBREW;
    }
    if (IsArmenianRange(codepoint)) {
        return Script::ARMENIAN;
    }
    if (IsDevanagariRange(codepoint)) {
        return Script::DEVANAGARI;
    }
    if (IsBengaliRange(codepoint)) {
        return Script::BENGALI;
    }
    if (IsGujaratiRange(codepoint)) {
        return Script::GUJARATI;
    }
    if (IsGurmukhiRange(codepoint)) {
        return Script::GURMUKHI;
    }
    return MatchScript(codepoint);
}

int HyphenationTypeBasedOnScript(uint32_t codePoint)
{
    Script script = GetScript(codePoint);
    if (script == Script::KANNADA || script == Script::MALAYALAM ||
        script == Script::TAMIL || script == Script::TELUGU) {
        return 2; // 2 means HyphenType::BREAK_NO_INSERT
    }
    return 1; // 1 means HyphenType::BREAK
}

const char* GetHyphenByLocale(const char* locale)
{
    if (locale == nullptr) {
        return HYPHEN_STANDARD;
    }
    std::string lang = locale;
    size_t pos = lang.find('-');
    if (pos != std::string::npos) {
        lang = lang.substr(0, pos);
    }
    if (lang == "hy") {
        return HYPHEN_ARMENIAN;
    }
    if (lang == "he" || lang == "iw") {
        return HYPHEN_HEBREW;
    }
    if (lang == "ar" || lang == "fa" || lang == "ur" || lang == "ug") {
        return HYPHEN_ZWJ_HYPHEN;
    }
    return HYPHEN_STANDARD;
}

std::string ToLower(const std::string& str)
{
    std::string result;
    result.reserve(str.size());
    for (char c : str) {
        result += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return result;
}

std::string MapLocaleToFile(const std::string& locale)
{
    static const std::map<std::string, std::string> localeMapping = {
        { "en-US", "en-us" },
        { "en-GB", "en-gb" },
        { "sr-Latn", "sr" },
        { "de", "de-1996" }
    };

    auto it = localeMapping.find(locale);
    if (it != localeMapping.end()) {
        return it->second;
    }

    std::string lang = locale;
    size_t pos = lang.find('-');
    if (pos != std::string::npos) {
        lang = lang.substr(0, pos);
    }

    it = localeMapping.find(lang);
    if (it != localeMapping.end()) {
        return it->second;
    }

    if (lang == "en") {
        return "en-us";
    }

    return lang;
}

std::string BuildFileName(const std::string& locale)
{
    std::string lowerLocale = ToLower(MapLocaleToFile(locale));
    return HYPHEN_PATH_PREFIX + lowerLocale + SYSTEM_HYPHENATOR_SUFFIX;
}

std::pair<const uint8_t*, size_t> LoadPatternFile(const std::string& locale)
{
    const std::string hyFilePath = BuildFileName(locale);
    struct stat buffer;
    if (stat(hyFilePath.c_str(), &buffer) != 0) {
        return std::make_pair(nullptr, 0);
    }
    std::ifstream file(hyFilePath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        return std::make_pair(nullptr, 0);
    }
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    if (static_cast<size_t>(size) > MAX_BINARY_FILE_SIZE) {
        return std::make_pair(nullptr, 0);
    }
    auto* dataBuffer = new uint8_t[size];
    if (!file.read(reinterpret_cast<char*>(dataBuffer), size)) {
        delete[] dataBuffer;
        return std::make_pair(nullptr, 0);
    }

    return std::make_pair(dataBuffer, static_cast<size_t>(size));
}

bool IsOnePrefixSuffixLang(const std::string& locale)
{
    return locale == "af" || locale == "am" || locale == "el" || locale == "cu";
}

int GetDefaultMinPrefix(const std::string& locale)
{
    if (IsOnePrefixSuffixLang(locale)) {
        return 1; // word break keep at least 1 char at head
    }
    return 2; // word break keep at least 2 char at head
}

bool IsThreeSuffixLang(const std::string& locale)
{
    return locale == "pt" || locale == "fr" || locale == "en" || locale == "ga" ||
           locale == "cy" || locale == "et" || locale == "lv";
}

int GetDefaultMinSuffix(const std::string& locale)
{
    if (IsThreeSuffixLang(locale)) {
        return 3; // word break keep at least 3 char at tail
    }
    return 2; // word break keep at least 2 char at tail
}

HyphenationLocale ParseLocale(const std::string& locale)
{
    if (locale == "pl") {
        return LOCALE_POLISH;
    }
    if (locale == "ca") {
        return LOCALE_CATALAN;
    }
    if (locale == "sl") {
        return LOCALE_SLOVENIAN;
    }
    if (locale == "pt") {
        return LOCALE_PORTUGUESE;
    }
    return LOCALE_OTHER;
}

bool IsLatinChar(uint32_t c)
{
    return IsLatinRange(c);
}

uint32_t Utf8ToCodepoint(const char*& ptr)
{
    const uint8_t* u = reinterpret_cast<const uint8_t*>(ptr);
    if ((*u & 0x80) == 0) {
        uint32_t cp = *u;
        ptr += 1;
        return cp;
    }
    if ((*u & 0xE0) == 0xC0) {
        uint32_t cp = ((*u & 0x1F) << 6) | (u[1] & 0x3F);
        ptr += 2; // 2 means unicode char has 2 bytes
        return cp;
    }
    if ((*u & 0xF0) == 0xE0) {
        uint32_t cp = ((*u & 0x0F) << 12) | ((u[1] & 0x3F) << 6) | (u[2] & 0x3F);
        ptr += 3; // 3 means unicode char has 3 bytes
        return cp;
    }
    if ((*u & 0xF8) == 0xF0) {
        uint32_t cp = ((*u & 0x07) << 18) | ((u[1] & 0x3F) << 12) |
                      ((u[2] & 0x3F) << 6) | (u[3] & 0x3F);
        ptr += 4; // 4 means unicode char has 4 bytes
        return cp;
    }
    return *u++;
}

std::vector<uint32_t> Utf8ToCodepoints(const char* word)
{
    std::vector<uint32_t> codepoints;
    const char* ptr = word;
    while (*ptr != '\0') {
        codepoints.push_back(Utf8ToCodepoint(ptr));
    }
    return codepoints;
}

} // namespace

Hyphenation::Hyphenation(const char* lang)
    : mLocale(lang), mMinPrefix(DEFAULT_MIN_VAL),
      mMinSuffix(DEFAULT_MIN_VAL), mPatternData(nullptr), mPatternSize(0),
      mHyphenLocale(0)
{
    std::string locale = lang;
    size_t pos = locale.find('-');
    if (pos != std::string::npos) {
        locale = locale.substr(0, pos);
    }
    mMinPrefix = GetDefaultMinPrefix(locale);
    mMinSuffix = GetDefaultMinSuffix(locale);
    mHyphenLocale = ParseLocale(locale);
    auto result = LoadPatternFile(lang);
    if (result.first != nullptr) {
        mPatternData = const_cast<uint8_t*>(result.first);
        mPatternSize = result.second;
    }
}

Hyphenation::~Hyphenation()
{
    if (mPatternData != nullptr) {
        delete[] static_cast<uint8_t*>(mPatternData);
    }
}

Hyphenation* Hyphenation::CreateInstance(const char* lang)
{
    if (lang == nullptr || strlen(lang) == 0) {
        return nullptr;
    }
    return new Hyphenation(lang);
}

const char* Hyphenation::GetHyphenCharByLocale(const char* locale) const
{
    return GetHyphenByLocale(locale);
}

struct Header {
    uint32_t magic;
    uint32_t version;
    uint32_t alphabetOffset;
    uint32_t trieOffset;
    uint32_t patternOffset;
    uint32_t fileSize;

    const uint8_t* Bytes() const
    {
        return reinterpret_cast<const uint8_t*>(this);
    }

    uint32_t AlphabetVersion() const
    {
        return *reinterpret_cast<const uint32_t*>(Bytes() + alphabetOffset);
    }

    const Trie* TrieTable() const
    {
        return reinterpret_cast<const Trie*>(Bytes() + trieOffset);
    }

    const Pattern* PatternTable() const
    {
        return reinterpret_cast<const Pattern*>(Bytes() + patternOffset);
    }
};

struct AlphabetTable0 {
    uint32_t version;
    uint32_t minCodepoint;
    uint32_t maxCodepoint;
    uint8_t data[1];

    uint8_t GetCode(uint32_t codepoint) const
    {
        if (codepoint < minCodepoint || codepoint >= maxCodepoint) {
            return 0;
        }
        return data[codepoint - minCodepoint];
    }
};

bool Hyphenation::CheckAlienChars(const std::vector<uint32_t>& codepoints) const
{
    if (mPatternData == nullptr) {
        return false;
    }

    const Header* header = reinterpret_cast<const Header*>(mPatternData);
    uint32_t alphabetVersion = header->AlphabetVersion();
    if (alphabetVersion == 0) {
        const AlphabetTable0* alphabet = reinterpret_cast<const AlphabetTable0*>(
            header->Bytes() + header->alphabetOffset);
        for (size_t i = 0; i < codepoints.size(); i++) {
            uint16_t c = static_cast<uint16_t>(codepoints[i]);
            if (c < alphabet->minCodepoint || c >= alphabet->maxCodepoint) {
                return true;
            }
            uint8_t code = alphabet->GetCode(c);
            if (code == 0) {
                return true;
            }
        }
    } else if (alphabetVersion == 1) {
        const AlphabetTable1* alphabet = reinterpret_cast<const AlphabetTable1*>(
            header->Bytes() + header->alphabetOffset);
        size_t nEntries = alphabet->nEntries;
        const uint32_t* begin = alphabet->data;
        const uint32_t* end = begin + nEntries;
        for (size_t i = 0; i < codepoints.size(); i++) {
            uint16_t c = static_cast<uint16_t>(codepoints[i]);
            auto p = std::lower_bound(begin, end, static_cast<uint32_t>(c) << 11); // 11 is shift bits
            if (p == end || AlphabetTable1::Codepoint(*p) != c) {
                return true;
            }
        }
    }
    return false;
}

bool Hyphenation::PreCharIsPolishHyphen(uint32_t prevChar, size_t i,
    const std::vector<uint32_t>& codepoints) const
{
    return (prevChar == CHAR_HYPHEN_MINUS || prevChar == CHAR_HYPHEN) &&
           (mHyphenLocale == LOCALE_POLISH || mHyphenLocale == LOCALE_SLOVENIAN) &&
                i < codepoints.size() && IsLatinChar(codepoints[i]);
}

void Hyphenation::ProcessNoPatterns(const std::vector<uint32_t>& codepoints,
                                    std::vector<int>& result) const
{
    result[0] = 0;
    for (size_t i = 1; i < codepoints.size(); i++) {
        uint32_t prevChar = codepoints[i - 1];
        if (i > 1 && IsLineBreakingHyphen(prevChar)) {
            if (PreCharIsPolishHyphen(prevChar, i, codepoints)) {
                result[i] = HyphenType::BREAK_INSERT_AND_NEXT;
            } else {
                result[i] = HyphenType::BREAK_NO_INSERT;
            }
        } else if (i > 1 && prevChar == CHAR_SOFT_HYPHEN) {
            if (GetScript(codepoints[i]) == Script::ARABIC) {
                result[i] = HyphenType::BREAK_INSERT_AND_NEXT;
            } else {
                result[i] = HyphenationTypeBasedOnScript(codepoints[i]);
            }
        } else if (prevChar == CHAR_MIDDLE_DOT && mMinPrefix < static_cast<int>(i) &&
                   i <= codepoints.size() - static_cast<size_t>(mMinSuffix) &&
                   mHyphenLocale == LOCALE_CATALAN &&
                   ((codepoints[i - PRE_CHAR_OFFSET] == 'l' && codepoints[i] == 'l') ||
                    (codepoints[i - PRE_CHAR_OFFSET] == 'L' && codepoints[i] == 'L'))) {
            result[i] = HyphenType::BREAK_AND_REPLACE;
        } else {
            result[i] = HyphenType::NO_BREAK;
        }
    }
}

std::vector<uint8_t> Hyphenation::ConvertToCharCodes(const std::vector<uint32_t>& codepoints,
                                                     size_t len) const
{
    std::vector<uint8_t> charCodes(len + ADD_ARRAY_HEAD_TAIL);
    charCodes[0] = 0;
    charCodes[len + 1] = 0;
    const Header* header = reinterpret_cast<const Header*>(mPatternData);
    uint32_t alphabetVersion = header->AlphabetVersion();
    if (alphabetVersion == 0) {
        const AlphabetTable0* alphabet = reinterpret_cast<const AlphabetTable0*>(
            header->Bytes() + header->alphabetOffset);
        for (size_t i = 0; i < len; i++) {
            uint16_t c = static_cast<uint16_t>(codepoints[i]);
            charCodes[i + 1] = alphabet->GetCode(c);
        }
    } else if (alphabetVersion == 1) {
        const AlphabetTable1* alphabet = reinterpret_cast<const AlphabetTable1*>(
            header->Bytes() + header->alphabetOffset);
        size_t nEntries = alphabet->nEntries;
        const uint32_t* begin = alphabet->data;
        const uint32_t* end = begin + nEntries;
        for (size_t i = 0; i < len; i++) {
            uint16_t c = static_cast<uint16_t>(codepoints[i]);
            auto p = std::lower_bound(begin, end, static_cast<uint32_t>(c) << 11);
            if (p != end && AlphabetTable1::Codepoint(*p) == c) {
                charCodes[i + 1] = static_cast<uint8_t>(AlphabetTable1::Value(*p));
            } else {
                charCodes[i + 1] = 0;
            }
        }
    }

    return charCodes;
}

void Hyphenation::MatchPatterns(const char* word, const std::vector<uint8_t>& charCodes,
                                size_t len, std::vector<int>& result) const
{
    const Header* header = reinterpret_cast<const Header*>(mPatternData);
    const Trie* trie = header->TrieTable();
    const Pattern* pattern = header->PatternTable();
    const uint32_t* trieData = trie->data;
    uint32_t charMask = trie->charMask;
    uint32_t linkShift = trie->linkShift;
    uint32_t linkMask = trie->linkMask;
    uint32_t patternShift = trie->patternShift;
    size_t paddedLen = len + ADD_ARRAY_HEAD_TAIL;
    size_t maxOffset = paddedLen - mMinSuffix - 1;

    std::vector<uint8_t> buffer(paddedLen, 0);
    for (size_t i = 0; i < paddedLen - 1; i++) {
        uint32_t node = 0;
        for (size_t j = i; j < paddedLen; j++) {
            uint16_t c = charCodes[j];
            uint32_t entry = trieData[node + c];
            if ((entry & charMask) != c) {
                break;
            }
            node = (entry & linkMask) >> linkShift;

            uint32_t patIx = trieData[node] >> patternShift;
            if (patIx == 0) {
                continue;
            }
            uint32_t patEntry = pattern->data[patIx];
            uint32_t patLen = Pattern::Len(patEntry);
            uint32_t patShiftVal = Pattern::Shift(patEntry);
            const uint8_t* patBuf = pattern->Buf(patEntry);
            uint32_t offset = j + 1 - (patLen + patShiftVal);

            int start = std::max(mMinPrefix - static_cast<int>(offset), 0);
            int end = std::min(static_cast<int>(patLen), static_cast<int>(maxOffset - offset));
            for (int k = start; k < end; k++) {
                buffer[offset + k] = std::max(buffer[offset + k], patBuf[k]);
            }
        }
    }
    for (size_t i = mMinPrefix; i < maxOffset; i++) {
        result[i] = (buffer[i] & 1u) ? 1 : 0;
        if (i > 0 && IsLineBreakingHyphen(word[i - 1])) {
            if (mHyphenLocale == LOCALE_PORTUGUESE) {
                result[i - 1] = HyphenType::BREAK_NO_INSERT;
                result[i] = HyphenType::NO_BREAK;
            } else {
                result[i - 1] = HyphenType::NO_BREAK;
                result[i] = HyphenType::BREAK_NO_INSERT;
            }
        }
    }
}

std::vector<int> Hyphenation::GetBreakCandidate(const char* word)
{
    return GetBreakCandidate(word, mMinPrefix, mMinSuffix);
}

std::vector<int> Hyphenation::GetBreakCandidate(const char* word, int minPrefix, int minSuffix)
{
    if (mPatternData == nullptr || word == nullptr || strlen(word) == 0) {
        return std::vector<int>(1, 0);
    }
    std::vector<uint32_t> codepoints = Utf8ToCodepoints(word);
    size_t len = codepoints.size();
    if (len == 0) {
        return std::vector<int>(1, 0);
    }
    size_t paddedLen = len + ADD_ARRAY_HEAD_TAIL;

    if (mPatternData != nullptr && len >= static_cast<size_t>(minPrefix + minSuffix) &&
        paddedLen <= MAX_HYPHENATED_SIZE) {
        bool hasAlienChar = CheckAlienChars(codepoints);
        if (!hasAlienChar) {
            std::vector<int> result(len, 0);
            result[0] = 0;

            std::vector<uint8_t> charCodes = ConvertToCharCodes(codepoints, len);
            MatchPatterns(word, charCodes, len, result);
            return result;
        }
    }
    std::vector<int> result(len, 0);
    result[0] = 0;
    ProcessNoPatterns(codepoints, result);
    return result;
}

std::vector<const char*> Hyphenation::GetHyphenation(const char* lang, HyphenType type)
{
    std::vector<const char*> result;
    const char* hyphen = GetHyphenByLocale(lang);

    switch (type) {
        case HyphenType::NO_BREAK:
            break;
        case HyphenType::BREAK:
            result.push_back(hyphen);
            break;
        case HyphenType::BREAK_NO_INSERT:
            break;
        case HyphenType::BREAK_AND_REPLACE:
            result.push_back(hyphen);
            break;
        case HyphenType::BREAK_INSERT_AND_NEXT:
            result.push_back("\u200D\u2010");
            result.push_back("\u200D");
            break;
        default:
            break;
    }

    return result;
}

void Hyphenation::ProcessHyphenBreak(const std::vector<uint32_t>& codepoints,
                                     std::vector<int>& result, size_t i) const
{
    uint32_t prevChar = codepoints[i - 1];
    if ((prevChar == CHAR_HYPHEN_MINUS || prevChar == CHAR_HYPHEN) &&
        (mHyphenLocale == LOCALE_POLISH || mHyphenLocale == LOCALE_SLOVENIAN) &&
        i < codepoints.size() && IsLatinChar(codepoints[i])) {
        result[i] = HyphenType::BREAK_INSERT_AND_NEXT;
    } else if (mHyphenLocale == LOCALE_PORTUGUESE && i > 1) {
        result[i - 1] = HyphenType::BREAK_NO_INSERT;
        result[i] = HyphenType::NO_BREAK;
    } else {
        result[i - 1] = HyphenType::NO_BREAK;
        result[i] = HyphenType::BREAK_NO_INSERT;
    }
}

bool Hyphenation::IsPreCharIsCatalanHyphen(uint32_t prevChar, size_t i,
    size_t len, const std::vector<uint32_t>& codepoints) const
{
    return prevChar == CHAR_MIDDLE_DOT && mMinPrefix < static_cast<int>(i) &&
           i <= len - mMinSuffix && mHyphenLocale == LOCALE_CATALAN &&
           ((codepoints[i - PRE_CHAR_OFFSET] == 'l' && codepoints[i] == 'l') ||
           (codepoints[i - PRE_CHAR_OFFSET] == 'L' && codepoints[i] == 'L'));
}

std::vector<int> Hyphenation::HyphenationWithNoRule(const char* word)
{
    if (word == nullptr || strlen(word) == 0) {
        return std::vector<int>(1, 0);
    }

    std::vector<uint32_t> codepoints = Utf8ToCodepoints(word);
    size_t len = codepoints.size();
    if (len == 0) {
        return std::vector<int>(1, 0);
    }

    if (CheckAlienChars(codepoints)) {
        return std::vector<int>(1, 0);
    }

    std::vector<int> result(len, 0);
    result[0] = 0;

    for (size_t i = 1; i < len; i++) {
        uint32_t prevChar = codepoints[i - 1];
        if (i > 1 && IsLineBreakingHyphen(prevChar)) {
            if (PreCharIsPolishHyphen(prevChar, i, codepoints)) {
                result[i] = HyphenType::BREAK_INSERT_AND_NEXT;
            } else {
                result[i] = HyphenType::BREAK_NO_INSERT;
            }
        } else if (i > 1 && prevChar == CHAR_SOFT_HYPHEN) {
            if (GetScript(codepoints[i]) == Script::ARABIC) {
                result[i] = HyphenType::BREAK_INSERT_AND_NEXT;
            } else {
                result[i] = HyphenationTypeBasedOnScript(codepoints[i]);
            }
        } else if (IsPreCharIsCatalanHyphen(prevChar, i, len, codepoints)) {
            result[i] = HyphenType::BREAK_AND_REPLACE;
        } else {
            result[i] = 0;
        }
    }
    return result;
}

} // namespace I18N
} // namespace OHOS
