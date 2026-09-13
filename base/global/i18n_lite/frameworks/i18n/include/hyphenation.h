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

#ifndef GLOBAL_I18N_LITE_HYPHENATION_H
#define GLOBAL_I18N_LITE_HYPHENATION_H

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace OHOS {
namespace I18N {

enum HyphenType {
    NO_BREAK = 0,
    BREAK = 1,
    BREAK_NO_INSERT = 2,
    BREAK_AND_REPLACE = 3,
    BREAK_INSERT_AND_NEXT = 4
};

struct Trie {
    uint32_t version;
    uint32_t charMask;
    uint32_t linkShift;
    uint32_t linkMask;
    uint32_t patternShift;
    uint32_t nEntries;
    uint32_t data[1];
};

struct Pattern {
    uint32_t version;
    uint32_t nEntries;
    uint32_t patternOffset;
    uint32_t patternSize;
    uint32_t data[1];

    static uint32_t Len(uint32_t entry)
    {
        return entry >> 26; // 26 is shift bits
    }

    static uint32_t Shift(uint32_t entry)
    {
        return (entry >> 20) & 0x3f; // 20 is shift bits
    }

    const uint8_t* Buf(uint32_t entry) const
    {
        return reinterpret_cast<const uint8_t*>(this) + patternOffset + (entry & 0xfffff);
    }
};

struct AlphabetTable1 {
    uint32_t version;
    uint32_t nEntries;
    uint32_t data[1];

    static uint32_t Codepoint(uint32_t entry)
    {
        return entry >> 11; // 11 is shift bits
    }

    static uint32_t Value(uint32_t entry)
    {
        return entry & 0x7ff;
    }
};

class Hyphenation {
public:
    static Hyphenation* CreateInstance(const char* lang);

    std::vector<int> GetBreakCandidate(const char* word);
    std::vector<int> GetBreakCandidate(const char* word, int minPrefix, int minSuffix);

    static std::vector<const char*> GetHyphenation(const char* lang, HyphenType type);

    std::vector<int> HyphenationWithNoRule(const char* word);

    ~Hyphenation();

private:
    explicit Hyphenation(const char* lang);

    bool CheckAlienChars(const std::vector<uint32_t>& codepoints) const;
    void ProcessNoPatterns(const std::vector<uint32_t>& codepoints,
                           std::vector<int>& result) const;
    void ProcessHyphenBreak(const std::vector<uint32_t>& codepoints,
                             std::vector<int>& result, size_t i) const;

    std::vector<uint8_t> ConvertToCharCodes(const std::vector<uint32_t>& codepoints,
                                              size_t len) const;
    void MatchPatterns(const char* word, const std::vector<uint8_t>& charCodes,
                       size_t len, std::vector<int>& result) const;

    const char* GetHyphenCharByLocale(const char* locale) const;
    bool PreCharIsPolishHyphen(uint32_t prevChar, size_t i,
        const std::vector<uint32_t>& codepoints) const;
    bool IsPreCharIsCatalanHyphen(uint32_t prevChar, size_t i,
        size_t len, const std::vector<uint32_t>& codepoints) const;

    std::string mLocale;
    int mMinPrefix;
    int mMinSuffix;
    void* mPatternData;
    size_t mPatternSize;
    int mHyphenLocale;
};

}
}

#endif
