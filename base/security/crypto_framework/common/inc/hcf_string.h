/*
* Copyright (C) 2021 Huawei Device Co., Ltd.
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#ifndef HC_STRING_H
#define HC_STRING_H

#include "hcf_parcel.h"

#ifdef __cplusplus
extern "C" {
#endif

    typedef struct HcString {
        HcParcel parcel; // parcel data, used to storage the string data
    } HcString;

    /*
    * Append string pointer
    * Notice: It will add '\0' automatically.
    * @param self: self pointer.
    * @param str: string pointer.
    * @return true (ok), false (error)
    */
    bool StringAppendPointer(HcString *self, const char *str);

    /*
    * Assign a value to the HcString
    * Notice: It will add '\0' automatically.
    * @param self: self pointer.
    * @param str: assign value of string pointer.
    * @return true (ok), false (error)
    */
    bool StringSetPointer(HcString *self, const char *str);

    /*
    * Assign a value to the HcString with fixed length
    * Notice: It will add '\0' automatically.
    * @param self: self pointer.
    * @param str: assign value of string pointer.
    * @param len: the length of string.
    * @return true (ok), false (error)
    */
    bool StringSetPointerWithLength(HcString* self, const char *str, uint32_t len);

    /*
    * Get the string pointer data
    * @param self: self pointer.
    * @return the pointer data of the string
    */
    const char* StringGet(const HcString *self);

    /*
    * Get the length of the string
    * @param self: self pointer.
    * @return the length of the string
    */
    uint32_t StringLength(const HcString *self);

    /*
    * Find a char from string
    * @param self: self pointer.
    * @param c: the char you want find
    * @param begin: the position find from
    * @return the position of the char
    */
    int StringFind(const HcString *self, char c, uint32_t begin);

    /*
    * Get sub string from a string.
    * @param self: self pointer.
    * @param begin: the begin position of the sub string.
    * @param len: the length of the sub string.
    * @param dst: the string pointer which saved the sub string content.
    * @return the operation result.
    */
    bool StringSubString(const HcString *self, uint32_t begin, uint32_t len, HcString* dst);

    /*
    * Compare the string with another string.
    * @param self: self pointer.
    * @param dst: the pointer of another string.
    * @return the compare result.
    *  -1: self is smaller than dst
    *   0: self is equal with dst
    *   1: self is bigger than dst
    */
    int StringCompare(const HcString *self, const char* dst);

    /*
    * Create a string.
    * Notice: You should delete string when you don't need the string anymore.
    * @return the created string.
    */
    HcString CreateString(void);

    /*
    * Delete a string. In fact it will not destroy the string,
    * but only free the allocated memory of the string and reset the member's value
    * of the string. You can continue to use the string if you want.
    * Notice: You should delete the string when you don't need it any more to avoid memory leak.
    * @param str: The string you want to delete.
    */
    void DeleteString(HcString *str);

#ifdef __cplusplus
}
#endif
#endif
