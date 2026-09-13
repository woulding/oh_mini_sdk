/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

package ohos.global.i18n;

/**
 * Represents a meta data config in dat file
 *
 * @since 2022-8-22
 */
public class LocaleConfig {
    /** Meata data's name for example calendar/gregorian/monthNames/format/abbreviated */
    public final String name;

    /** Meta data's index in str2Int */
    public final int nameId;

    /** Meta data's index in sIdMap */
    public final int stringId;

    /**
     * Constructor of class LocaleConfig
     *
     * @param str Meata data's name
     * @param nameId Meta data's index in str2Int
     * @param stringId Meta data's index in sIdMap
     */
    public LocaleConfig(String str, int nameId, int stringId) {
        this.name = str;
        this.nameId = nameId;
        this.stringId = stringId;
    }
}
