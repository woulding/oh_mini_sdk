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

import java.util.HashMap;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.logging.Logger;
import java.util.logging.Level;

/**
 * This class is used to extract measure format pattern data related to a locale
 *
 * @since 2022-8-22
 */
public class MeasureFormatPatternFetcher {
    private static MeasureFormatPatternFetcher patternFetcher = new MeasureFormatPatternFetcher();
    private static final Logger logger = Logger.getLogger("MeasureFormatPatternFetcher");
    private static final String PATH = "/measure_format_patterns.txt";

    static {
        patternFetcher.init();
    }

    private HashMap<String, String> locale2Pattern;

    private MeasureFormatPatternFetcher() {}

    /**
     * Return singleton instance;
     *
     * @return patternFetcher;
     */
    public static MeasureFormatPatternFetcher getInstance() {
        return patternFetcher;
    }

    /**
     * Get measure format pattern related to locale.
     *
     * @param locale Indicates which locale's data will be retrived.
     * @return measure format pattern related to locale.
     */
    public String get(String locale) {
        String pattern = locale2Pattern.get(locale);
        if (pattern == null) {
            return "";
        }
        return pattern;
    }

    private void init() {
        try (InputStream inputStream = MeasureFormatPatternFetcher.class.getResourceAsStream(PATH);
            BufferedReader fin = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.UTF_8))) {

            if (inputStream == null) {
                throw new IOException("Resource '" + PATH + "' not found in classpath.");
            }

            locale2Pattern = new HashMap<>();
            String line = "";
            while ((line = fin.readLine()) != null) {
                String[] temp = getPatterns(line);
                if (temp.length == 2) {
                    locale2Pattern.put(temp[0], temp[1]);
                }
            }
        } catch (IOException e) {
            logger.log(Level.SEVERE, "Init error");
        }
    }

    private String[] getPatterns(String line) {
        String[] result = new String[2];
        String trimedLine = line.trim();
        String[] localeAndPatterns = trimedLine.split(" ", 2); // Split into 2 parts
        if (localeAndPatterns.length != 2) {
            logger.log(Level.SEVERE, "Init error");
            return new String[0];
        }
        result[0] = localeAndPatterns[0];
        String[] patterns = localeAndPatterns[1].split(", ");
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < patterns.length; ++i) {
            if (patterns[i].length() > 2) {
                int length = patterns[i].length();
                sb.append(patterns[i].substring(1, length - 1));
            }
            if (i != patterns.length) {
                sb.append(FileConfig.SEP);
            }
        }
        result[1] = sb.toString();
        return result;
    }
}