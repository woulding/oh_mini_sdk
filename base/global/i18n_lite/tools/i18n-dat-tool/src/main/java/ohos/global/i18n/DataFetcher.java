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

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.File;
import java.io.BufferedReader;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;
import java.util.logging.Level;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

import com.ibm.icu.util.ULocale;

import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

/**
 * This class is used to generate i18n.dat file
 *
 * @since 2022-8-22
 */
public class DataFetcher {
    private static final ReentrantLock LOCK = new ReentrantLock();
    private static final ArrayList<Fetcher> FETCHERS = new ArrayList<>();
    private static final ArrayList<String> SCRIPTS = new ArrayList<>(Arrays.asList(
        "", "Latn", "Hans", "Hant", "Qaag", "Cyrl", "Deva", "Guru"
    ));
    private static final ArrayList<String> DATA_TYPES = new ArrayList<>(Arrays.asList(
        "calendar-gregorian-monthNames-format-abbreviated", "calendar-gregorian-dayNames-format-abbreviated",
        "time-patterns", "date-patterns", "am-pm-markers", "plural", "number-format", "number-digit",
        "Time-separator", "default-hour", "stand-alone-abbr-month-names", "standalone-abbr-weekday-names",
        "format-wide-month-names", "hour-minute-secons-pattern", "full-medium-short-pattern",
        "format-wide-weeday-names", "standalone-wide-weekday-names", "standalone-wide-month-names",
        "elapsed-patterns", "week_data", "decimal_plural", "minus-sign"
    ));
    private static final HashMap<String, Integer> ID_MAP = new HashMap<>(64);
    private static final HashMap<String, Integer> LOCALES = new HashMap<>();
    private static final HashMap<Integer, ArrayList<LocaleConfig>> LOCALE_CONFIGS = new HashMap<>(64);
    private static final Logger LOG = Logger.getLogger("DataFetcher");
    private static int sStatus = 0;
    private static final Pattern RE_LANGUAGE = Pattern.compile("^([a-z]{2,3})-\\*$");
    private static final int MAX_TIME_TO_WAIT = 10;
    private static final String SEP = File.separator;
    private static final int CORE_POOL_SIZE = 1000;
    private static final int MAX_POOL_SIZE = 1000;
    private static final int QUEUE_CAPACITY = 2000;
    private static final Long KEEP_ALIVE_TIME = 1L;

    static {
        addFetchers();
    }

    private DataFetcher() {}

    /**
     *
     * Add all required locales from locale.txt and fetch its related data.
     */
    private static void addFetchers() {
        try (BufferedReader fLocales = new BufferedReader(new InputStreamReader(
                DataFetcher.class.getResourceAsStream("/locales.txt"),
                StandardCharsets.UTF_8))) {
            String line = "";
            int count = 0;
            ULocale[] availableLocales = ULocale.getAvailableLocales();
            while ((line = fLocales.readLine()) != null) {
                String tag = line.trim();
                if (LOCALES.containsKey(tag)) {
                    continue;
                }
                // special treatment to wildcard
                int tempCount = processWildcard(line, availableLocales, count);
                if (tempCount > count) {
                    count = tempCount;
                    continue;
                }
                if (!Utils.isValidLanguageTag(tag)) {
                    LOG.log(Level.SEVERE, String.format("wrong languageTag %s", tag));
                    sStatus = 1;
                    return;
                }
                FETCHERS.add(new Fetcher(tag, LOCK, ID_MAP));
                LOCALES.put(tag, count);
                ++count;
            }
        } catch (IOException e) {
            LOG.log(Level.SEVERE, "Add fetchers failed: Io exception");
            sStatus = 1;
        }
    }

    private static int processWildcard(String line, ULocale[] availableLocales, int count) {
        String tag = line.trim();
        int tempCount = count;
        if ("*".equals(line)) { // special treatment to wildcard xx-*
            for (ULocale loc : availableLocales) {
                String finalLanguageTag = loc.toLanguageTag();
                // now we assume en-001 as invalid locale,
                if (!LOCALES.containsKey(finalLanguageTag) && Utils.isValidLanguageTag(finalLanguageTag)) {
                    FETCHERS.add(new Fetcher(finalLanguageTag, LOCK, ID_MAP));
                    LOCALES.put(tag, tempCount);
                    ++tempCount;
                }
            }
            return tempCount;
        }
        Matcher matcher = RE_LANGUAGE.matcher(line);
        if (matcher.matches()) { // special treatment to wildcard language-*
            String baseName = matcher.group(1);
            for (ULocale loc : availableLocales) {
                String finalLanguageTag = loc.toLanguageTag();
                if (loc.getLanguage().equals(baseName) && !LOCALES.containsKey(finalLanguageTag) &&
                    Utils.isValidLanguageTag(finalLanguageTag)) {
                    FETCHERS.add(new Fetcher(finalLanguageTag, LOCK, ID_MAP));
                    LOCALES.put(tag, tempCount);
                    ++tempCount;
                }
            }
        }
        return tempCount;
    }

    private static boolean checkStatus() {
        return sStatus == 0;
    }

    private static int countData(Fetcher currentFetcher, int count,
            Fetcher fallbackFetcher, ArrayList<LocaleConfig> temp) {
        String fallbackData = null;
        for (int i = 0; i < Fetcher.getResourceCount(); i++) {
            String targetMetaData = Fetcher.getInt2Str().get(i);
            String myData = currentFetcher.datas.get(i);
            if (fallbackFetcher != null) {
                fallbackData = fallbackFetcher.datas.get(i);
            } else {
                fallbackData = null;
            }
            if (!myData.equals(fallbackData)) {
                temp.add(new LocaleConfig(targetMetaData, i, ID_MAP.get(myData)));
                ++count;
                currentFetcher.reservedAdd(1);
            } else {
                currentFetcher.reservedAdd(0);
            }
        }
        return count;
    }

    /**
     * If a locale's data equals to its fallback's data, this locale is excluded
     * if a meta data of a locale equals to its fallback's data, this meta data is excluded
     * validLocales keep track of how many locales will be available in dat file.
     * count indicates how many metaData in total will be available in dat file.
     *
     * @return Total number of meta data count
     */
    private static int buildLocaleConfigs() {
        Fetcher fallbackFetcher = null;
        int count = 0;
        for (Map.Entry<String, Integer> entry : LOCALES.entrySet()) {
            String languageTag = entry.getKey();
            int index = entry.getValue();
            Fetcher currentFetcher = FETCHERS.get(index);
            ArrayList<LocaleConfig> temp = new ArrayList<>();
            LOCALE_CONFIGS.put(index, temp);
            String fallbackLanguageTag = Utils.getFallback(languageTag);
            // now we need to confirm whether current fetcher's data should be write to i18n.dat
            // if current fetcher's fallback contains equivalent data, then we don't need current fetcher's data.
            if (!LOCALES.containsKey(fallbackLanguageTag) || fallbackLanguageTag.equals(languageTag)) {
                fallbackFetcher = null;
            } else {
                fallbackFetcher = FETCHERS.get(LOCALES.get(fallbackLanguageTag));
            }
            if (currentFetcher.equals(fallbackFetcher)) {
                currentFetcher.setIncluded(false);
            } else {
                count = countData(currentFetcher, count, fallbackFetcher, temp);
            }
        }
        return count;
    }

    private static int localeCompare(String locale1, String locale2) {
        String[] locale1Parts = locale1.split("-");
        String script1 = "";
        String region1 = "";
        if (locale1Parts.length == 2) {
            if (locale1Parts[1].length() == 2) {
                region1 = locale1Parts[1];
            } else {
                script1 = locale1Parts[1];
            }
        }
        if (locale1Parts.length == 3) {
            script1 = locale1Parts[1];
            region1 = locale1Parts[2];
        }
        String[] locale2Parts = locale2.split("-");
        String script2 = "";
        String region2 = "";
        if (locale2Parts.length == 2) {
            if (locale2Parts[1].length() == 2) {
                region2 = locale2Parts[1];
            } else {
                script2 = locale2Parts[1];
            }
        }
        if (locale2Parts.length == 3) {
            script2 = locale2Parts[1];
            region2 = locale2Parts[2];
        }
        String lang1 = locale1Parts[0];
        String lang2 = locale2Parts[0];
        if (!lang1.equals(lang2)) {
            return lang1.compareTo(lang2);
        }
        if (!script1.equals(script2)) {
            return SCRIPTS.indexOf(script1) - SCRIPTS.indexOf(script2);
        }
        return region1.compareTo(region2);
    }

    private static void writeLocales() {
        JSONArray array = new JSONArray();
        ArrayList<String> locales = new ArrayList<>(LOCALES.keySet());
        locales.sort(new Comparator<String>() {
            @Override
            public int compare(String o1, String o2) {
                return localeCompare(o1, o2);
            }
        });
        for (String locale : locales) {
            array.add(locale);
        }
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("locales", locales);

        File outputDir = new File("resources");
        File localesFile = new File(outputDir, "locales.json");
        if (!outputDir.exists()) {
            outputDir.mkdirs();
        }
        try (OutputStreamWriter osw = new OutputStreamWriter(
            new FileOutputStream(localesFile), StandardCharsets.UTF_8)) {
            osw.write(jsonObject.toString(2));
            osw.flush();
            osw.close();
        } catch (IOException e) {
            LOG.log(Level.SEVERE, 
                    "Write locales.json failed: IO exception. Path: " + localesFile.getAbsolutePath(), e);
        }
    }

    private static void writeData(String fileName, int index) {
        JSONObject object = new JSONObject();
        for (Fetcher fetcher : FETCHERS) {
            String language = fetcher.languageTag;
            String data = fetcher.datas.get(index);
            if (data.length() == 0 || !fetcher.getIncluded() || fetcher.reservedGet(index) == 0) {
                continue;
            }
            String[] values = data.split("_", -1);
            JSONArray array = new JSONArray();
            for (String val : values) {
                array.add(val);
            }
            object.put(language, array);
        }

        File outputDir = new File("resources");
        File localesFile = new File(outputDir, fileName + ".json");
        if (!outputDir.exists()) {
            outputDir.mkdirs();
        }

        try (OutputStreamWriter osw = new OutputStreamWriter(
            new FileOutputStream(localesFile), StandardCharsets.UTF_8)) {
            osw.write(object.toString(2));
            osw.flush();
            osw.close();
        } catch (IOException e) {
            LOG.log(Level.SEVERE, "Write file failed: IO exception. Path: " + localesFile.getAbsolutePath(), e);
        }
    }

    private static JSONObject getMeasureDataUnit(String[] values) {
        String[] units = values[1].split("\\|");
        String[] types = {"short", "medium", "long", "full"};
        int pluralNum = 6;
        int start = 4; // 4 is unit start index

        JSONObject unitsJson = new JSONObject();
        for (int i = 0; i < units.length; i++) {
            JSONObject typedUnitsJson = new JSONObject();
            for (int j = 0; j < types.length; j++) {
                JSONArray pluralUnitJson = new JSONArray();
                for (int k = 0; k < pluralNum; k++) {
                    pluralUnitJson.add(values[start]);
                    start++;
                }
                typedUnitsJson.put(types[j], pluralUnitJson);
            }
            unitsJson.put(units[i], typedUnitsJson);
        }
        return unitsJson;
    }

    private static void writeMeasureData() {
        JSONObject object = new JSONObject();
        for (Fetcher fetcher : FETCHERS) {
            // 22 is measure data index
            String data = fetcher.datas.get(22);
            if (data.length() == 0) {
                continue;
            }
            String[] values = data.split("_", -1);
            JSONObject languageJson = new JSONObject();
            languageJson.put("unit_num", values[0]);  // 0 is unit num index in measure data
            languageJson.put("unit_set", values[1]);  // 1 is unit set index in measure data
            languageJson.put("pattern", values[2]);  // 2 is pattern index in measure data
            languageJson.put("order", values[3]);  // 3 is order index in measure data

            JSONObject units = getMeasureDataUnit(values);
            languageJson.put("units", units);
            object.put(fetcher.languageTag, languageJson);
        }

        File outputDir = new File("resources");
        File localesFile = new File(outputDir, "measure-format-patterns.json");
        if (!outputDir.exists()) {
            outputDir.mkdirs();
        }

        try (OutputStreamWriter osw = new OutputStreamWriter(
            new FileOutputStream(localesFile), StandardCharsets.UTF_8)) {
            osw.write(object.toString(2));
            osw.flush();
            osw.close();
        } catch (IOException e) {
            LOG.log(Level.SEVERE, "Write measure data failed. Path: " + localesFile.getAbsolutePath(), e);
        }
    }

    private static void writeResourceItems() {
        JSONObject object = new JSONObject();
        for (int i = 0; i < DATA_TYPES.size(); i++) {
            object.put(DATA_TYPES.get(i), i);
        }
        object.put("measure-format-patterns", DATA_TYPES.size());

        File outputDir = new File("resources");
        File localesFile = new File(outputDir, "resource_items.json");
        if (!outputDir.exists()) {
            outputDir.mkdirs();
        }

        try (OutputStreamWriter osw = new OutputStreamWriter(
            new FileOutputStream(localesFile), StandardCharsets.UTF_8)) {
            osw.write(object.toString(2));
            osw.flush();
            osw.close();
        } catch (IOException e) {
            LOG.log(Level.SEVERE, "Write resource items failed. Path: " + localesFile.getAbsolutePath(), e);
        }
    }

    /**
     * Main function used to generate i18n.dat file
     *
     * @param args Main function's argument
     */
    public static void main(String[] args) {
        if (!Fetcher.isFetcherStatusOk() || !checkStatus()) {
            return;
        }
        ThreadPoolExecutor exec = new ThreadPoolExecutor(CORE_POOL_SIZE, MAX_POOL_SIZE,
            KEEP_ALIVE_TIME, TimeUnit.SECONDS, new ArrayBlockingQueue<>(QUEUE_CAPACITY));
        for (Fetcher fe : FETCHERS) {
            exec.execute(fe);
        }
        exec.shutdown();
        try {
            exec.awaitTermination(MAX_TIME_TO_WAIT, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            LOG.log(Level.SEVERE, "main class in DataFetcher interrupted");
        }
        buildLocaleConfigs(); // every metaData needs 6 bytes
        for (Fetcher fetcher : FETCHERS) {
            if (!fetcher.getIncluded()) {
                LOCALES.remove(fetcher.languageTag);
            }
        }
        FETCHERS.sort(null);

        writeLocales();
        for (int i = 0; i < DATA_TYPES.size(); i++) {
            writeData(DATA_TYPES.get(i), i);
        }
        writeMeasureData();
        writeResourceItems();
    }
}