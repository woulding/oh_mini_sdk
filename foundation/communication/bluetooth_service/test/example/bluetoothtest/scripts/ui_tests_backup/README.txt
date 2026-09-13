Copyright (C) 2022 Huawei Device Co., Ltd.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

UiTest sources (@ohos.UiTest) live under entry ohosTest:
  entry/src/ohosTest/ets/uitest/
Hypium entry is entry/src/ohosTest/ets/apitest/List.test.ets (see entry/src/ohosTest/ets/uitest/DEPLOY.txt).

This directory keeps copies of generated files and main_page_control_manifest.json for regeneration:
  python3 scripts/inject_main_page_control_ids.py
  python3 scripts/gen_main_page_control_ui_tests.py
Then sync outputs into entry/src/ohosTest/ets/uitest/ (or adjust generator OUT_DIR).

Previously these files were kept here because compiling all ohosTest sources pulled UiTest into the
same test HAP as API-only Hypium; the uitest module avoids that split.
