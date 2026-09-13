/**
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

/**
 * Shared helpers for main-module page control UiTest (Hypium).
 * EntryAbility loads route from want.parameters.testTargetPage (see entry EntryAbility.ts).
 */
import abilityDelegatorRegistry from '@ohos.app.ability.abilityDelegatorRegistry';
import { Want } from '@kit.AbilityKit';
import { Driver, ON } from '@ohos.UiTest';

export const MAIN_BUNDLE: string = 'com.example.myapplicationbt';
export const ENTRY_ABILITY: string = 'EntryAbility';

function delayMs(ms: number): Promise<void> {
  return new Promise<void>((resolve: (v?: void) => void) => {
    setTimeout((): void => {
      resolve();
    }, ms);
  });
}

export async function startMainPage(route: string): Promise<void> {
  const delegator = abilityDelegatorRegistry.getAbilityDelegator();
  const want: Want = {
    bundleName: MAIN_BUNDLE,
    abilityName: ENTRY_ABILITY,
    parameters: {
      testTargetPage: route
    }
  };
  try {
    await delegator.startAbility(want);
  } catch (_e) {
    console.error('[MainPageControlUi] startAbility failed');
  }
  await delayMs(1200);
}

export async function assertControlVisible(controlId: string): Promise<void> {
  const driver = Driver.create();
  const on = ON.id(controlId);
  await driver.assertComponentExist(on);
}
