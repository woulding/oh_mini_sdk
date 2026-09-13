/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 *
 * You may not use this file except in compliance with the License.
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
 * 直方图统计模块的 TypeScript 声明文件
 * 提供各种类型的数据添加和统计功能
 */

declare namespace histogram {
    /**
     * 添加布尔类型样本
     * @param sample 样本值，0 或 1
     * @returns 返回值（具体含义取决于 NAPI 实现）
     */
    function AddBoolean(name: string, sample: number): number;
  
    /**
     * 添加枚举类型样本
     * @param sample 样本值
     * @param boundary 边界值（枚举范围）
     * @returns 返回值（具体含义取决于 NAPI 实现）
     */
    function AddEnumeration(name: string, sample: number, boundary: number): number;
  
    /**
     * 添加自定义计数区间样本
     * @param sample 样本值
     * @param min 最小值
     * @param max 最大值
     * @param bucketCount 桶数量（区间数量）
     * @returns 返回值（具体含义取决于 NAPI 实现）
     */
    function AddCustomCounts(
      name: string,
      sample: number,
      min: number,
      max: number,
      bucketCount: number
    ): number;
  
    /**
     * 添加时间类型样本
     * @param sample 时间值（毫秒）
     * @returns 返回值（具体含义取决于 NAPI 实现）
     */
    function AddTimes(name: string, sample: number): number;
  
    /**
     * 添加百分比类型样本
     * @param sample 百分比值（0-100）
     * @returns 返回值（具体含义取决于 NAPI 实现）
     */
    function AddPercentage(name: string, sample: number): number;
  }
  
  export default histogram;