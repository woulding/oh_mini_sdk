#!/usr/bin/env python3
# coding=utf-8
# The build entrance of UniProton.

#
# Copyright (c) 2021-2023 Huawei Device Co., Ltd.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import os


build_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
home_path = os.path.dirname(build_dir)
config_dir = os.path.join(home_path,'config.xml')
kbuild_path = '%s/cmake/common/build_auxiliary_script' % home_path

cpus_ = {'all': ['clean', 'm4', 'raspi4', 'hi3093'],
         'clean':['clean'],
         'm4': ['m4'],
         'raspi4': ['raspi4'],
         'hi3093': ['hi3093'],
         }

cpu_plat = {'m4': ['cortex'],
            'raspi4': ['armv8'],
            'hi3093': ['armv8'],
           }
