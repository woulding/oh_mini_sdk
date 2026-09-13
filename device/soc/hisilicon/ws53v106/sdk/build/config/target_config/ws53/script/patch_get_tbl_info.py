#!/usr/bin/env python3
# encoding=utf-8
# ============================================================================
# @brief    get patch tbl addr from map file, and writeback to cfg file.
# Copyright CompanyNameMagicTag 2022-2023. All rights reserved.
# ============================================================================
import struct
import ctypes
import sys
import os
import shutil
import traceback
import subprocess

if __name__ == "__main__":
    if(len(sys.argv) == 6):
        core = sys.argv[1]
        target_name = sys.argv[2]
        bin_name = sys.argv[3]
        patch_config_dir = sys.argv[4]
        map_dir = sys.argv[5]

        if os.path.exists(os.path.join(patch_config_dir, f'{target_name}.cfg')):
            patch_info = os.path.join(patch_config_dir, f'{target_name}.cfg')
        else:
            patch_info = os.path.join(patch_config_dir, f'{core}.cfg')

        if not os.path.exists(patch_info):
            print("%s is not exist!" % patch_info)
            sys.exit(1)

        map_file = os.path.join(map_dir, f'{bin_name}.map')
        if not os.path.exists(map_file):
            print("%s is not exist!" % map_file)
            sys.exit(1)

        # sed -n '/__patch_tbl_bin_offset__/p' xxx.map | awk -F " " '{print $1}'
        cmd = f"sed -n '/__patch_tbl_bin_offset__/p' {map_file} | awk '{{print $1}}'"
        output = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='utf-8')
        result = output.stdout.strip()

        if result == "":
            print("cannot find symbol __patch_tbl_bin_offset__")
            # do nothing
            sys.exit(0)

        result = result.replace("0x00000000", "0x")
        # sed -i '/^Patch_TBL_Address \+= / c\Patch_TBL_Address = 0xxxxx' xxx.cfg
        cmd = f"sed -i '/^Patch_TBL_Address \+= / c\Patch_TBL_Address = {result}' {patch_info}"
        os.system(cmd)

        # sed -n '/__patch_tbl_run_addr__/p' xxx.map | awk -F " " '{print $1}'
        cmd = f"sed -n '/__patch_tbl_run_addr__/p' {map_file} | awk '{{print $1}}'"
        output = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='utf-8')
        result = output.stdout.strip()

        if result == "":
            print("cannot find symbol __patch_tbl_run_addr__")
            # do nothing
            sys.exit(0)

        result = result.replace('0x00000000', '0x')
        # sed -i '/^Patch_TBL_Run_Address \+= / c\Patch_TBL_Run_Address = 0xxxxx' xxx.cfg
        cmd = f"sed -i '/^Patch_TBL_Run_Address \+= / c\Patch_TBL_Run_Address = {result}' {patch_info}"
        os.system(cmd)

        sys.exit(0)
    else:
        print(
            "Usage: %s <core> <target_name> <bin_name> <patch_confi_dir> <map_dir>"  % os.path.basename(sys.argv[0]))
        sys.exit(1)
