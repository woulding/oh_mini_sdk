#!/usr/bin/env python3
# encoding=utf-8
# ============================================================================
# @brief    packet files
# ============================================================================

import os
import sys
import tarfile

PY_PATH = os.path.dirname(os.path.realpath(__file__))
sys.path.append(PY_PATH)
PKG_DIR = os.path.dirname(PY_PATH)
PKG_DIR = os.path.dirname(PKG_DIR)

from packet_create import create_sha_file
from packet_create import packet_bin

TOOLS_DIR = os.path.dirname(PKG_DIR)
SDK_DIR = os.path.dirname(TOOLS_DIR)
sys.path.append(os.path.join(SDK_DIR, "build", "script"))

# ws53
def make_all_in_one_packet(pack_style_str, extr_defines):
    # make all in one packet
    bin_dir = os.path.join(SDK_DIR, "output", "ws53", "acore", "boot_bin")
    loadboot = os.path.join(bin_dir, "loaderboot_sign.bin")
    loadboot_bx = loadboot + "|0x0|0x0|0"
    params = os.path.join(bin_dir, "root_params_sign.bin")
    params_bx = params + "|0x400000|0x1000|1"
    ssb = os.path.join(bin_dir, "ssb_sign.bin")
    ssb_bx = ssb + "|0x402000|0x6000|1"
    flashboot = os.path.join(bin_dir, "flashboot_sign.bin")
    flashboot_bx = flashboot + "|0x420000|0x10000|1"
    flashboot_bak = os.path.join(bin_dir, "flashboot_backup_sign.bin")
    flashboot_bak_bx = flashboot_bak + "|0x410000|0x10000|1"
    nv = os.path.join(SDK_DIR, "output", "ws53", "acore", "nv_bin", "ws53_all_nv.bin")
    nv_bx = nv + "|0x7FC000|0x4000|1"
    nv_bak = os.path.join(SDK_DIR, "output", "ws53", "acore", "nv_bin", "ws53_all_nv_factory.bin")
    nv_bak_bx = nv_bak + "|0x40C000|0x4000|1"
    # efuse bin
    efuse_bin = os.path.join(bin_dir, "efuse_cfg.bin")
    efuse_bx = efuse_bin + "|0x0|0x200000|3"

    app_bin = os.path.join(SDK_DIR, "output", "ws53", "acore", pack_style_str, f"{pack_style_str}_sign.bin")
    app_bx = app_bin + "|0x430000|0x240000|1"

    build_extr_defines = " ".join(sys.argv[3].split(","))

    if os.path.exists(app_bin):
        packet_post_agvs = list()
        packet_post_agvs.append(loadboot_bx)
        packet_post_agvs.append(params_bx)
        packet_post_agvs.append(ssb_bx)
        packet_post_agvs.append(flashboot_bx)
        packet_post_agvs.append(flashboot_bak_bx)
        packet_post_agvs.append(nv_bx)
        if "PACKET_NV_FACTORY" in build_extr_defines:
            print("nv factory pack")
            packet_post_agvs.append(nv_bak_bx)

        if pack_style_str == 'ws53_liteos_mfg':
            output_bin_dir = os.path.join(SDK_DIR, "output", "ws53", "acore")
            app_bin = os.path.join(output_bin_dir, "ws53_liteos_app", "ws53_liteos_app_sign.bin")
            app_bx = app_bin + f"|0x430000|0x240000|1"

            mfg_bin = os.path.join(SDK_DIR, "application", "ws53", "ws53_liteos_mfg", "ws53_liteos_mfg_sign.bin")
            mfg_bx = mfg_bin + f"|0x670000|{hex(0x183000)}|1" # 0x183000为产测分区B区大小
            packet_post_agvs.append(app_bx)
            packet_post_agvs.append(mfg_bx)
            fpga_fwpkg_all = os.path.join(SDK_DIR, "output", "ws53", "fwpkg", "pack_all_core", pack_style_str, f"{pack_style_str}_all_in_one.fwpkg")
            packet_bin(fpga_fwpkg_all, packet_post_agvs)
            return
        if "PACKET_MFG_BIN" in extr_defines:
            mfg_sign_bin = os.path.join(SDK_DIR, "application", "ws53", "ws53_liteos_mfg", "ws53_liteos_mfg_sign.bin")
            if os.path.exists(mfg_sign_bin):
                mfg_bx = mfg_sign_bin + f"|0x670000|{hex(0x183000)}|1" # 0x183000为产测分区B区大小
                packet_post_agvs.append(mfg_bx)
            else:
                print("error: don't find ws53-liteos-mfg-sign.bin...")
                exit(-1)
        else:
            application_mfg_bin = os.path.join(SDK_DIR, "output", "ws53", "pktbin", "ws53_liteos_mfg.bin")
            if os.path.exists(application_mfg_bin):
                os.remove(application_mfg_bin)
            cur_dir = os.getcwd()
            os.chdir(os.path.join(SDK_DIR, "output", "ws53"))
            if os.path.isfile('pktbin.zip'):
                os.remove('pktbin.zip')
            with tarfile.open('pktbin.zip', "w") as tar:
                for root, _, files in os.walk('./pktbin'):
                    for file in files:
                        file_path = os.path.join(root, file)
                        rel_path = os.path.relpath(file_path, './pktbin')
                        tar.add(file_path, arcname=rel_path)
            os.chdir(cur_dir)
        packet_post_agvs.append(app_bx)
        if "SUPPORT_EFUSE" in build_extr_defines or "PACKET_MFG_BIN" in build_extr_defines:
            print("efuse pack")
            packet_post_agvs.append(efuse_bx)
        fpga_fwpkg_all = os.path.join(SDK_DIR, "output", "ws53", "fwpkg", "pack_all_core", pack_style_str, f"{pack_style_str}_all_in_one.fwpkg")
        packet_bin(fpga_fwpkg_all, packet_post_agvs)

        packet_post_agvs = list()
        packet_post_agvs.append(loadboot_bx)
        packet_post_agvs.append(app_bx)
        fpga_loadapp_only_fwpkg = os.path.join(SDK_DIR, "output", "ws53", "fwpkg", "pack_all_core", pack_style_str, f"{pack_style_str}_load_only.fwpkg")
        packet_bin(fpga_loadapp_only_fwpkg, packet_post_agvs)


def is_packing_files_exist(soc, pack_style_str):
    return
