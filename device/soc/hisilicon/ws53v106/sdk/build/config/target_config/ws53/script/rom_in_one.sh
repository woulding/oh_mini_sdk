#!/bin/sh
# Copyright (c) CompanyNameMagicTag 2023-2023. All rights reserved.
set -e

root_dir=$1
bin_name=$2
target_name=$3
core=$4
out_dir=${root_dir}/output/ws53/${core}/${target_name}
rom_ver_dir=${root_dir}/output/ws53/rom_ver
romboot_bin=${root_dir}/output/ws53/acore/ws53-romboot/romboot.bin
create_hex_py=${root_dir}/build/script/utils/create_hex.py

if [ "${core}" = "acore" -a "${target_name}" = "liteos_ws53" ];then
    if [ ! -f ${romboot_bin} ];then
        echo "[*] romboot not found, codepoint files will not be one!"
        exit 0
    fi

    pushd ${out_dir}
        # Fill romboot bin to 39K
        dd if=${romboot_bin} of=romboot.39K.bin seek=0 conv=sync bs=39K count=1

        # All in one rompack file
        cat romboot.39K.bin ${bin_name}_rom.bin > ${bin_name}_rompack_tmp.bin

        dd if=${bin_name}_rompack_tmp.bin of=${bin_name}_rompack.bin seek=0 conv=sync bs=64k count=1
        dd if=${bin_name}_rompack.bin of=S40ULPROM8192X32_0SVTX16B4PD.bin bs=32k count=1
        python3 ${create_hex_py} S40ULPROM8192X32_0SVTX16B4PD.bin S40ULPROM8192X32_0SVTX16B4PD.hex

        dd if=${bin_name}_rompack.bin of=S40ULPROM8192X32_1SVTX16B4PD.bin bs=32k count=1 skip=1
        python3 ${create_hex_py} S40ULPROM8192X32_1SVTX16B4PD.bin S40ULPROM8192X32_1SVTX16B4PD.hex

        # archive
        mkdir -p ${rom_ver_dir}/acore
        mkdir -p ${rom_ver_dir}/acore/raw_files

        cp -rf ${bin_name}_rom.bin ${rom_ver_dir}/acore/raw_files/
        cp -rf ${bin_name}_rom.hex ${rom_ver_dir}/acore/raw_files/
        cp -rf romboot.39K.bin ${rom_ver_dir}/acore/raw_files/
        cp -rf ${bin_name}_rompack.bin ${rom_ver_dir}/acore/raw_files/
        cp -rf S40ULPROM8192X32_0SVTX16B4PD.bin ${rom_ver_dir}/acore/raw_files/
        cp -rf S40ULPROM8192X32_1SVTX16B4PD.bin ${rom_ver_dir}/acore/raw_files/

        cp -rf S40ULPROM8192X32_0SVTX16B4PD.hex ${rom_ver_dir}/acore/
        cp -rf S40ULPROM8192X32_1SVTX16B4PD.hex ${rom_ver_dir}/acore/
    popd
fi

# C核填充切分
if [ "${core}" = "control_core" -a "${target_name}" = "control_ws53" ];then
    pushd ${out_dir}
        adapt_rom_dir=${out_dir}/adapt_rom_bin
        mkdir -p ${adapt_rom_dir}
        cp ${bin_name}_rom.bin ${adapt_rom_dir}/
        cd ${adapt_rom_dir}
        dd if=${bin_name}_rom.bin of=${bin_name}_rom.288K.bin bs=1k count=288 seek=0 conv=sync
        python3 ${create_hex_py} ${bin_name}_rom.288K.bin ${bin_name}_rom.288K.hex
        i=0
        awk '{print $0.hex > NR%2.hex}' ${bin_name}_rom.288K.hex
        mv 1 temp_0.hex;mv 0 temp_1.hex;
        # C核切分
        for i in {0..3};do
            sed -n "$(($i * 8192+1)),$((($i + 1)*8192))p" temp_0.hex > S40ULPROM8192X32_$(($i * 2+3))SVTX16B4PD.hex
            sed -n "$(($i * 8192+1)),$((($i + 1)*8192))p" temp_1.hex > S40ULPROM8192X32_$(($i * 2+4))SVTX16B4PD.hex
        done
        tail -n 4096 temp_0.hex  > S40ULPROM4096X32_0SVTX16B2PD.hex
        tail -n 4096 temp_1.hex  > S40ULPROM4096X32_1SVTX16B2PD.hex

        # archive
        mkdir -p ${rom_ver_dir}/ccore
        mkdir -p ${rom_ver_dir}/ccore/raw_files

        cp -rf ${bin_name}_rom.bin ${rom_ver_dir}/ccore/raw_files/
        cp -rf ${bin_name}_rom.288K.bin ${rom_ver_dir}/ccore/raw_files/
        cp -rf ${bin_name}_rom.288K.hex ${rom_ver_dir}/ccore/raw_files/

        cp -rf S40ULPROM4096X32_0SVTX16B2PD.hex ${rom_ver_dir}/ccore
        cp -rf S40ULPROM4096X32_1SVTX16B2PD.hex ${rom_ver_dir}/ccore
        cp -rf S40ULPROM8192X32_10SVTX16B4PD.hex ${rom_ver_dir}/ccore
        cp -rf S40ULPROM8192X32_3SVTX16B4PD.hex ${rom_ver_dir}/ccore
        cp -rf S40ULPROM8192X32_4SVTX16B4PD.hex ${rom_ver_dir}/ccore
        cp -rf S40ULPROM8192X32_5SVTX16B4PD.hex ${rom_ver_dir}/ccore
        cp -rf S40ULPROM8192X32_6SVTX16B4PD.hex ${rom_ver_dir}/ccore
        cp -rf S40ULPROM8192X32_7SVTX16B4PD.hex ${rom_ver_dir}/ccore
        cp -rf S40ULPROM8192X32_8SVTX16B4PD.hex ${rom_ver_dir}/ccore
        cp -rf S40ULPROM8192X32_9SVTX16B4PD.hex ${rom_ver_dir}/ccore
    popd
fi
