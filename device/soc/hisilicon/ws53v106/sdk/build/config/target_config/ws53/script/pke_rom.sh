#!/bin/sh
# Copyright (c) CompanyNameMagicTag 2023-2023. All rights reserved.
set -e

root_dir=$1
out_dir=${root_dir}/output/ws53/acore/pke_rom
rom_ver_dir=${root_dir}/output/ws53/rom_ver
create_hex_py=${root_dir}/build/script/utils/create_hex.py
objcopy_tool=${root_dir}/tools/bin/compiler/riscv/cc_riscv32_musl_b010/cc_riscv32_musl/bin/riscv32-linux-musl-objcopy
gcc_tool=${root_dir}/tools/bin/compiler/riscv/cc_riscv32_musl_b010/cc_riscv32_musl/bin/riscv32-linux-musl-gcc
rom_lib_c=${root_dir}/drivers/chips/ws53/rom/romboot/drivers/drivers/hal/security_unified/hal_cipher/pke/rom_lib.c
td_type_h=${root_dir}/drivers/chips/ws53/rom/romboot/middleware/utils/common_headers/native/td_type.h

if [ ! -d ${out_dir} ];then
    mkdir ${out_dir}
fi

cat ${rom_lib_c}|grep -Pzo ".*g_instr_rom\[\]\s*=\s*\{[\s\S]+\}\s*;"|sed 's/\x0//g' > ${out_dir}/rom_lib.c
rom_lib_file_path=${out_dir}/rom_lib.o
${gcc_tool} -include ${td_type_h} -c ${out_dir}/rom_lib.c -o ${rom_lib_file_path}
if [ -f ${rom_lib_file_path} ]; then
    ${objcopy_tool} -O binary -j "\.rodata" ${rom_lib_file_path} ${out_dir}/pke_rom_raw.bin
    dd if=${out_dir}/pke_rom_raw.bin of=${out_dir}/pke_rom.bin seek=0 conv=sync bs=3k count=1

    # generate hex
    python3 ${create_hex_py} ${out_dir}/pke_rom.bin ${out_dir}/S40ULPROM768X32_0SVTX8B1PD.hex

    # archive
    mkdir -p ${rom_ver_dir}/pke
    mkdir -p ${rom_ver_dir}/pke/raw_files
    cp -rf ${out_dir}/pke_rom_raw.bin ${rom_ver_dir}/pke/raw_files/
    cp -rf ${out_dir}/pke_rom.bin ${rom_ver_dir}/pke/raw_files/
    cp -rf ${out_dir}/S40ULPROM768X32_0SVTX8B1PD.hex ${rom_ver_dir}/pke/
fi


exit 0
