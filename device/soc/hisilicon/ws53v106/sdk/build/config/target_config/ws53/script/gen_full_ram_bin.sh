#!/bin/sh
# Copyright (c) CompanyNameMagicTag 2023-2023. All rights reserved.
set -e

root_dir=$1
objcopy=${root_dir}/tools/bin/compiler/riscv/cc_riscv32_musl_b090/cc_riscv32_musl/bin/riscv32-linux-musl-objcopy
acore_part1_bin=${root_dir}/output/ws53/acore/ws53_liteos_for_sw21/acore_dtcm.bin
acore_part2_bin=${root_dir}/output/ws53/acore/ws53_liteos_for_sw21/acore_itcm.bin
ccore_part1_bin=${root_dir}/output/ws53/control_core/ws53_control_for_sw21/ccore_rambin_part1.bin
ccore_part2_bin=${root_dir}/output/ws53/control_core/ws53_control_for_sw21/ccore_rambin_part2.bin
acore_elf=${root_dir}/output/ws53/acore/ws53_liteos_for_sw21/application.elf
ccore_elf=${root_dir}/output/ws53/control_core/ws53_control_for_sw21/control_ws53.elf

py3=/usr/bin/python3
gen_patch_py=${root_dir}/build/script/patch/patch_riscv.py
acore_bin_dir=${root_dir}/output/ws53/acore/ws53_liteos_for_sw21
ccore_bin_dir=${root_dir}/output/ws53/control_core/ws53_control_for_sw21
acore_patch_config_dir=${root_dir}/build/config/target_config/ws53/patch_config
ccore_patch_config_dir=${ccore_bin_dir}/patch_config

if [ -f ${ccore_elf} ]; then
    $objcopy -O binary -j .trampoline -j .romdata -j .rom_ram_cb_text -j .sramtext -j .data -j .patch $ccore_elf $ccore_part1_bin
    $objcopy -O binary -j .startup -j .text $ccore_elf $ccore_part2_bin

    pushd ${ccore_bin_dir}
    ${py3} ${gen_patch_py} $ccore_part1_bin control_ws53_rom.bin control_ws53.nm ${ccore_patch_config_dir} control_core ws53_control_for_sw21 ${ccore_bin_dir}
    popd
fi

if [ -f ${acore_elf} ]; then
    $objcopy -O binary -j .data $acore_elf $acore_part1_bin
    $objcopy -O binary -R .stacks -R .plt_sramdata -R .wifi_sramdata -R .plt_flashdata -R .wifi_flashdata -R .btc_flashdata -R .bth_flashdata -R .data -R .plt_srambss -R .wifi_srambss -R .plt_flashbss -R .wifi_flashbss -R .btc_flashbss -R .bth_flashbss -R .bss -R .heap $acore_elf $acore_part2_bin

    pushd ${acore_bin_dir}
    ${py3} ${gen_patch_py} $acore_part2_bin application_rom.bin application.nm ${acore_patch_config_dir} acore ws53_liteos_for_sw21 ${acore_bin_dir}
    popd
fi

exit 0
