#!/bin/sh
# Copyright (c) CompanyNameMagicTag 2023-2023. All rights reserved.
set -e 

root_dir=$1
target_name=$2
ssb=${root_dir}/output/ws53/acore/ws53-ssb/ssb_sign.bin
ssb_bin=${root_dir}/output/ws53/acore/ws53-ssb/ssb.bin
flashboot_a=${root_dir}/output/ws53/acore/ws53-flashboot/flashboot_sign.bin
flashboot_bin=${root_dir}/output/ws53/acore/ws53-flashboot/flashboot.bin
flashboot_b=${root_dir}/output/ws53/acore/ws53-flashboot/flashboot_backup_sign.bin
loaderboot=${root_dir}/output/ws53/acore/ws53-loaderboot/loaderboot_sign.bin
loaderboot_bin=${root_dir}/output/ws53/acore/ws53-loaderboot/loaderboot.bin
param_bin=${root_dir}/output/ws53/acore/param_bin/root_params_sign.bin
pke_rom=${root_dir}/output/ws53/acore/pke_rom/pke_rom.bin
romboot=${root_dir}/output/ws53/acore/ws53-romboot/romboot.bin
sdk_ccore_app=${root_dir}/output/ws53/control_core/ws53_control_app/control_ws53.bin
sdk_ccore_app_lite=${root_dir}/output/ws53/control_core/ws53_control_app_lite/control_ws53_lite.bin
efuse_bin=${root_dir}/output/ws53/acore/ws53_liteos_app/efuse_cfg.bin
bootbin=${root_dir}/interim_binary/ws53/bin/boot_bin
ccore_src_hdb=${root_dir}/output/ws53/build_hso_cfg/hso_database/xml/base/control_core
ccore_dst_hdb=${root_dir}/interim_binary/ws53/ccore/build_hso_cfg/hso_database/xml/base

if [ ! -d ${bootbin} ]; then
    mkdir -p ${bootbin}
fi

if [ -f ${ssb} ] && [ -f $bootbin"/ssb_sign.bin" ]; then
    cp $ssb $bootbin
fi

if [ -f ${ssb_bin} ] && [ -f $bootbin"/ssb.bin" ]; then
    cp $ssb_bin $bootbin
fi

if [ -f ${flashboot_bin} ] && [ -f $bootbin"/flashboot.bin" ]; then
    cp $flashboot_bin $bootbin
fi

if [ -f ${loaderboot_bin} ] && [ -f $bootbin"/loaderboot.bin" ]; then
    cp $loaderboot_bin $bootbin
fi

if [ -f ${flashboot_a} ] && [ -f $bootbin"/flashboot_sign.bin" ]; then
    cp $flashboot_a $bootbin
fi

if [ -f ${flashboot_b} ] && [ -f $bootbin"/flashboot_backup_sign.bin" ]; then
    cp $flashboot_b $bootbin
fi

if [ -f ${loaderboot} ] && [ -f $bootbin"/loaderboot_sign.bin" ]; then
    cp $loaderboot $bootbin
fi

if [ -f ${param_bin} ] && [ -f $bootbin"/root_params_sign.bin" ]; then
    cp $param_bin $bootbin
fi

if [ -f ${romboot} ] && [ -f $bootbin"/romboot.bin" ]; then
    cp $romboot $bootbin
fi

if [ -f ${sdk_ccore_app} ] && [ -f $bootbin"/control_ws53.bin" ]; then
    cp $sdk_ccore_app $bootbin
fi

if [ -f ${sdk_ccore_app_lite} ]; then
    cp $sdk_ccore_app_lite $bootbin
fi

if [ -f ${efuse_bin} ] && [ -f $bootbin"/efuse_cfg.bin" ]; then
    cp $efuse_bin $bootbin
fi

if [ $target_name == "ws53_control_app" ] && [ -d $ccore_src_hdb ]; then
    if [ ! -d $ccore_dst_hdb ]; then
        mkdir -p $ccore_dst_hdb
    fi
    cp -r $ccore_src_hdb $ccore_dst_hdb
fi

exit 0
