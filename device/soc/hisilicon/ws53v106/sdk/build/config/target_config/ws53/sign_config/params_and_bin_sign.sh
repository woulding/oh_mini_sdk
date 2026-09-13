#!/bin/bash

set -e

script_dir=$(cd $(dirname $0); pwd)
pushd $script_dir
target=$1
bin_name=$2

sign_tool=../../../../../tools/bin/sign_tool/sign_tool_pltuni
pack_tool=../../../../script/param_packet.py
out_put=../../../../../output/ws53/acore
ccore_out=../../../../../output/ws53/control_core
inter_dir=../../../../../interim_binary/ws53/bin/boot_bin
boot_bin=../../../../../output/ws53/acore/boot_bin
pktbin=../../../../../output/ws53/pktbin
efuse_csv=../script/efuse.csv

generate_fill_bin()
{
    size=$1
    output_file=$2
    dd if=/dev/zero bs=1 count=$size | tr '\000' '\377' > $output_file
}

#Generate param.bin
python3 $pack_tool ../param_sector/param_sector.json params.bin
if [ -f params.bin ]; then
    echo "params.bin generate succed!!!"
    #sign params.bin
    $sign_tool 0 param_bin_ecc.cfg
    echo "params_sign.bin generate succed!!!"
    #Generate root public key
    { # try
        $sign_tool 1 root_pubk.cfg
    } || { # catch
        echo "generate fill root_pubk.bin"
        generate_fill_bin 128 root_pubk.bin
    }
    #packet root public key and param.bin
    cat root_pubk.bin params_sign.bin > root_params_sign.bin
    echo "root_params.bin generate succed!!!"
fi

if [ ! -d ${boot_bin} ]; then
    mkdir -p $boot_bin
    cp -r $inter_dir ${boot_bin%/*}
fi
rm -rf $pktbin
mkdir $pktbin


if [ -f "root_params_sign.bin" ]; then
    cp "root_params_sign.bin" $boot_bin
fi

padd_align_64byte()
{
    input_file=$1
    tmp_file=$input_file.tmp
    size=`wc -c < $input_file`
    block_cnt=`expr $size / 64 + 1`
    dd if=$input_file of=$tmp_file bs=64c seek=0 count=$block_cnt conv=sync
    mv $tmp_file $input_file
}

#sign ssb
if [ -f $out_put"/ws53-ssb/ssb.bin" ]; then
    padd_align_64byte $out_put"/ws53-ssb/ssb.bin"
    $sign_tool 0 ssb_ws53_ecc.cfg
    cp $out_put"/ws53-ssb/ssb_sign.bin" $boot_bin
    echo "ssb_sign.bin generate succed!!!"
fi

if [ ! -f $out_put"/ws53-ssb/ssb.bin" ] && [ -f $inter_dir"/ssb.bin" ]; then
    mkdir -p "$out_put/ws53-ssb"
    cp $inter_dir"/ssb.bin" $out_put"/ws53-ssb"
    echo "copy ssb.bin generate succed!!!"
    padd_align_64byte $out_put"/ws53-ssb/ssb.bin"
    $sign_tool 0 ssb_ws53_ecc.cfg
    cp $out_put"/ws53-ssb/ssb_sign.bin" $boot_bin
    rm -rf $out_put"/ws53-ssb"
fi

#sign flash boot
if [ -f $out_put"/ws53-flashboot/flashboot.bin" ]; then
    padd_align_64byte $out_put"/ws53-flashboot/flashboot.bin"
    $sign_tool 0 flashboot_ws53_ecc.cfg
    $sign_tool 0 flashboot_ws53_bak_ecc.cfg
    echo "flash_sign.bin generate succed!!!"
fi

if [ -f $out_put"/ws53-flashboot/flashboot.bin" ]; then
    cp $out_put"/ws53-flashboot/flashboot_sign.bin" $boot_bin
    cp $out_put"/ws53-flashboot/flashboot_backup_sign.bin" $boot_bin
fi

#sign ws53_flash_aging_test
if [ -f $out_put"/ws53-flash-aging-test/ws53_flash_aging_test.bin" ]; then
    padd_align_64byte $out_put"/ws53-flash-aging-test/ws53_flash_aging_test.bin"
    $sign_tool 0 flash_againe_test_ecc.cfg
    echo "ws53_flash_aging_test_sign.bin generate succed!!!"
fi

#sign loaderboot
if [ -f $out_put"/ws53-loaderboot/loaderboot.bin" ]; then
    dd if=$out_put"/ws53-loaderboot/loaderboot.bin" of=$out_put"/ws53-loaderboot/loaderboot.28k.bin" bs=28k seek=0 count=1 conv=sync
    mv $out_put"/ws53-loaderboot/loaderboot.28k.bin" $out_put"/ws53-loaderboot/loaderboot.bin" 
    $sign_tool 0 loaderboot_ws53_ecc.cfg
    echo "loaderboot_sign.bin generate succed!!!"
    #pack root public bin and loaderboot
    cat root_pubk.bin loaderboot_sign.bin > $out_put"/ws53-loaderboot/loaderboot_sign.bin"
    cp $out_put"/ws53-loaderboot/loaderboot_sign.bin" $boot_bin
    echo "root_loaderboot_sign.bin generate succed!!!"
    rm -rf loaderboot_sign.bin
fi

if [ ! -f $out_put"/ws53-loaderboot/loaderboot.bin" ] && [ -f $inter_dir"/loaderboot.bin" ]; then
    mkdir -p "$out_put/ws53-loaderboot"
    cp $inter_dir"/loaderboot.bin" $out_put"/ws53-loaderboot"
    echo "copy ws53-loaderboot generate succed!!!"
    dd if=$out_put"/ws53-loaderboot/loaderboot.bin" of=$out_put"/ws53-loaderboot/loaderboot.28k.bin" bs=28k seek=0 count=1 conv=sync
    mv $out_put"/ws53-loaderboot/loaderboot.28k.bin" $out_put"/ws53-loaderboot/loaderboot.bin" 
    $sign_tool 0 loaderboot_ws53_ecc.cfg
    echo "loaderboot_sign.bin generate succed!!!"
    #pack root public bin and loaderboot
    cat root_pubk.bin loaderboot_sign.bin > $boot_bin"/loaderboot_sign.bin"
    echo "root_loaderboot_sign.bin generate succed!!!"
    rm -rf loaderboot_sign.bin
    rm -rf $out_put"/ws53-loaderboot"
fi

if [ -f $inter_dir"/control_ws53.bin" ] && [ ! -f $ccore_out"/ws53_control_app/control_ws53.bin" ]; then
    mkdir -p $ccore_out"/ws53_control_app"
    cp $inter_dir"/control_ws53.bin" $ccore_out"/ws53_control_app/control_ws53.bin"
    echo "copy control_ws53.bin generate succed!!!"
    padd_align_64byte $ccore_out"/ws53_control_app/control_ws53.bin"
    $sign_tool 0 ws53_control_ecc_app.cfg
    cp $ccore_out"/ws53_control_app/control_ws53_sign.bin" $boot_bin
    rm -rf $ccore_out"/ws53_control_app"
    echo "control_ws53_sign.bin generate succed!!!"
fi

#sign ws53_liteos_mfg
if [ -f $out_put"/../../../application/ws53/ws53_liteos_mfg/ws53_liteos_mfg.bin" ]; then
    $sign_tool 0 liteos_mfg_bin_factory_ecc.cfg
    echo "ws53_liteos_mfg.bin generate succed!!!"
fi

# 镜像填充
ccore_padd=180k # c核镜像固定填充到180k
image_padding()
{
    image=$1
    tmp=$image.tmp
    dd if=$image of=$tmp bs=$ccore_padd seek=0 count=1 conv=sync
    mv $tmp $image
}

# 合并镜像, 并签名
merge_and_sign()
{
    ccore_image=$1
    acore_image=$2
    merge_image=$3
    cat $ccore_image $acore_image > $merge_image
    padd_align_64byte $merge_image
    cp $merge_image $pktbin
    $sign_tool 0 $target"_ecc.cfg"
}

# acore和core目标，打包时用于镜像合一，注意成对添加
target_map_list=(
    #  a核目标                  c核目标
    ws53_liteos_perf          ws53_control_perf
    ws53_liteos_app           ws53_control_app
    ws53_liteos_mfg           ws53_control_app
    ws53_liteos_xts           ws53_control_app
    ws53_liteos_plt_only      ws53_control_plt_only
    ws53_liteos_btc_only      ws53_control_btc_only
    ws53_liteos_bt_only       ws53_control_bgle_all
    ws53_liteos_for_sw21      ws53_control_for_sw21
    ws53_liteos_daq           ws53_control_daq
)

# 在map_list中查找target
target_type="none"
find_target_in_map_list()
{
    for i in "${!target_map_list[@]}"
    do {
        if [ $target == ${target_map_list[$i]} ]; then
            if [ $(expr $i % 2) -eq 0 ]; then
                target_type="acore"
            else
                target_type="ccore"
            fi
            target_num=$i
            return
        fi
    }
    done
}

find_target_in_map_list

if [[ $target == *liteos* ]] || [[ $target == *control* ]]; then
    if [ $target_type == "none" ]; then
        echo "ERR: cann't find target in target_map_list, please add it."
        exit 1
    fi
fi

# 处理c核镜像：将c核镜像填充到分区大小
if [[ $target_type == "ccore" ]]; then
    ccore_image=$ccore_out"/"$target"/control_ws53.bin"
    if [ -f $ccore_image ]; then
        echo "padding ccore image"
        image_padding $ccore_image
    fi
fi

# 处理a核镜像：与对应c核镜像合并后签名
if [[ $target_type == "acore" ]]; then
    ccore_image=$ccore_out"/"${target_map_list[$target_num + 1]}"/control_ws53.bin"
    acore_image=$out_put"/"$target"/application.bin"
    sdk_ccore=$inter_dir"/control_ws53.bin"
    merge_image=$out_put"/"$target"/"$target".bin"
    if [ -f $acore_image ] && [ -f $ccore_image ]; then
        echo "merge image: $ccore_image & $acore_image > $merge_image"
        merge_and_sign $ccore_image $acore_image $merge_image
    elif [ -f $acore_image ] && [ -f $sdk_ccore ]; then
        echo "merge image: $sdk_ccore & $acore_image > $merge_image"
        merge_and_sign $sdk_ccore $acore_image $merge_image
    fi
fi

rm -rf params_sign.bin
rm -rf root_pubk.bin
rm -rf $out_put"/param_bin/"
mkdir $out_put"/param_bin/"
mv root_params_sign.bin $out_put"/param_bin/"
mv params.bin $out_put"/param_bin/"

#pack all unsgin bin
cp $inter_dir"/ssb.bin" $pktbin || :
cp $inter_dir"/loaderboot.bin" $pktbin || :
cp $efuse_csv $pktbin || :
cp $out_put"/param_bin/params.bin" $pktbin || :
cp $out_put"/nv_bin/ws53_all_nv.bin" $pktbin || :
cp $out_put"/nv_bin/ws53_all_nv_backup.bin" $pktbin || :
cp $out_put"/ws53-flashboot/flashboot.bin" $pktbin || :
pushd $pktbin"/../"
rm -rf pktbin.zip
tar -cf pktbin.zip ./pktbin
popd

popd
exit 0
