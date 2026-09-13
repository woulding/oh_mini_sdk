import subprocess
import os
import sys
import shutil
import platform
import tarfile
import subprocess

file_dir = os.path.dirname(os.path.realpath(__file__))
g_root = os.path.realpath(os.path.join(file_dir, "..", "..", "..", "..", ".."))
sys.path.append(os.path.join(g_root, 'build', 'script'))
sys.path.append(os.path.join(g_root, "build", "config"))
from enviroment import TargetEnvironment
import param_packet

target = sys.argv[1]
bin_name = sys.argv[2]
ccore_bin_name = sys.argv[3]

print(f"==========1target:{target}")
current_path = os.getcwd()
cwd_path = os.path.split(os.path.realpath(__file__))[0]
os.chdir(cwd_path)
if "windows" in platform.platform().lower():
    sign_tool = "../../../../../tools/bin/sign_tool/sign_tool_pltuni.exe"
else:
    sign_tool = "../../../../../tools/bin/sign_tool/sign_tool_pltuni"

out_put = "../../../../../output/ws53/acore"
ccore_out = "../../../../../output/ws53/control_core"
inter_dir = "../../../../../interim_binary/ws53/bin/boot_bin"
boot_bin = "../../../../../output/ws53/acore/boot_bin"
pktbin = "../../../../../output/ws53/pktbin"
out_put_ws53_path = "../../../../../output/ws53/"
efuse_csv = "../script/efuse.csv"


def merge(file_first, file_second, file_out):
    if "windows" in platform.platform().lower():
        out_path = os.path.normpath(os.path.realpath(file_out)).rsplit('\\', 1)[0]
    else:
        out_path = os.path.normpath(os.path.realpath(file_out)).rsplit('/', 1)[0]
    print("merge out path: ", out_path)
    if not os.path.exists(out_path):
        os.makedirs(out_path)
    ret = open(file_out, 'wb')
    with open(file_first, 'rb') as file_1:
        for i in file_1:
            ret.write(i)
    with open(file_second, 'rb') as file_2:
        for i in file_2:
            ret.write(i)
    ret.close()


def move_file(src_path, dst_path, file_name):
    src_file = os.path.join(src_path, file_name)
    if not os.path.exists(dst_path):
        os.mkdir(dst_path)
    dst_file = os.path.join(dst_path, file_name)
    shutil.move(src_file, dst_file)


def sign_app(file_path, type, cfg_name):
    if os.path.isfile(file_path):
        print("sign name: ", file_path)
        dd64c(file_path)
        ret = subprocess.run([sign_tool, type, cfg_name])
        if ret.returncode == 0:
            print(file_path, " generated successfully!!!")
        else:
            print(file_path, " generated failed!!!")
        shutil.copy(file_path, pktbin)
    else:
        pass


def generate_fill_bin(file_path, size):
    with open(file_path, 'wb') as f:
        f.write(bytes([0xFF] * size))


def dd64c(input_file_path):
    file_size = os.path.getsize(input_file_path)
    print(input_file_path, "size: ", file_size)
    if file_size % 64 != 0:
        max_size = int((file_size / 64) + 1) * 64
        if file_size < max_size:
            file_content = open(input_file_path, 'ab')
            file_content.write(bytes([0] * int(max_size - file_size)))


def dd_file_with_size(input_file_path, output_file_path, output_size):
    file_size = os.path.getsize(input_file_path)
    print(input_file_path, "size: ", file_size)
    input_file = open(input_file_path, 'rb')
    temp_copy_content = input_file.read(output_size)
    output_file = open(output_file_path, 'wb+')
    output_file.write(temp_copy_content)
    if file_size < output_size:
        output_file.write(bytes([0] * int(output_size - file_size)))
    output_file.close()
    input_file.close()


def zip_folder(folder_path, zip_file_name):
    with tarfile.open(zip_file_name, "w") as tar:
        for root, _, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, folder_path)
                tar.add(file_path, arcname=rel_path)


if os.path.exists(pktbin):
    shutil.rmtree(pktbin)
os.makedirs(pktbin)

# generate params.bin
print("generate params.bin...")
params_cmd = ["../param_sector/param_sector.json", "params.bin"]
param_packet.gen_flash_part_bin(params_cmd[0], params_cmd[1])

if os.path.isfile("params.bin"):
    dd64c("params.bin")
    print("params.bin generate successfully!!!")

    # generate params_sign.bin
    param_bin_ecc_cmd = [sign_tool, "0", "param_bin_ecc.cfg"]
    ret = subprocess.run(param_bin_ecc_cmd, cwd=cwd_path, stdout=subprocess.DEVNULL)

    if ret.returncode == 0:
        print("params_sign.bin generate successfully!!!")
    else:
        print("params_sign.bin generate failed!!!")

    # generate root public key
    root_pubk_cmd = [sign_tool, "1", "root_pubk.cfg"]
    ret = subprocess.run(root_pubk_cmd, cwd=cwd_path, stdout=subprocess.DEVNULL)

    if ret.returncode == 0:
        print("root_pubk.bin generate successfully!!!")
    else:
        generate_fill_bin("root_pubk.bin", 0x80)
        print("generate fill root_pubk.bin")
    # packet root public key and param.bin
    merge("root_pubk.bin", "params_sign.bin", "root_params_sign.bin")
    print("root_params_sign.bin generate successfully!!!")
    move_file(cwd_path, os.path.join(out_put, "boot_bin"), "root_params_sign.bin")


if not os.path.isdir(boot_bin) and os.path.isdir(inter_dir):
    shutil.copytree(inter_dir, boot_bin)
    shutil.copy(os.path.join(inter_dir, "ssb.bin"), boot_bin)


# sign ssb
if os.path.isfile(os.path.join(out_put, "ws53-ssb/ssb.bin")):
    dd64c(os.path.join(out_put, "ws53-ssb/ssb.bin"))
    ret1 = subprocess.run([sign_tool, "0", "ssb_ws53_ecc.cfg"], stdout=subprocess.DEVNULL)
    if ret1.returncode == 0:
        print("ssb_sign.bin generated successfully!!!")
        shutil.copy(os.path.join(out_put, "ws53-ssb/ssb_sign.bin"), boot_bin)
    else:
        print("ssb_sign.bin generated failed!!!")

# if [ ! -f $out_put"/ws53-ssb/ssb.bin" ] && [ -f $inter_dir"/ssb.bin" ]; then
if (not os.path.isfile(os.path.join(out_put, "ws53-ssb/ssb.bin"))) and (
os.path.isfile(os.path.join(inter_dir, 'ssb.bin'))):
    if not os.path.isdir(os.path.join(out_put, "ws53-ssb")):
        os.mkdir(os.path.join(out_put, "ws53-ssb"))
    shutil.copy(os.path.join(inter_dir, 'ssb.bin'), os.path.join(out_put, "ws53-ssb"))
    print("ssb_sign.bin generated successfully!!!")
    dd64c(os.path.join(out_put, "ws53-ssb/ssb.bin"))
    ret_ssb = subprocess.run([sign_tool, "0", "ssb_ws53_ecc.cfg"], stdout=subprocess.DEVNULL)
    shutil.copy(os.path.join(out_put, "ws53-ssb/ssb_sign.bin"), boot_bin)
    shutil.rmtree(os.path.join(out_put, "ws53-ssb"))

# sign flash boot
if os.path.isfile(os.path.join(out_put, "ws53-flashboot/flashboot.bin")):
    dd64c(os.path.join(out_put, "ws53-flashboot/flashboot.bin"))
    ret_flash_bin_ecc = subprocess.run([sign_tool, "0", "flashboot_ws53_ecc.cfg"],
                                        stdout=subprocess.DEVNULL)
    ret_flash_backup_bin_ecc = subprocess.run([sign_tool, "0", "flashboot_ws53_bak_ecc.cfg"],
                                               stdout=subprocess.DEVNULL)
    print(ret_flash_bin_ecc)
    print(ret_flash_backup_bin_ecc)
    if ret_flash_bin_ecc.returncode == 0 and ret_flash_backup_bin_ecc.returncode == 0:
        print("flash_sign.bin generated successfully!!!")
        shutil.copy(os.path.join(out_put, "ws53-flashboot/flashboot_sign.bin"), boot_bin)
        shutil.copy(os.path.join(out_put, "ws53-flashboot/flashboot_backup_sign.bin"), boot_bin)
    else:
        print("flash_sign.bin generated failed!!!")

# sign ws53_flash_aging_test
if os.path.isfile(os.path.join(out_put, "ws53-flash-aging-test/ws53_flash_aging_test.bin")):
    dd64c(os.path.join(out_put, "ws53-flash-aging-test/ws53_flash_aging_test.bin"))
    ret1 = subprocess.run([sign_tool, "0", "flash_againe_test_ecc.cfg"],
                           stdout=subprocess.DEVNULL)
    print("ws53_flash_aging_test_sign.bin generated successfully!!!")

#  sign loaderboot
if os.path.isfile(os.path.join(out_put, "ws53-loaderboot", "loaderboot.bin")):
    dd_file_with_size(os.path.join(out_put, "ws53-loaderboot", "loaderboot.bin"),
                      os.path.join(out_put, "ws53-loaderboot", "loaderboot.28k.bin"), 1024 * 28)
    shutil.move(os.path.join(out_put, "ws53-loaderboot", "loaderboot.28k.bin"),
                os.path.join(out_put, "ws53-loaderboot", "loaderboot.bin"))
    ret1 = subprocess.run([sign_tool, "0", "loaderboot_ws53_ecc.cfg"],
                           stdout=subprocess.DEVNULL)

    if ret1.returncode == 0:
        print("loaderboot_sign.bin generated successfully!!!")
    else:
        print('===========================')
        print(ret1)
        print("loaderboot_sign.bin generated failed!!!")
####################################################
    merge("root_pubk.bin", "loaderboot_sign.bin", os.path.join(out_put, "ws53-loaderboot", "loaderboot_sign.bin"))
    shutil.copy(os.path.join(out_put, "ws53-loaderboot/loaderboot_sign.bin"), boot_bin)
    print("root_loaderboot_sign.bin generated successfully!!!")
    os.remove("loaderboot_sign.bin")

# sign loaderboot.bin interim
if (not os.path.isfile(os.path.join(out_put, "ws53-loaderboot", 'loaderboot.bin'))) and os.path.isfile(
        os.path.join(inter_dir, 'loaderboot.bin')):
    if not os.path.isdir(os.path.join(out_put, "ws53-loaderboot")):
        os.makedirs(os.path.join(out_put, 'ws53-loaderboot'))
    shutil.copy(os.path.join(inter_dir, 'loaderboot.bin'), os.path.join(out_put, "ws53-loaderboot"))
    print("copy ws53-loaderboot generate succed!!!")
    dd_file_with_size(os.path.join(out_put, "ws53-loaderboot", "loaderboot.bin"),
                      os.path.join(out_put, "ws53-loaderboot", "loaderboot.28k.bin"), 1024 * 28)
    shutil.move(os.path.join(out_put, "ws53-loaderboot", "loaderboot.28k.bin"),
                os.path.join(out_put, "ws53-loaderboot", "loaderboot.bin"))
    ret1 = subprocess.run([sign_tool, "0", "loaderboot_ws53_ecc.cfg"],
                           stdout=subprocess.DEVNULL)
    if ret1.returncode == 0:
        print("loaderboot_sign.bin generated successfully!!!")
    else:
        print("loaderboot_sign.bin generated failed!!!")
    # pack root public bin and loaderboot
    merge("root_pubk.bin", 'loaderboot_sign.bin', os.path.join(boot_bin, 'loaderboot_sign.bin'))
    print("loaderboot_sign.bin generated successfully!!!")
    os.remove('loaderboot_sign.bin')
    shutil.rmtree(os.path.join(out_put, "ws53-loaderboot"))

# if [ -f $inter_dir"/control_ws53.bin" ] && [ ! -f $ccore_out"/ws53_control_app/control_ws53.bin" ]; then
if (os.path.isfile(os.path.join(inter_dir, 'control_ws53.bin'))) and (
not os.path.isfile(os.path.join(ccore_out, 'ws53_control_app', 'control_ws53.bin'))):
    if not os.path.isdir(os.path.join(ccore_out, "ws53_control_app")):
        os.makedirs(os.path.join(ccore_out, 'ws53_control_app'))
    shutil.copy(os.path.join(inter_dir, 'control_ws53.bin'),
                os.path.join(ccore_out, "ws53_control_app", 'control_ws53.bin'))
    print("copy control_ws53.bin generate succed!!!")
    dd64c(os.path.join(ccore_out, "ws53_control_app", 'control_ws53.bin'))
    #    $sign_tool 0 ws53_control_ecc_app.cfg
    ret1 = subprocess.run([sign_tool, "0", "ws53_control_ecc_app.cfg"],
                           stdout=subprocess.DEVNULL)
    shutil.copy(os.path.join(ccore_out, "ws53_control_app", 'control_ws53_sign.bin'), boot_bin)
    shutil.rmtree(os.path.join(ccore_out, "ws53_control_app"))
    print("control_ws53_sign.bin generate succed!!!")

# sign ws53_liteos_mfg
application_mfg_bin = os.path.join(out_put, '../../../application/ws53/ws53_liteos_mfg/ws53_liteos_mfg.bin')
if (os.path.isfile(application_mfg_bin)):
    dd64c(application_mfg_bin)
    shutil.copy(application_mfg_bin, pktbin)
    subprocess.run([sign_tool, "0", "liteos_mfg_bin_factory_ecc.cfg"],
                    stdout=subprocess.DEVNULL)
    print("liteos_mfg_bin_factory_ecc.bin generated successfully!!!")


def image_padding(image_path):
    dd_file_with_size(image_path, image_path + '.tmp', 180 * 1024)
    shutil.move(image_path + '.tmp', image_path)

def merge_and_sign(ccore_image_path, acore_image_path, merge_image_path):
    merge(ccore_image_path, acore_image_path, merge_image_path)
    dd64c(merge_image_path)
    shutil.copy(merge_image_path, pktbin)
    subprocess.run([sign_tool, "0", target + "_ecc.cfg"],
                    stdout=subprocess.DEVNULL)


# 在map_list中查找target

def find_target_in_map_list(target):
    temp_target_type = "none"
    target_num = 0
    for index, value in enumerate(target_map_list):
        if target in value:
            if index % 2 == 0:
                temp_target_type = 'acore'
            else:
                temp_target_type = 'ccore'
            return index, temp_target_type
    return index, temp_target_type


target_map_list = [
    'ws53_liteos_perf', 'ws53_control_perf',
    'ws53_liteos_app', 'ws53_control_app',
    'ws53_liteos_mfg', 'ws53_control_app',
    'ws53_liteos_xts', 'ws53_control_app',
    'ws53_liteos_plt_only', 'ws53_control_plt_only',
    'ws53_liteos_btc_only', 'ws53_control_btc_only',
    'ws53_liteos_bt_only', 'ws53_control_bgle_all',
    'ws53_liteos_for_sw21', 'ws53_control_for_sw21',
    'ws53_liteos_daq', 'ws53_control_daq',
    '', 'ws53_control_app_lite',
]

target_num, target_type = find_target_in_map_list(target)

if target_type.__contains__('liteos') or target.__contains__('control'):
    if target_type == 'none':
        exit(1)

if target_type == 'ccore':
    ccore_image = os.path.join(ccore_out, target, bin_name + ".bin")
    if (os.path.isfile(ccore_image)):
        image_padding(ccore_image)


if target_type == 'acore':
    # target:ws53_liteos_app bin_name:application.bin ccore_bin_name:control_ws53.bin/control_ws53_lite.bin
    ccore_inter_path = os.path.join(inter_dir, ccore_bin_name)
    if ccore_bin_name == "default":
        ccore_image = os.path.join(ccore_out, target_map_list[target_num + 1], 'control_ws53.bin')
        acore_image = os.path.join(out_put, target, 'application.bin')
        sdk_ccore = os.path.join(inter_dir, 'control_ws53.bin')
        merge_image = os.path.join(out_put, target, target + '.bin')
        if (os.path.isfile(acore_image) and os.path.isfile(ccore_image)):
            merge_and_sign(ccore_image, acore_image, merge_image)
        elif (os.path.isfile(acore_image) and os.path.isfile(sdk_ccore)):
            merge_and_sign(sdk_ccore, acore_image, merge_image)
    elif not os.path.isfile(ccore_inter_path):
        print(f"not find ccore_bin:{ccore_inter_path}")
        exit(1)
    else:
        acore_image = os.path.join(out_put, target, 'application.bin')
        merge_image = os.path.join(out_put, target, target + '.bin')
        if os.path.isfile(acore_image):
            merge_and_sign(ccore_inter_path, acore_image, merge_image)


# clean middle files
os.remove("params_sign.bin")
os.remove("root_pubk.bin")
if os.path.isdir(os.path.join(out_put, "param_bin")):
    shutil.rmtree(os.path.join(out_put, "param_bin"))
os.mkdir(os.path.join(out_put, "param_bin"))

if os.path.isfile('root_params_sign.bin'):
    shutil.move('root_params_sign.bin', os.path.join(out_put, "param_bin"))

if os.path.isfile('params.bin'):
    shutil.move('params.bin', os.path.join(out_put, "param_bin"))

# pack all unsgin bin

if os.path.isfile(os.path.join(inter_dir, "ssb.bin")):
    shutil.copy(os.path.join(inter_dir, "ssb.bin"), pktbin)

if os.path.isfile(os.path.join(inter_dir, "loaderboot.bin")):
    shutil.copy(os.path.join(inter_dir, "loaderboot.bin"), pktbin)

if os.path.isfile(efuse_csv):
    shutil.copy(efuse_csv, pktbin)

if os.path.isfile(os.path.join(out_put, "param_bin", "params.bin")):
    shutil.copy(os.path.join(out_put, "param_bin", "params.bin"), pktbin)

if os.path.isfile(os.path.join(out_put, "nv_bin", "ws53_all_nv.bin")):
    shutil.copy(os.path.join(out_put, "nv_bin", "ws53_all_nv.bin"), pktbin)

if os.path.isfile(os.path.join(out_put, "nv_bin", "ws53_all_nv_backup.bin")):
    shutil.copy(os.path.join(out_put, "nv_bin", "ws53_all_nv_backup.bin"), pktbin)

if os.path.isfile(os.path.join(out_put, "ws53-flashboot", "flashboot.bin")):
    shutil.copy(os.path.join(out_put, "ws53-flashboot", "flashboot.bin"), pktbin)

if os.path.isfile(os.path.join(out_put, "ws53-flashboot", "flashboot.bin")):
    shutil.copy(os.path.join(out_put, "ws53-flashboot", "flashboot.bin"), pktbin)

if os.path.isfile(os.path.join(out_put_ws53_path, "pktbin.zip")):
    os.remove(os.path.join(out_put_ws53_path, "pktbin.zip"))
zip_folder(os.path.join(out_put_ws53_path, "pktbin"), os.path.join(out_put_ws53_path, "pktbin.zip"))

os.chdir(current_path)
