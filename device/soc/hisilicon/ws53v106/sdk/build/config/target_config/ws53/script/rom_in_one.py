import subprocess
import os
import sys
import shutil
import platform
import tarfile
import subprocess
from collections import deque

root_dir=sys.argv[1]
bin_name=sys.argv[2]
target_name=sys.argv[3]
core=sys.argv[4]

out_dir='../../../../../output/ws53/' + core + '/' +target_name
rom_ver_dir='../../../../../output/ws53/rom_ver'
romboot_bin='../../../../../output/ws53/acore/ws53-romboot/romboot.bin'
create_hex_py='../../../../../build/script/utils/create_hex.py'

python_path = sys.executable
current_path = os.getcwd()
cwd_path = os.path.split(os.path.realpath(__file__))[0]
os.chdir(cwd_path)

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


def dd_file_with_size_skip(input_file_path, output_file_path, output_size, skip_block):
    file_size = os.path.getsize(input_file_path)
    print(input_file_path, "size: ", file_size)
    with open(input_file_path, 'rb') as input_file:
        temp_copy_content = []
        i = 0
        while i <= skip_block: 
            temp_copy_content = input_file.read(output_size)
        with open(output_file_path, 'wb+') as output_file:
            output_file.write(temp_copy_content)


def dd_file(input_file_path, output_file_path, output_size, skip_block, count):
    file_size = os.path.getsize(input_file_path)
    print(input_file_path, "size: ", file_size)
    with open(input_file_path, 'rb') as input_file:
        temp_copy_content = []
        i = 0
        while i <= skip_block: 
            temp_copy_content = input_file.read(output_size)
        write_count = 1
        with open(output_file_path, 'wb+') as output_file:
            while write_count <= count:
                output_file.write(temp_copy_content)
                if (len(temp_copy_content) < output_size):
                    output_file.write(bytes([0] * int(output_size - len(temp_copy_content))))
                write_count = write_count + 1
                temp_copy_content = input_file.read(output_size)

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


def split_file_by_num(fileName):
    with open(fileName, 'rb') as input_file:
        i = 1
        file_0 = open(0, 'wb')
        file_1 = open(1, 'wb')
        while True:
            data = input_file.readline()
            if not data:
                break;
            if i % 2 ==0:
                file_0.write(data)
            else:
                file_1.write(data)


def tail_file(input_file_name, out_put_file_name, num):
    last_lines = deque(maxlen=num)
    with open(input_file_name, 'r') as input_file:
        for line in input_file:
            last_lines.append(line)
    with open(out_put_file_name, 'r') as out_put_file:
        for line in last_lines:
            out_put_file.write(line)


# if [ "${core}" = "acore" -a "${target_name}" = "liteos_ws53" ];then
if core == 'acore' and target_name == 'liteos_ws53':
    if not os.path.isfile(romboot_bin):
        print("[*] romboot not found, codepoint files will not be one!")
        exit(0)
    
    os.chdir(out_dir)

    # Fill romboot bin to 39K
    dd_file_with_size(romboot_bin, 'romboot.39K.bin',39 * 1024 * 1024)

    # All in one rompack file
    merge('romboot.39K.bin', bin_name + '_rom.bin', bin_name + '_rompack_tmp.bin')

    dd_file_with_size(bin_name + '_rompack_tmp.bin', bin_name + '_rompack.bin', 64 * 1024 * 1024)
    dd_file_with_size_skip(bin_name + '_rompack.bin', 'S40ULPROM8192X32_0SVTX16B4PD.bin', 32 * 1024 * 1024, 0)
    print("copy_bin ing...")
    errcode = exec_shell([python_path, create_hex_py, 'S40ULPROM8192X32_0SVTX16B4PD.bin', 'S40ULPROM8192X32_0SVTX16B4PD.hex'], None, True)

    dd_file_with_size_skip(bin_name + '_rompack.bin', 'S40ULPROM8192X32_1SVTX16B4PD.bin', 32 * 1024 * 1024, 1)
    errcode = exec_shell([python_path, create_hex_py, 'S40ULPROM8192X32_1SVTX16B4PD.bin', 'S40ULPROM8192X32_1SVTX16B4PD.hex'], None, True)

    if not os.isDir(os.path.join(rom_ver_dir, "acore")):
        os.mkdirs(os.path.join(rom_ver_dir, "acore"))

    if not os.isDir(os.path.join(rom_ver_dir, "acore", "raw_files")):
        os.mkdirs(os.path.join(rom_ver_dir, "acore", "raw_files"))

    if os.path.isfile(bin_name + '_rom.bin'):
        shutil.copy(bin_name + '_rom.bin', os.path.join(rom_ver_dir, 'acore', 'raw_files'))

    if os.path.isfile(bin_name + '_rom.hex'):
        shutil.copy(bin_name + '_rom.hex', os.path.join(rom_ver_dir, 'acore', 'raw_files'))

    if os.path.isfile('romboot.39K.bin'):
        shutil.copy('romboot.39K.bin', os.path.join(rom_ver_dir, 'acore', 'raw_files'))
    if os.path.isfile(bin_name + '_rompack.bin'):
        shutil.copy(bin_name + '_rompack.bin', os.path.join(rom_ver_dir, 'acore', 'raw_files'))
    if os.path.isfile('S40ULPROM8192X32_0SVTX16B4PD.bin'):
        shutil.copy('S40ULPROM8192X32_0SVTX16B4PD.bin', os.path.join(rom_ver_dir, 'acore', 'raw_files'))
    if os.path.isfile('S40ULPROM8192X32_1SVTX16B4PD.bin'):
        shutil.copy('S40ULPROM8192X32_1SVTX16B4PD.bin', os.path.join(rom_ver_dir, 'acore', 'raw_files'))
    if os.path.isfile('S40ULPROM8192X32_0SVTX16B4PD.hex'):
        shutil.copy('S40ULPROM8192X32_0SVTX16B4PD.hex', os.path.join(rom_ver_dir, 'acore'))
    if os.path.isfile('S40ULPROM8192X32_1SVTX16B4PD.hex'):
        shutil.copy('S40ULPROM8192X32_1SVTX16B4PD.hex', os.path.join(rom_ver_dir, 'acore'))

    os.chdir(cwd_path)

if core == 'control_core' and target_name == 'control_ws53':
    os.chdir(out_dir)

    if not os.isDir(os.path.join(out_dir, "adapt_rom_bin")):
        os.mkdirs(os.path.join(out_dir, "adapt_rom_bin"))
    if os.path.isfile(bin_name + '_rom.bin'):
        shutil.copy(bin_name + '_rom.bin', os.path.join(out_dir, 'adapt_rom_bin'))
    os.chdir(os.path.join(out_dir, "adapt_rom_bin"))
    dd_file(bin_name + '_rom.bin', bin_name + '_rom.288K.bin', 1024*1024, 0,288)

    errcode = exec_shell([python_path, create_hex_py, bin_name + '_rom.288K.bin', bin_name + '_rom.288K.hex'], None, True)
    split_file_by_num(bin_name + '_rom.288K.hex')
    shutil.move(1, 'temp_0.hex')
    shutil.move(0, 'temp_1.hex')

    split_ccore_index = 0
    temp_0_file = open('temp_0.hex', 'rb')
    temp_1_file = open('temp_1.hex', 'rb')
    while split_ccore_index <=3:
        data = temp_0_file.readline(8192)
        with open('S40ULPROM8192X32_' + (split_ccore_index * 2 + 3)+ 'SVTX16B4PD.hex', 'rb') as temp_file_0:
            temp_file_0.write(data)
        data = temp_1_file.readline(8192)
        with open('S40ULPROM8192X32_' + (split_ccore_index * 2 + 4) + 'SVTX16B4PD.hex', 'rb') as temp_file_1:
            temp_file_1.write

    tail_file('temp_0.hex',  'S40ULPROM4096X32_0SVTX16B2PD.hex' , 4096)
    tail_file('temp_1.hex',  'S40ULPROM4096X32_1SVTX16B2PD.hex' , 4096)
        # tail -n 4096 temp_0.hex  > S40ULPROM4096X32_0SVTX16B2PD.hex
        # tail -n 4096 temp_1.hex  > S40ULPROM4096X32_1SVTX16B2PD.hex

    if not os.isDir(os.path.join(rom_ver_dir, "ccore")):
        os.mkdirs(os.path.join(rom_ver_dir, "ccore"))
    if not os.isDir(os.path.join(rom_ver_dir, "ccore", 'raw_files')):
        os.mkdirs(os.path.join(rom_ver_dir, "ccore", 'raw_files'))
    if os.path.isfile(bin_name + '_rom.bin'):
        shutil.copy(bin_name + '_rom.bin', os.path.join(rom_ver_dir, 'ccore', 'raw_files'))
    if os.path.isfile(bin_name + '_rom.288K.bin'):
        shutil.copy(bin_name + '_rom.288K.bin', os.path.join(rom_ver_dir, 'ccore', 'raw_files'))
    if os.path.isfile(bin_name + '_rom.288K.hex'):
        shutil.copy(bin_name + '_rom.288K.hex', os.path.join(rom_ver_dir, 'ccore', 'raw_files'))
    if os.path.isfile('S40ULPROM4096X32_0SVTX16B2PD.hex'):
        shutil.copy('S40ULPROM4096X32_0SVTX16B2PD.hex', os.path.join(rom_ver_dir, 'ccore'))
    if os.path.isfile('S40ULPROM4096X32_1SVTX16B2PD.hex'):
        shutil.copy('S40ULPROM4096X32_1SVTX16B2PD.hex', os.path.join(rom_ver_dir, 'ccore'))
    if os.path.isfile('S40ULPROM8192X32_10SVTX16B4PD.hex'):
        shutil.copy('S40ULPROM8192X32_10SVTX16B4PD.hex', os.path.join(rom_ver_dir, 'ccore'))
    if os.path.isfile('S40ULPROM8192X32_3SVTX16B4PD.hex'):
        shutil.copy('S40ULPROM8192X32_3SVTX16B4PD.hex', os.path.join(rom_ver_dir, 'ccore'))
    if os.path.isfile('S40ULPROM8192X32_4SVTX16B4PD.hex'):
        shutil.copy('S40ULPROM8192X32_4SVTX16B4PD.hex', os.path.join(rom_ver_dir, 'ccore'))
    if os.path.isfile('S40ULPROM8192X32_5SVTX16B4PD.hex'):
        shutil.copy('S40ULPROM8192X32_5SVTX16B4PD.hex', os.path.join(rom_ver_dir, 'ccore'))
    if os.path.isfile('S40ULPROM8192X32_6SVTX16B4PD.hex'):
        shutil.copy('S40ULPROM8192X32_6SVTX16B4PD.hex', os.path.join(rom_ver_dir, 'ccore'))
    if os.path.isfile('S40ULPROM8192X32_7SVTX16B4PD.hex'):
        shutil.copy('S40ULPROM8192X32_7SVTX16B4PD.hex', os.path.join(rom_ver_dir, 'ccore'))
    if os.path.isfile('S40ULPROM8192X32_8SVTX16B4PD.hex'):
        shutil.copy('S40ULPROM8192X32_8SVTX16B4PD.hex', os.path.join(rom_ver_dir, 'ccore'))
    if os.path.isfile('S40ULPROM8192X32_9SVTX16B4PD.hex'):
        shutil.copy('S40ULPROM8192X32_9SVTX16B4PD.hex', os.path.join(rom_ver_dir, 'ccore'))

    os.chdir(cwd_path)

