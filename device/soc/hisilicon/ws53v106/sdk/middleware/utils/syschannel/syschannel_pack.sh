#!/bin/bash
syschannel_path=$(pwd)
utils_path=$(dirname $(pwd))
middleware_path=$(dirname $utils_path)
root=$(dirname $middleware_path)
kernel_path=${root}/kernel
open_source_path=${root}/open_source
include_path=${root}/include
output=${root}/syschannel
 
if [ ! -d ${output} ]; then
    # middleware
    mkdir ${output}
    mkdir ${output}/middleware
    mkdir ${output}/middleware/utils
    mkdir ${output}/middleware/utils/hcc
    mkdir ${output}/middleware/utils/common_headers
    mkdir ${output}/middleware/utils/common_headers/native
    mkdir ${output}/middleware/utils/syschannel
    # kernel
    mkdir ${output}/kernel
    mkdir ${output}/kernel/osal
    mkdir ${output}/kernel/osal/adapt
    mkdir ${output}/kernel/osal/adapt/liteos
    mkdir ${output}/kernel/osal/src
    mkdir ${output}/kernel/osal/src/liteos
    mkdir ${output}/kernel/osal/src/linux
    mkdir ${output}/kernel/osal/src/rtthread
    mkdir ${output}/kernel/osal_adapt
    # open_source
    mkdir ${output}/open_source
    mkdir ${output}/open_source/libboundscheck
    # include
    mkdir ${output}/include
    # cmake
    cp -r ${root}/CMakeLists.txt ${output}/
    # syschannel
    cp -r ${middleware_path}/CMakeLists.txt ${output}/middleware
    cp -r ${utils_path}/CMakeLists.txt ${output}/middleware/utils
    cp -r ${syschannel_path}/syschannel_api ${output}/middleware/utils/syschannel/syschannel_api
    cp -r ${syschannel_path}/syschannel_common ${output}/middleware/utils/syschannel/syschannel_common
    cp -r ${syschannel_path}/syschannel_host ${output}/middleware/utils/syschannel/syschannel_host
    cp -r ${syschannel_path}/CMakeLists.txt ${output}/middleware/utils/syschannel
    # cmn_header
    cp -r ${utils_path}/common_headers/native/*.h ${output}/middleware/utils/common_headers/native
    cp -r ${utils_path}/common_headers/osal ${output}/middleware/utils/common_headers/osal
    cp -r ${utils_path}/common_headers/*.h ${output}/middleware/utils/common_headers
    cp -r ${utils_path}/common_headers/CMakeLists.txt ${output}/middleware/utils/common_headers
    # hcc
    cp -r ${utils_path}/hcc/cfg ${output}/middleware/utils/hcc/cfg
    cp -r ${utils_path}/hcc/comm ${output}/middleware/utils/hcc/comm
    cp -r ${utils_path}/hcc/host ${output}/middleware/utils/hcc/host
    cp -r ${utils_path}/hcc/inc ${output}/middleware/utils/hcc/inc
    cp -r ${utils_path}/hcc/CMakeLists.txt ${output}/middleware/utils/hcc
    # osal
    cp -r ${kernel_path}/CMakeLists.txt ${output}/kernel
    cp -r ${kernel_path}/osal/adapt/include ${output}/kernel/osal/adapt/include
    cp -r ${kernel_path}/osal/adapt/liteos/*.c ${output}/kernel/osal/adapt/liteos
    cp -r ${kernel_path}/osal/include ${output}/kernel/osal/include
    cp -r ${kernel_path}/osal/src/liteos/*.c ${output}/kernel/osal/src/liteos
    cp -r ${kernel_path}/osal/src/liteos/*.h ${output}/kernel/osal/src/liteos
    cp -r ${kernel_path}/osal/src/rtthread/*.c ${output}/kernel/osal/src/rtthread
    cp -r ${kernel_path}/osal/src/rtthread/*.h ${output}/kernel/osal/src/rtthread
    cp -r ${kernel_path}/osal/CMakeLists.txt ${output}/kernel/osal/
    # osal linux
    cp -r ${kernel_path}/osal/src/linux/kernel ${output}/kernel/osal/src/linux/kernel
    cp -r ${kernel_path}/osal/src/linux/userspace ${output}/kernel/osal/src/linux/userspace
    rm -rf ${output}/kernel/osal/include/.git
    # osal_adapt
    cp -r ${kernel_path}/osal_adapt/inc ${output}/kernel/osal_adapt/inc
    cp -r ${kernel_path}/osal_adapt/src ${output}/kernel/osal_adapt/src
    cp -r ${kernel_path}/osal_adapt/CMakeLists.txt ${output}/kernel/osal_adapt
    # libboundscheck
    cp -r ${open_source_path}/CMakeLists.txt ${output}/open_source
    cp -r ${open_source_path}/libboundscheck/CMakeLists.txt ${output}/open_source/libboundscheck
    cp -r ${open_source_path}/libboundscheck/include ${output}/open_source/libboundscheck/include
    cp -r ${open_source_path}/libboundscheck/src ${output}/open_source/libboundscheck/src
    # include
    cp -r ${include_path}/*.h ${output}/include
    cp -r ${include_path}/CMakeLists.txt ${output}/include
    cp -r ${include_path}/driver ${output}/include/driver
    cp -r ${include_path}/middleware ${output}/include/middleware
    rm -rf ${output}/include/driver/.gitignore
    rm -rf ${output}/include/driver/security_unified/.git
else
    rm -rf ${output}
    echo "exist, will delete it, try again!"
fi
 
echo "finish"
