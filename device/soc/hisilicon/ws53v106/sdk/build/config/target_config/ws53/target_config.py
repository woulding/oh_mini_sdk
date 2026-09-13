#!/usr/bin/env python3
# encoding=utf-8
# =========================================================================
# @brief    Target Definitions File
# Copyright CompanyNameMagicTag 2022-2022. All rights reserved.
# =========================================================================
import os
import copy

codesize_flags = {
    'ccflags':[
        "-madjust-regorder",
        "-madjust-const-cost",
        "-freorder-commu-args",
        "-fimm-compare-expand",
        "-frmv-str-zero",
        "-mfp-const-opt",
        "-mswitch-jump-table",
        "-frtl-sequence-abstract",
        "-frtl-hoist-sink",
        "-fsafe-alias-multipointer",
        "-finline-optimize-size",
        "-fmuliadd-expand",
        "-mlli-expand",
        "-Wa,-mcjal-expand",
        "-foptimize-reg-alloc",
        "-fsplit-multi-zero-assignments",
        "-floop-optimize-size",
        "-Wa,-mlli-relax",
        "-mpattern-abstract",
        "-foptimize-pro-and-epilogue",
    ],
    'linkflags':[
        "-Wl,--cjal-relax",
        "-Wl,--dslf",
    ],
    'rom_ccflags':[
        "-madjust-regorder",
        "-madjust-const-cost",
        "-freorder-commu-args",
        "-fimm-compare-expand",
        "-frmv-str-zero",
        "-mfp-const-opt",
        "-frtl-sequence-abstract",
        "-frtl-hoist-sink",
        "-fsafe-alias-multipointer",
        "-finline-optimize-size",
        "-fmuliadd-expand",
        "-mlli-expand",
        "-Wa,-mcjal-expand",
        "-foptimize-reg-alloc",
        "-fsplit-multi-zero-assignments",
        "-floop-optimize-size",
        "-foptimize-pro-and-epilogue",
        "-fno-inline-functions-called-once",
        "-fno-inline-small-functions",
    ]
}

required_flags = {
    'ccflags':[
        '-Wfloat-equal','-Wdate-time', '-fno-builtin', '-fno-exceptions', '--short-enums',
        '-:-Wno-error=main','-:-fno-tree-scev-cprop','-:-fno-ipa-ra', '-:-fldm-stm-optimize',
    ],
    'linkflags':[],
    'rom_ccflags':[
        '-Wdate-time','-Wimplicit-fallthrough=2','-fno-builtin','-fno-exceptions',"-Wfloat-equal",
        "-:-Wno-error=main", "-:-Wno-type-limits", "-:-Wno-implicit-fallthrough", '-:-fldm-stm-optimize',
        '-:-fno-tree-scev-cprop','-:-fno-ipa-ra', '--short-enums',
        '-Wundef', '-Wswitch-default', '-nostdinc'
    ]
}

target_template = {
    'target_application_rom_template': {
        'chip': 'ws53',
        'core': 'acore',
        'arch': 'riscv31',
        'tool_chain': 'riscv32_musl_b010',
        'board': 'fpga',
        'build_type': 'COMPILE',
        'os': 'liteos',
        'std_libs': ['m', 'c', 'gcc'],
        'CONFIG_TIMER_USING_V150': 'y',
        'defines': [
            "SDK_VERSION=\"1.10.106\"", '-:CHIP_WS53=1', 'LIBCPU_UTILS', 'LIBLIB_UTILS', 'LIBPANIC', 'LIBAPP_VERSION',
            'VERSION_STANDARD', 'LIBBUILD_VERSION', "CONFIG_UART_FIFO_DEPTH=64", 'RISCV_31',
            'LIBTEST_COMMON', '_ALL_SOURCE', 'LOSCFG_MEM_TASK_STAT', 'SUPPORT_CXX',
            'LIBLOG', 'LIBLOG_READER', 'USE_LITEOS', 'USE_VECTORS', 'BUILD_APPLICATION_STANDARD', 'CMD_ENABLE',
            '__LITEOS__', 'LIBCPU_LOAD', 'LOSCFG_DRIVERS_EMMC', 'UART_DRIVER_CONFIG_USE_VETOS_IN_STEAD_OF_TIMERS', 'LIBUTIL_COMPAT',
            'USE_CMSIS_OS', 'LIBCMD', 'LITEOS_ONETRACK', 'LIBCONNECTIVITY', 'LOSCFG_FS_FAT_CACHE', 'IPC_NEW', 'SUPPORT_HCC',
            "CONFIG_TIMER_MAX_TIMERS_NUM_0=1", "CONFIG_TIMER_MAX_TIMERS_NUM_1=8",
            "USE_WS53_ROM_REPO", "EFUSE_BIT_OPERATION",
        ],
        'defines_set': ['libsec_defines', 'chip_defines', 'version_defines'],
        'ram_component': [
            'plat_patch',
            'non_os', 'board_config', 'ulp_aon', 'osal', 'osal_adapt', 'ws53_dyn_mem',
            'ws53_clocks', 'error_code', 'hal_mips', 'ws53_mem_config', 'driver_header',
            'dfx_exception', 'chip_ws53_acore', 'cmn_header', '-:port_pinctrl',
            'pinctrl_port', 'security_unified_header', 'app_init', 'samples',
            '-:lib_utils', 'ws53_app_lds', 'ws53_standard', 'hal_cpu_hifi', 'liteos_207_0_0', 'dfx_port_ws53',
            'algorithm', 'test_pinctrl', 'hcc_host_ram', 'ws53_hcc_cfg', 'test_hcc',
            'drv_timer', 'hal_timer', 'dma_flash', 'dma_port_flash', 'hal_dma_v151_flash',
            'timer_port', 'sfc_port_ws53', 'acore_trng_buffer',
            'tsensor_port', 'update_common', 'update_common_ws53', 'update_storage', 'update_storage_ws53',
            'adc', 'hal_adc', 'adc_port', 'reboot_port',
            'ws53_flash_recover',
            'mcpu_trace_porting',
            'ws53_flash_patch_port',
            'libboundscheck_ram',
            'version_port' , 'mac_addr_ws53',
            'efuse', 'hal_efuse_v151', 'efuse_port',
            '-:connectivity',
        ],
        'ram_component_set': [
            'cpu', 'cpu_trace', 'gpio_v150','mem', 'watchdog', 'pinctrl', 'pmp_set',
            'spi', 'uart', 'std_common_lib', 'dfx_set', 'security_unified', 'pm_set', 'sfc_flash'
        ],
        'rom_component': [
            'libboundscheck_rom', 'version_rom',
            'ipc_rom', 'hal_ipc_rom', 'ipc_porting_acore_rom', 'ws53_flash_patch_rom',
            'hal_dma_v151_rom', 'dma_rom', 'dma_port_rom',
            'tcxo_rom', 'hal_tcxo_rom', 'tcxo_port_rom',
            'rtc_unified_rom', 'hal_rtc_unified_rom', 'rtc_unified_port_rom',
            'systick_rom', 'hal_systick_rom', 'systick_port_rom',
            'sdio_rom', 'hal_sdio_rom', 'sdio_port_rom',
            'syschannel_filter_rom', 'hcc_host_rom',
        ],
        'rom_component_set': [
        ],
        'ccflags': [
            *codesize_flags['ccflags'],
            *required_flags['ccflags'],
            '-:-Wno-type-limits',
        ],
        'linkflags': [
            *codesize_flags['linkflags'],
            *required_flags['linkflags'],
        ],
        'rom_ccflags':[
            *codesize_flags['rom_ccflags'],
            *required_flags['rom_ccflags'],
            "-DCONFIG_ROM_COMPILE",
            '-UBOARD_FPGA', '-UPRE_FPGA', '-UWS53_PRODUCT_FPGA',
            '-UBOARD_ASIC', '-UPRE_ASIC', '-UWS53_PRODUCT_ASIC',
        ],
        'application': 'standard',
        'bin_name': 'application',
        'hso_enable': True,
        'packet': True,
        'build_rom_callback': True,
        'rom_ram_check': True,
        'rom_ram_compare': True,
        'patch': True,
        'fixed_rom': True,
        'fixed_rom_path': '<root>/libs_url/ws53/check_bin/application_rom.bin',
        'rom_sym_path': '<root>/drivers/chips/ws53/rom_config/acore/acore.sym',
        'rom_in_one': True
    },
    'target_boot_ws53': {
        'chip': 'ws53',
        'core': 'acore',
        'board': 'fpga',
        'tool_chain': 'riscv32_musl_b010',
        'build_type': 'COMPILE',
        'os': 'non-os',
        'std_libs': ['m', 'c', 'gcc'],
        'CONFIG_TIMER_USING_V150': 'y',
        'defines': [
            "SDK_VERSION=\"1.10.106\"", '-:CHIP_WS53=1',
            "CONFIG_UART_FIFO_DEPTH=64",
        ],
        'defines_set': ['libsec_defines', 'chip_defines'],
        'ram_component': [
            'pinctrl_port', '-:port_pinctrl', 'board_config', 'driver_header', 'security_unified_header'
        ],
        'ccflags': [
            *codesize_flags['ccflags'],
            *required_flags['ccflags'],
        ],
        'linkflags': [
            *codesize_flags['linkflags'],
            *required_flags['linkflags'],
        ],
        'rom_ccflags': [
            *codesize_flags['rom_ccflags'],
            *required_flags['rom_ccflags'],
        ],
        'bin_name': 'boot',
        'arch': 'riscv31'
    },
}
