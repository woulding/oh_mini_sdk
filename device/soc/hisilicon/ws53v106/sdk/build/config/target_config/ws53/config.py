#!/usr/bin/env python3
# encoding=utf-8
# ============================================================================
# @brief    Target Definitions File
# Copyright CompanyNameMagicTag 2022-2023. All rights reserved.
# ============================================================================

from .target_config import required_flags

macro_ccflags = {
    'fpga':[
        '-DBOARD_FPGA',
        '-DPRE_FPGA',
        '-DWS53_PRODUCT_FPGA',
    ],
    'asic':[
        '-DBOARD_ASIC',
        '-DPRE_ASIC',
        '-DWS53_PRODUCT_ASIC',
        '-:-g',
    ]
}

target = {
    'ws53_liteos_app': {
        'base_target_name': 'target_application_rom_template',
        'defines': [
            'BOARD_ASIC',
            'HSO_SUPPORT', 'DIAG_PRINT', 'SW_UART_DEBUG',
            'CONFIG_IPERF_SUPPORT',
            # 'CONFIG_SENDTEST_SUPPORT',
            'CONFIG_XIP_ENABLE_READ_OVERTIME',
            'CONFIG_SUPPORT_WIFI', '_PRE_WLAN_FEATURE_FRW_IPC',
            'WS53_APP_VERSION',
            'AT_COMMAND', 'BTH_TASK_EXIST',
            # 'LWIP_TCM_OPTIMIZE',
            'NOT_SUPPORT_LWIP_IPV6', 'CONFIG_DHCPS_GW',
            'CHECKSUM_CHECK_TCP=0','CHECKSUM_CHECK_UDP=0', 'UPDATE_WIFI_STATIC_LIB', '_PRE_WLAN_FEATURE_PK',
            'CONFIG_NV_SUPPORT_SINGLE_CORE_SYSTEM', 'CONFIG_OTA_UPDATE_SUPPORT',
            'CHBA_SUPPORT',"CHBA_LWIP_SWITCH=1","SW_UART_CHIP_DEFINE",'CONFIG_LWIP_LOWPOWER','CONFIG_ARP_ANNOUNCE_OPT',
            'CONFIG_NETIF_HOSTNAME','_PRE_WIFI_LOWERPOWER_APP',
            'CONFIG_NO_VERIFY_TLS_TIME', 'CONFIG_NOT_SUPPORT_RSA_ALT',
            'CONFIG_WIFI_INFO_REPORT',
            'CONFIG_SUPPORT_OHOS_SUPPORT',
        ],
        'ram_component': [
            '-:liteos_207_0_0', 'liteos_208_5_0',
            '-:test_pinctrl',
            '-:test_hcc',
            '-:hal_cpu_hifi',
            'sio_port', 'hal_sio', 'i2s', 'driver_header',
            'mbedtls_v3.6.0', 'mbedtls_harden', 'wpa_supplicant', 'wifi_drv_ws53','wifi_fe','wifi_hal_ws53', 'wifi_driver_tcm', 'wifi_hal_tcm', 'lwip',
            'lwip_tcm', 'wifi_service', 'at', 'wifi_at', 'plt_at',
            'wifi_alg_txbf', 'wifi_alg_temp_protect', 'wifi_alg_anti_interference',
            'wifi_alg_edca_opt', 'wifi_alg_cca_opt',
            'syschannel_dev',
            'bt_at', 'mips', 'hal_mips', 'bg_common', 'bth_gle', 'bt_host', 'bth_sdk',
            'bt_app', 'bts_header',
            'wifi_csa', 'wifi_frag',
            'wifi_apf', 'wifi_auto_adjust_freq',
            'wifi_tx_amsdu',
            'wifi_btcoex', 'wifi_uapsd_ap', 'wifi_pk_txrx',
            'nv', 'nv_ws53', "partition", "partition_ws53", 'update_ab_ws53', 'nv_zdiag_ws53',
            'pwm', 'hal_pwm', 'pwm_port', 'sio_port', 'i2s', 'hal_sio',
            "coap",
            'factory_ws53', 'xo_trim_port',
            'sle_netdev', 'achba', 'chba_at', "dfx_printer", "enterprise_cert",
            # OHOS integration: cmsis adapt hooks + printf adapt + littlefs
            'ohos_adapt', 'printf_adapt', 'little_fs', 'littlefs_adapt_ws53',
        ],
        'ram_component_set': ['i2c'],
        'ccflags': [
            *macro_ccflags['asic'],
        ],
        'hso_enable_bt': True,
        'nv_update':True,
        'copy_boot_bin': True,
        'generate_efuse_bin': True,
	    'smaller': True,
    },
    'ws53-flashboot': {
        'base_target_name': 'target_boot_ws53',
        'defines': [
            "WS53_PRODUCT_NONE",
            "SW_UART_DEBUG",
            "CONFIG_UART_SUPPORT_TX",
            "BUILD_APPLICATION_ROM",
            "EFUSE_BIT_OPERATION",
            "BUILD_NOOSAL",
            "FLASH_REGION_CFG_FLASHBOOT",
            'BOOT_STR="flashboot:"',
            "CONFIG_BOOT_NO_SEC_VERIFY"
        ],
        'ram_component': [
            "flashboot_common", "common_boot", "ws53_flashboot_lds", 'tcxo',
            "libboundscheck", "chip_ws53_acore", "ws53_mem_config", "common_headers", "non_os",
            "cmn_header", "osal", "sfc_port_ws53", "dfx_panic", "dfx_exception", "dfx_preserve","cpu_utils",
            "error_code", "board_config", "chip_boot_port", "chip_boot_config",  "partition", "partition_ws53",
            'update_common', 'update_local', 'update_local_ws53', 'lzma_22.00', 'update_common_ws53', 'nonos_malloc', 'nonos_malloc_port',
            'update_ab_ws53', 'update_storage', 'factory_ws53',
        ],
        'ram_component_set': ["time_set", "pinctrl", "sfc_flash", "time_set", "uart", "watchdog", "efuse_v151", "security_unified", "cpu"],
        'os': 'non-os',
        'application': 'flashboot',
        'copy_boot_bin': True,
        'bin_name': 'flashboot'
    },
    'ws53_liteos_xts': {
        'base_target_name': 'target_application_rom_template',
        'liteos_kconfig':'ws53_liteos_xts',
        'std_libs': ['m', 'c', 'gcc', 'atomic'],
        'defines': [
            'BOARD_ASIC',
            'HSO_SUPPORT', 'DIAG_PRINT', 'SW_UART_DEBUG',
            'CONFIG_IPERF_SUPPORT', 'CONFIG_SENDTEST_SUPPORT',
            'CONFIG_XIP_ENABLE_READ_OVERTIME',
            'CONFIG_SUPPORT_WIFI', '_PRE_WLAN_FEATURE_FRW_IPC',
            'AT_COMMAND', 'BTH_TASK_EXIST', 'CHECKSUM_CHECK_TCP=0',
            'CHECKSUM_CHECK_UDP=0', 'UPDATE_WIFI_STATIC_LIB', '_PRE_WLAN_FEATURE_PK',
            'CONFIG_NV_SUPPORT_SINGLE_CORE_SYSTEM', 'CONFIG_OTA_UPDATE_SUPPORT',
            'CHBA_SUPPORT',"CHBA_LWIP_SWITCH=1","SW_UART_CHIP_DEFINE",'CONFIG_LWIP_LOWPOWER','CONFIG_ARP_ANNOUNCE_OPT',
            'LOSCFG_XTS_SUPPORT',
        ],
        'ram_component': [
            '-:liteos_207_0_0', 'liteos_208_5_0',
            '-:test_pinctrl',
            '-:test_hcc',
            '-:hal_cpu_hifi',
            'mbedtls_v3.6.0', 'mbedtls_harden', 'wpa_supplicant', 'wifi_drv_ws53','wifi_fe','wifi_hal_ws53', 'wifi_driver_tcm', 'wifi_hal_tcm', 'lwip',
            'lwip_tcm', 'wifi_service', 'at', 'wifi_at', 'plt_at',
            'wifi_alg_txbf', 'wifi_alg_temp_protect', 'wifi_alg_anti_interference',
            'wifi_alg_edca_opt', 'wifi_alg_cca_opt',
            'syschannel_dev',
            'bt_at', 'mips', 'hal_mips', 'bg_common', 'bth_gle', 'bt_host', 'bth_sdk',
            'bt_app', 'bts_header',
            'wifi_csa', 'wifi_frag', 'wifi_mbo', 'wifi_bsrp_nfrp', 'wifi_slp',
            'wifi_apf', 'wifi_11k', 'wifi_11v', 'wifi_auto_adjust_freq', 'wifi_11r',
            'wifi_repeater', 'wifi_csi', 'wifi_m2u', 'wifi_wps', 'wifi_wapi', 'wifi_blacklist',
             'wifi_sdp', 'wifi_wps', 'wifi_latency', 'wifi_promisc', 'wifi_tx_amsdu', 'wifi_uapsd_sta',
            'wifi_roam', 'wifi_ant_sel', 'wifi_psd', 'wifi_twt', 'wifi_btcoex', 'wifi_uapsd_ap',
             'wifi_dnb', 'wifi_sr', 'wifi_pk_txrx',
            'nv', 'nv_ws53', "partition", "partition_ws53",
            "cjson", 'libboundscheck_sscanf_s',
            'factory_ws53', 'xo_trim_port',
            'sle_netdev', 'achba', 'chba_at',
            "dfx_printer",
            'ohos_adapt',
            'little_fs', 'littlefs_adapt_ws53', 'printf_adapt',
            'update_common', 'update_common_ws53', 'update_storage',
        ],
        'ram_component_set': [],
        'ccflags': [
            *macro_ccflags['asic'],
        ],
        'hso_enable_bt': True,
        'nv_update':True,
    },
}

# custom copy rules, put it in target_group below and it takes effect.
# <root> means root path
# <out_root> means output_root path
# <pack_target> means target_group key_name

target_copy = {

}

target_group = {

}
