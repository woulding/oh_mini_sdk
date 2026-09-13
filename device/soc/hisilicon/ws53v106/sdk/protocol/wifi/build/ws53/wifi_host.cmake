#[[
Description: CMake construct system.
Create: 2021-12-22
]]

set(COMPONENT_NAME wifi_drv_ws53)

set(SOURCES
    ${WIFI_DEVICE_DIR}/source/common/romable/common_dft_rom.c

    ${WIFI_DEVICE_DIR}/source/common/romable/wlan_util_common_rom.c
    #${WIFI_DEVICE_DIR}/source/common/romable/wlan_ring.c

    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/feature/interface/hmac_feature_interface.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/feature/interface/hmac_ccpriv.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_stat.c

    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_11i.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_11w.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_alg_config.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_alg_notify.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_ampdu_config.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_ant_switch.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_arp_offload.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_beacon.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_bsle.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_blockack.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_cali_mgmt.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_chan_mgmt.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_chr.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_config.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_crypto_tkip.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_data_acq.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_device.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_dfr.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_dfs.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_dfx.c
    #${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_dhcp_offload.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_encap_frame.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_encap_frame_ap.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_encap_frame_sta.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_fcs.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_feature_dft.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_fsm.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_ftm.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_isolation.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_keep_alive.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_al_tx_rx.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_m2s.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_main.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_achba.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_mfg.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_mgmt_ap.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_mgmt_bss_comm.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_mgmt_classifier.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_mgmt_sta.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_obss_sta.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_obss_ap.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_opmode.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_p2p.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_power.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_protection.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_proxy_arp.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_psm_ap.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_psm_sta.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_radar.c
    #${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_rekey_offload.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_reset.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_resource.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_rx_filter.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_scan.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_sme_sta.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_smps.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_sniffer.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_sta_pm.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_tcp_opt.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_thruput_test.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_tid.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_tx_mgmt.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_sample_daq.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_sample_daq_phy.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_txopps.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_user.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_vap.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_wmm.c
    #${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_wow.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_wur_ap.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_hook.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/mac/mac_device.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/mac/mac_frame.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/mac/mac_ie.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/mac/mac_regdomain.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/mac/mac_resource.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/mac/mac_user.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/mac/mac_vap.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/mac/oal_fsm.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/main/liteOS/wifi_main.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/oal/liteOS/oal_main.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/oal/liteOS/pm_temp.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/version/hmac_version.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/wal/common/wal_ccpriv_common.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/wal/common/wal_common.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/wal/common/wal_utils.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/wal/release/liteOS/soc_wifi_driver_api.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/wal/release/liteOS/wal_11d.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/wal/release/liteOS/wal_ccpriv.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/wal/release/liteOS/wal_cfg80211.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/wal/release/liteOS/wal_cfg80211_apt.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/wal/release/liteOS/wal_config.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/wal/release/liteOS/wal_config_sdp.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/wal/release/liteOS/wal_customize.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/wal/release/liteOS/wal_event.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/wal/release/liteOS/wal_event_msg.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/wal/release/liteOS/wal_ioctl.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/wal/release/liteOS/wal_liteos_sdp.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/wal/release/liteOS/wal_main.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/wal/release/liteOS/wal_regdb.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/wal/release/liteOS/wal_scan.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/wal/release/liteOS/wal_wpa_ioctl.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/wal/release/liteOS/wal_mfg_ccpriv.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/wal/debug/liteOS/wal_ccpriv_debug.c
    # HCC编译
    ${CMAKE_CURRENT_SOURCE_DIR}/test/ftrace.c
    ${CMAKE_CURRENT_SOURCE_DIR}/test/ftrace_hash.c
)

set(Wi-Fi-PUBLIC_HEADER
    ${WIFI_DEVICE_DIR}/sample/ws53
    ${WIFI_DEVICE_DIR}/source/common
    ${WIFI_DEVICE_DIR}/source/common/wifi_fe/calibrate/common_utils
    ${WIFI_DEVICE_DIR}/source/common/wifi_fe/calibrate/online_cali
    ${WIFI_DEVICE_DIR}/source/common/wifi_fe/calibrate/outer_if
    ${WIFI_DEVICE_DIR}/source/common/wifi_fe/fe_extern
    ${WIFI_DEVICE_DIR}/source/common/wifi_fe/fe_hal/phy
    ${WIFI_DEVICE_DIR}/source/common/wifi_fe/fe_hal/rf
    ${WIFI_DEVICE_DIR}/source/common/wifi_fe/fe_hal/phy/ws53
    ${WIFI_DEVICE_DIR}/source/common/wifi_fe/power_ctrl
    ${WIFI_DEVICE_DIR}/source/common/wifi_fe/rf_customize
    ${WIFI_DEVICE_DIR}/source/common/wifi_fe/equipment
    ${WIFI_DEVICE_DIR}/source/common/wifi_fe/spec/ws53

    ${WIFI_DEVICE_DIR}/source/inc
    ${WIFI_DEVICE_DIR}/source/inc/romable
    ${WIFI_DEVICE_DIR}/source/inc/romable/msg
    ${WIFI_DEVICE_DIR}/source/inc/romable/alg
    ${WIFI_DEVICE_DIR}/source/inc/romable/device_common
    ${WIFI_DEVICE_DIR}/source/inc/romable/hal/ws53
    ${WIFI_DEVICE_DIR}/source/inc/romable/hal/ws53/spec
    ${WIFI_DEVICE_DIR}/source/inc/romable/hal/ws53/soc

    ${CMAKE_CURRENT_SOURCE_DIR}/source/frw/
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/board
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/feature
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/forward
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/forward/liteOS
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/feature/interface
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/frw
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hal
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hal/cali/hh503/mpw/cali_packetram
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hal/cali/hh503/mpw/cali_packetram/common
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hal/cali/hh503/mpw/cali_packetram/rf
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hal/hal_ws53
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hal/hal_ws53/hh503
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hal/hal_ws53/romable
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hal/hal_ws53/romable/hh503
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hal/hal_ws53/spec
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hal/hal_verify/
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_verify/
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/inc
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/inc/dmac
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/inc/frw
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/inc/hal
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/inc/hcc
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/inc/hmac
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/inc/liteOS
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/inc/mac
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/inc/oal
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/inc/oal/liteOS
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/inc/oal/liteOS/pm
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/inc/oam
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/inc/romable
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/inc/wal
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/mac
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/main/liteOS
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/oal
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/oal/liteOS
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/oam
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/platform/inc/oal
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/platform/osal
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/pm
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/sdt
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/version
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/wal/common
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/wal/release/liteOS
    ${CMAKE_SOURCE_DIR}/include/middleware/services/wifi/host
)

set(Wi-Fi-PRIVATE_HEADER
    ${CMAKE_SOURCE_DIR}/drivers/chips/ws53/arch/include
    ${CMAKE_SOURCE_DIR}/open_source/lwip/lwip_v2.1.3/src/include

    # 暂时以复制的形式导入，待平台整改后更改引用
    ${CMAKE_SOURCE_DIR}/protocol/wifi/source/host/inc/cfbb_temp_inc
    ${CMAKE_SOURCE_DIR}/protocol/wifi/source/host/inc/cfbb_temp_inc/soc
    # ftrace编译引用
    ${CMAKE_SOURCE_DIR}/protocol/wifi/test

    #osal
    ${CMAKE_SOURCE_DIR}/middleware/utils/common_headers/osal
    ${CMAKE_SOURCE_DIR}/kernel/osal/include
    ${CMAKE_SOURCE_DIR}/kernel/osal_adapt/inc

    #driver
    ${CMAKE_SOURCE_DIR}/drivers/drivers/driver

    # HCC编译引用
    ${CMAKE_SOURCE_DIR}/drivers/chips/ws53/rom/app/middleware/utils/hcc/inc
)

set(Wi-Fi-PRIVATE_DEFINES
    _PRE_CONFIG_WLAN_THRANS_THREAD_DEBUG
    _PRE_DBAC_HI_TIMERX=0
    _PRE_DBAC_MDRV_TIMER=1
    _PRE_DBAC_OFFLOAD_TIMER=2
    _PRE_WLAN_FEATRUE_DBAC_TIMER=_PRE_DBAC_OFFLOAD_TIMER
    _PRE_DEBUG_MODE_USER_TRACK
    _PRE_DFX_USER_CONNECT_INFO_RECORD
    _PRE_FRW_EVENT_PROCESS_TRACE_DEBUG
    _PRE_FRW_FEATURE_PROCCESS_ENTITY_TASKLET=1
    _PRE_FRW_FEATURE_PROCCESS_ENTITY_THREAD=0
    _PRE_FRW_FEATURE_PROCCESS_ENTITY_TYPE=_PRE_FRW_FEATURE_PROCCESS_ENTITY_THREAD
    _PRE_FRW_TIMER_BIND_CPU
    _PRE_HW_DEVICE_REGISTER_WITP=0
    _PRE_MAX_WIDTH_20M=0
    _PRE_MAX_WIDTH_40M=1
    _PRE_MAX_WIDTH_80M=2
    _PRE_WLAN_FEATURE_WIDTH_MODE=_PRE_MAX_WIDTH_40M
    _PRE_MULTI_CORE_MODE_SMP=0
    _PRE_MULTI_CORE_MODE_PIPELINE_AMP=1
    _PRE_MULTI_CORE_MODE_OFFLOAD_HMAC=2
    _PRE_MULTI_CORE_MODE_OFFLOAD_DMAC=3
    _PRE_MULTI_CORE_MODE=_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC
    _PRE_OAL_FEATURE_KEY_PROCESS_TRACE
    _PRE_OAL_FEATURE_SDT
    _PRE_OAL_FEATURE_TASK_NEST_LOCK
    _PRE_PLAT_FEATURE_CUSTOMIZE
    _PRE_PRODUCT_ID_WITP=0
    _PRE_PRODUCT_ID_MP13_HOST=6
    _PRE_PRODUCT_ID_MP0X_HOST
    _PRE_PRODUCT_ID_HOST
    _PRE_PRODUCT_ID=_PRE_PRODUCT_ID_MP13_HOST
    _PRE_PSM_DEBUG_MODE
    _PRE_SUPPORT_DFS
    _PRE_TARGET_PRODUCT_TYPE_5610EVB=0
    _PRE_TARGET_PRODUCT_TYPE_5610DMB=1
    _PRE_TARGET_PRODUCT_TYPE_1102COMMON=2
    _PRE_TARGET_PRODUCT_TYPE_VSPM310DMB=3
    _PRE_TARGET_PRODUCT_TYPE_WS835DMB=4
    _PRE_TARGET_PRODUCT_TYPE_E5=5
    _PRE_TARGET_PRODUCT_TYPE_ONT=6
    _PRE_TARGET_PRODUCT_TYPE_5630HERA=7
    _PRE_TARGET_PRODUCT_TYPE_CPE=8
    _PRE_CONFIG_TARGET_PRODUCT=_PRE_TARGET_PRODUCT_TYPE_1102COMMON
    _PRE_TEST_MODE_OFF=0
    _PRE_TEST_MODE_UT=1
    _PRE_TEST_MODE_ST=2
    _PRE_TEST_MODE_BOARD_ST=3
    _PRE_TEST_MODE=_PRE_TEST_MODE_OFF
    _PRE_WLAN_MP13_DDC_BUGFIX
    _PRE_WLAN_MP13_TCP_SMALL_QUEUE_BUGFIX
    _PRE_WLAN_WS86_FPGA
    _PRE_WLAN_802_11B=1
    _PRE_WLAN_802_11G=2
    _PRE_WLAN_802_11A=4
    _PRE_WLAN_802_11N=8
    _PRE_WLAN_PROTOCAL_VER=_PRE_WLAN_802_11B+_PRE_WLAN_802_11G+_PRE_WLAN_802_11A+_PRE_WLAN_802_11N
    _PRE_WLAN_CFGID_DEBUG
    _PRE_WLAN_CHIP_ASIC=2
    _PRE_WLAN_CHIP_FPGA=3
    _PRE_WLAN_CHIP_VERSION=_PRE_WLAN_CHIP_ASIC
    _PRE_WLAN_DEBUG_REG_PERIOD_REPORT
    _PRE_WLAN_DFT_DUMP_DSCR
    _PRE_WLAN_PKT_DEBUG
    _PRE_WLAN_DFT_IRQ_STAT
    _PRE_WLAN_DFT_STAT
    _PRE_WLAN_SUPPORT_CCPRIV_CMD
    #_PRE_WLAN_SUPPORT_VHT
    #_PRE_WLAN_FEATURE_11AC2G
    #_PRE_WLAN_802_11AC=16
    #_PRE_WLAN_11AC_20M_ONLY
    _PRE_WLAN_FEATURE_11AX
    _PRE_WLAN_FEATURE_TWT
    _PRE_WLAN_11AX_20M_ONLY
    _PRE_WLAN_FEATURE_11AX_ER_SU_DCM
    _PRE_WLAN_FEATURE_BSRP
    _PRE_WLAN_FEATURE_SR
    _PRE_WLAN_FEATURE_11D
    _PRE_WLAN_FEATURE_11K
    _PRE_WLAN_FEATURE_11R
    _PRE_WLAN_FEATURE_11V
    _PRE_WLAN_FEATURE_20_40_80_COEXIST
    _PRE_WLAN_FEATURE_ACS
    _PRE_WLAN_FEATURE_AGGR_OPTIMIZE
    _PRE_WLAN_FEATURE_ALG_CFG
    _PRE_WLAN_FEATURE_ALWAYS_TX
    _PRE_WLAN_FEATURE_DAQ
    _PRE_WLAN_FEATURE_AMPDU
    _PRE_WLAN_FEATURE_AMPDU_TX_HW
    _PRE_WLAN_FEATURE_AMSDU
    _PRE_WLAN_FEATURE_ANT_SEL
    #_PRE_WLAN_FEATURE_ANT_SWITCH
    _PRE_WLAN_FEATURE_APF
    _PRE_WLAN_FEATURE_CSA
    _PRE_WLAN_FEATURE_BLACKLIST
    _PRE_WLAN_FEATURE_BTCOEX
    #_PRE_WLAN_FEATURE_BT_SUPPORT
    _PRE_WLAN_FEATURE_EXT_BTCOEX
    _PRE_WLAN_FEATURE_CCPRIV
    _PRE_WLAN_FEATURE_CLASSIFY
    _PRE_WLAN_FEATURE_COMP_TEMP
    _PRE_WLAN_FEATURE_CSI
    _PRE_WLAN_FEATURE_CUSTOM_SECURITY
    _PRE_WLAN_FEATURE_CUSTOMIZE_PRE_WLAN_FEATURE_WIDTH_MODE=_PRE_MAX_WIDTH_20M
    _PRE_WLAN_FEATURE_DBDC
    _PRE_WLAN_FEATURE_DEV_RX_DSCR_CTL
    _PRE_WLAN_FEATURE_DYNAMIC_BANDWIDTH
    _PRE_WLAN_FEATURE_FRW_DEBUG
    _PRE_WLAN_FEATURE_GCMP_256_CCMP256
    _PRE_WLAN_FEATURE_SLP
    _PRE_WLAN_FEATURE_WS92_MERGE
    _PRE_WLAN_FEATURE_MAC_PARSE_TIM
    _PRE_WLAN_FEATURE_MEM_OPT
    _PRE_WLAN_FEATURE_MIDDLE_GI
    _PRE_WLAN_FEATURE_MVAP_SCH
    _PRE_WLAN_FEATURE_NO_FRM_INT
    #_PRE_WLAN_FEATURE_OFFLOAD_FLOWCTL
    _PRE_WLAN_FEATURE_STAT
    _PRE_WLAN_FEATURE_PK_MODE
    _PRE_WLAN_FEATURE_PM
    _PRE_WLAN_FFD
    _PRE_WLAN_FEATURE_PMF
    _PRE_WLAN_FEATURE_PSM
    _PRE_WLAN_FEATURE_ROAM
    _PRE_WLAN_FEATURE_SCH_STRATEGY_PROPO_FAIR
    _PRE_WLAN_FEATURE_SCH_STRATEGY_ROUND_ROBIN
    _PRE_WLAN_FEATURE_SINGLE_PROXYSTA
    _PRE_WLAN_FEATURE_SINGLE_RF_RX_BCN
    _PRE_WLAN_FEATURE_SPECIAL_PKT_LOG
    _PRE_WLAN_FEATURE_STA_DNB
    _PRE_WLAN_FEATURE_STA_PM
    _PRE_WLAN_FEATURE_STA_UAPSD
    _PRE_WLAN_FEATURE_TPC_TX_DSCR_BIT8=0
    _PRE_WLAN_FEATURE_TPC_TX_DSCR_BIT20=1
    _PRE_WLAN_FEATURE_TPC_TX_DSCR_BITX=_PRE_WLAN_FEATURE_TPC_TX_DSCR_BIT20
    _PRE_WLAN_FEATURE_UAPSD
    _PRE_WLAN_FEATURE_USER_RESP_POWER
    _PRE_WLAN_FEATURE_VOWIFI
    _PRE_WLAN_FEATURE_WPA3
    _PRE_WLAN_FEATURE_POWERSAVE
    _PRE_WLAN_LATENCY_STAT
    _PRE_WLAN_PHY_IRQ_ENABLE
    _PRE_WLAN_PLAT_WS83
    _PRE_WLAN_RATE_RTS
    _PRE_WLAN_SIM_CHIP=0
    _PRE_WLAN_REAL_CHIP=1
    _PRE_WLAN_CHIP_SIM=_PRE_WLAN_REAL_CHIP
    _PRE_WLAN_REG_DEBUG
    _PRE_WLAN_ONLINE_CALI
    _PRE_WLAN_ONLINE_IQ_CALI
    _PRE_WLAN_SUPPORT_SINGLE_NSS=0
    _PRE_WLAN_SUPPORT_DOUBLE_NSS=1
    _PRE_WLAN_SUPPORT_TRIPLE_NSS=2
    _PRE_WLAN_SUPPORT_FOUR_NSS=3
    _PRE_WLAN_FEATURE_NSS_MODE=_PRE_WLAN_SUPPORT_SINGLE_NSS
    _PRE_WLAN_FEATURE_LDPC_TX_ONLY
    _PRE_WLAN_PEAK_PERFORMANCE_DFX
    CONFIG_HMAC_SUPPORT_FLOW_CONTRL
    CUSTOMIZE_NV_WS92
    DMAC_ON_HOST
    HH503_WL_BUS=WL_BUS_SDIO
    RELEASE_TYPE=DEBUG
    WL_BUS_SDIO=0
    WL_BUS_PCIE=1
    WL_BUS_USB=2
    _PRE_WLAN_SMALL_MEMORY
    _PRE_WLAN_SMOOTH_PHASE
    _PRE_LWIP_ZERO_COPY_MALLOC_SKB
    #以下是非重要，可关闭的宏，其它宏请加载此宏的前面
    _PRE_WIFI_DEBUG
    #_PRE_WLAN_FEATURE_TX_CLASSIFY_LAN_TO_WLAN
    _PRE_WLAN_POWERSAVE_DEBUG
)

set(Wi-Fi-PUBLIC_DEFINES
    _PRE_WLAN_FEATURE_WS53
    __LITEOS__
    _PRE_BIG_CPU_ENDIAN=0
    _PRE_LITTLE_CPU_ENDIAN=1
    _PRE_CPU_ENDIAN=_PRE_LITTLE_CPU_ENDIAN
    _PRE_CHIP_BITS_MIPS32=0
    _PRE_CHIP_BITS_MIPS64=1
    _PRE_CHIP_BITS=_PRE_CHIP_BITS_MIPS32
    _PRE_CONFIG_CONN_SOFTWDFT
    _PRE_CONFIG_PANIC_DUMP_SUPPORT
    _PRE_OS_VERSION_LINUX=0
    _PRE_OS_VERSION_WIN32=1
    _PRE_OS_VERSION_WINDOWS=2
    _PRE_OS_VERSION_RAW=3
    _PRE_OS_VERSION_HiRTOS=4
    _PRE_OS_VERSION_WIN32_RAW=5
    _PRE_OS_VERSION_LITEOS=6
    _PRE_OS_VERSION=_PRE_OS_VERSION_LITEOS
    _PRE_WLAN_FEATURE_WOW_OFFLOAD
    _PRE_WLAN_FEATURE_ARP_OFFLOAD
    _PRE_WLAN_FEATURE_INTRF_MODE
    _PRE_WLAN_FEATURE_SDP
    _PRE_LWIP_ZERO_COPY
    CONFIG_LAMBORGHINI_DEVICE
    CONFIG_NON_OS
    CONFIG_SPIN_LOCK_MAGIC_DEBUG
    CONFIG_SUPPORT_NEW_DIAG
    CONFIG_SUPPORT_TSENSOR_VERSION_D
    CONFIG_SYSERR_INFO_SUPPORT_PRINT
    LOSCFG_PLATFORM_BSP_RISCV_PLIC
    SECUREC_ENABLE_SPRINTF_FLOAT=0
    SECUREC_HAVE_WCTOMB=0
    #CONFIG_SUPPORT_MSG_QUEUE_PRIORITY
    _PRE_WIFI_PRINTK
)

if(${SMALLER})
    list(REMOVE_ITEM Wi-Fi-PRIVATE_DEFINES
        _PRE_WLAN_PKT_DEBUG
        _PRE_WIFI_DEBUG
        _PRE_WLAN_CFGID_DEBUG
        _PRE_WLAN_DFT_STAT
        _PRE_WLAN_FEATURE_DAQ
        _PRE_WLAN_FEATURE_TWT
        _PRE_WLAN_DFT_DUMP_DSCR
        _PRE_WLAN_DFT_IRQ_STAT
        _PRE_WLAN_FEATURE_SNIFFER
        _PRE_WLAN_LATENCY_STAT
        _PRE_WLAN_FEATURE_P2P
        _PRE_WLAN_FEATURE_SR
        _PRE_WLAN_FEATURE_ANT_SEL
        _PRE_WLAN_FEATURE_BSRP
        _PRE_WLAN_FEATURE_STAT
        _PRE_WLAN_FEATURE_M2U
        _PRE_WLAN_FEATURE_SLP
        _PRE_WLAN_FEATURE_ANT_SWITCH
        _PRE_WLAN_FEATURE_SPECIAL_PKT_LOG
        _PRE_WLAN_PEAK_PERFORMANCE_DFX
    )
    list(REMOVE_ITEM Wi-Fi-PUBLIC_DEFINES
        _PRE_WLAN_FEATURE_SDP
        _PRE_WIFI_PRINTK
    )
    list(APPEND Wi-Fi-PRIVATE_DEFINES
        _PRE_WLAN_TCM_SMALLER
    )
endif()

if(_PRE_WLAN_FEATURE_TX_CLASSIFY_LAN_TO_WLAN IN_LIST Wi-Fi-PRIVATE_DEFINES)
    list(APPEND SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_traffic_classify.c
    )
endif()

# wifi维测上报
if("CONFIG_WIFI_INFO_REPORT" IN_LIST DEFINES)
list(APPEND SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/feature/hmac_net_diagnosis.c
)
list(APPEND Wi-Fi-PRIVATE_DEFINES
    _PRE_WLAN_FEATURE_NET_DIAGNOSIS
    _PRE_WLAN_FEATURE_STA_CHANNEL_SCORING # 信道评分
)
if(_PRE_WLAN_FEATURE_STA_CHANNEL_SCORING IN_LIST Wi-Fi-PRIVATE_DEFINES)
list(APPEND SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hmac/hmac_sta_channel_scoring.c
)
endif()
endif()

if(BOARD_ASIC IN_LIST DEFINES)
    list(APPEND Wi-Fi-PRIVATE_DEFINES
        BOARD_ASIC_WIFI
    )
else()
    list(APPEND Wi-Fi-PRIVATE_DEFINES
        BOARD_FPGA_WIFI
        _PRE_WLAN_03_MPW_RF
    )
endif()

# use this when you want to add ccflags like -include xxx
set(Wi-Fi-COMPONENT_PUBLIC_CCFLAGS
)

set(Wi-Fi-COMPONENT_CCFLAGS
    -Wno-error=pointer-sign
    -Wno-error=unused-parameter
    -Wno-error=unused-variable
    -Wno-error=unused-but-set-variable
    -Wno-error=unused-function
    -Wno-error=missing-field-initializers
    # 使用ftrace时开启此选项
    # -finstrument-functions
)

set(Wi-Fi-WHOLE_LINK
    true
)

set(Wi-Fi-MAIN_COMPONENT
    false
)

macro(add_base_config)
    set(PUBLIC_HEADER            ${Wi-Fi-PUBLIC_HEADER})
    set(PRIVATE_HEADER           ${Wi-Fi-PRIVATE_HEADER})
    set(PRIVATE_DEFINES          ${Wi-Fi-PRIVATE_DEFINES})
    set(PUBLIC_DEFINES           ${Wi-Fi-PUBLIC_DEFINES})
    set(COMPONENT_PUBLIC_CCFLAGS ${Wi-Fi-COMPONENT_PUBLIC_CCFLAGS})
    set(COMPONENT_CCFLAGS        ${Wi-Fi-COMPONENT_CCFLAGS})
    set(WHOLE_LINK               ${Wi-Fi-WHOLE_LINK})
    set(MAIN_COMPONENT           ${Wi-Fi-MAIN_COMPONENT})
    if("UPDATE_WIFI_STATIC_LIB" IN_LIST DEFINES)
        set(LIB_OUT_PATH ${BIN_DIR}/${CHIP}/libs/wifi/${TARGET_COMMAND})
    endif()
endmacro()

set(LIBRARY_OUTPUT_PATH ${BIN_DIR}/${CHIP}/libs/wifi/${TARGET_COMMAND})
# 添加算法源码和头文件
wifi_alg_compiler_entry(ws53_alg_host_wifi OUT_SOURCES SOURCES OUT_INCLUDES Wi-Fi-PUBLIC_HEADER OUT_DEFINES Wi-Fi-PRIVATE_DEFINES
    WIFI_SOURCES ${SOURCES} WIFI_INCLUDES ${Wi-Fi-PUBLIC_HEADER} WIFI_DEFINES ${Wi-Fi-PRIVATE_DEFINES})
add_base_config()
build_component()

# 编译算法独立组件
wifi_alg_independent_build(ws53_alg_host_ind_wifi)

# Wi-Fi TCM组件
set(COMPONENT_NAME wifi_driver_tcm)
set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/forward/hmac_rx_data.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/forward/hmac_rx_data_event.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/forward/hmac_rx_data_feature.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/forward/hmac_rx_data_filter.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/forward/hmac_tx_data.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/forward/hmac_tx_encap.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/forward/hmac_tx_mpdu_adapt.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/forward/hmac_tx_mpdu_queue.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/forward/liteOS/oal_skbuff.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/forward/liteOS/oal_netbuf.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/frw/frw_common.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/frw/frw_hcc_adapt.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/frw/frw_hmac.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/frw/frw_hmac_adapt.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/frw/frw_main.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/frw/frw_thread.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/frw/frw_timer.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/frw/frw_util_notifier.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/mac/mac_mem.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/oal/liteOS/oal_net.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/wal/release/liteOS/wal_net.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/wal/release/liteOS/wal_net_bridge.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/mac/mac_data.c
)
add_base_config()
build_component()

# WIFI PK TXRX
set(COMPONENT_NAME "wifi_pk_txrx")
set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/forward/hmac_rx_pk.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/forward/hmac_tx_pk.c
)
add_base_config()
build_component()

# FEATURE CSA
set(COMPONENT_NAME "wifi_csa")
set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/feature/hmac_csa_ap.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/feature/hmac_csa_sta.c
)
add_base_config()
build_component()

# FEATURE FRAG
set(COMPONENT_NAME "wifi_frag")
set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/feature/hmac_frag.c
)
add_base_config()
build_component()

# FEATURE MBO
set(COMPONENT_NAME "wifi_mbo")
set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/feature/hmac_mbo.c
)
add_base_config()
build_component()

# FEATURE BSRP_NFRP
set(COMPONENT_NAME "wifi_bsrp_nfrp")
set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/feature/hmac_bsrp_nfrp.c
)
add_base_config()
build_component()

# FEATURE SLP
set(COMPONENT_NAME "wifi_slp")
set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/feature/hmac_slp.c
)
add_base_config()
build_component()

# FEATURE APF
set(COMPONENT_NAME "wifi_apf")
set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/feature/hmac_apf.c
)
add_base_config()
build_component()

# FEATURE 11k
set(COMPONENT_NAME "wifi_11k")
set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/feature/hmac_11k.c
)
add_base_config()
build_component()

# FEATURE 11v
set(COMPONENT_NAME "wifi_11v")
set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/feature/hmac_11v.c
)
add_base_config()
build_component()

# FEATURE wifi_auto_adjust_freq
set(COMPONENT_NAME "wifi_auto_adjust_freq")
set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/feature/hmac_auto_adjust_freq.c
)
add_base_config()
build_component()

# FEATURE 11r
set(COMPONENT_NAME "wifi_11r")
set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/feature/hmac_11r.c
)
add_base_config()
build_component()

# FEATURE REPEATER
set(COMPONENT_NAME "wifi_repeater")
set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/feature/hmac_single_proxysta.c
)
add_base_config()
build_component()

# FEATURE CSI
set(COMPONENT_NAME "wifi_csi")
set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/feature/hmac_csi.c
)
add_base_config()
build_component()

# FEATURE M2U
set(COMPONENT_NAME "wifi_m2u")
set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/feature/hmac_m2u.c
)
add_base_config()
build_component()

# FEATURE BLACKLIST
set(COMPONENT_NAME "wifi_blacklist")
set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/feature/hmac_blacklist.c
)
add_base_config()
build_component()

# FEATURE wapi
set(COMPONENT_NAME "wifi_wapi")
set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/feature/hmac_wapi.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/feature/hmac_wapi_sms4.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/feature/hmac_wapi_wpi.c
)
add_base_config()
build_component()

# FEATURE sdp
set(COMPONENT_NAME "wifi_sdp")
set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/feature/hmac_sdp.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/feature/hmac_sdp_test.c
)
add_base_config()
build_component()

# FEATURE WPS
set(COMPONENT_NAME "wifi_wps")
set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/feature/hmac_wps.c
)
add_base_config()
build_component()

# FEATURE latency
set(COMPONENT_NAME "wifi_latency")
set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/feature/hmac_latency_stat.c
)
add_base_config()
build_component()

# FEATURE promisc
set(COMPONENT_NAME "wifi_promisc")
set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/feature/hmac_promisc.c
)
add_base_config()
build_component()

# FEATURE tx_amsdu
set(COMPONENT_NAME "wifi_tx_amsdu")
set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/feature/hmac_tx_amsdu.c
)
add_base_config()
build_component()

# FEATURE uapsd_sta
set(COMPONENT_NAME "wifi_uapsd_sta")
set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/feature/hmac_uapsd_sta.c
)
add_base_config()
build_component()

# FEATURE roam
set(COMPONENT_NAME "wifi_roam")
set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/feature/hmac_roam_alg.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/feature/hmac_roam_connect.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/feature/hmac_roam_main.c
)
add_base_config()
build_component()

# FEATURE ant_sel
set(COMPONENT_NAME "wifi_ant_sel")
set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/feature/hmac_ant_sel.c
)
add_base_config()
build_component()

# FEATURE PSD
set(COMPONENT_NAME "wifi_psd")
set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/feature/hmac_psd.c
)
add_base_config()
build_component()

# FEATURE twt
set(COMPONENT_NAME "wifi_twt")
set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/feature/hmac_twt.c
)
add_base_config()
build_component()

# FEATURE btcoex
set(COMPONENT_NAME "wifi_btcoex")
set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/feature/hmac_btcoex.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/feature/hmac_btcoex_ba.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/feature/hmac_btcoex_btsta.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/feature/hmac_btcoex_m2s.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/feature/hmac_btcoex_notify.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/feature/hmac_btcoex_ps.c
)
add_base_config()
build_component()

# FEATURE uapsd_ap
set(COMPONENT_NAME "wifi_uapsd_ap")
set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/feature/hmac_uapsd.c
)
add_base_config()
build_component()

# FEATURE dnb
set(COMPONENT_NAME "wifi_dnb")
set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/feature/hmac_dnb_sta.c
)
add_base_config()
build_component()

# FEATURE sr
set(COMPONENT_NAME "wifi_sr")
set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/feature/hmac_sr_sta.c
)
add_base_config()
build_component()

# FEATURE wifi_fe
set(COMPONENT_NAME "wifi_fe")
set(SOURCES
    ${WIFI_DEVICE_DIR}/source/common/wifi_fe/calibrate/common_utils/cali_rf_temp_code.c
    ${WIFI_DEVICE_DIR}/source/common/wifi_fe/calibrate/online_cali/cali_online.c
    ${WIFI_DEVICE_DIR}/source/common/wifi_fe/calibrate/online_cali/cali_online_tx_pwr.c
    ${WIFI_DEVICE_DIR}/source/common/wifi_fe/calibrate/online_cali/fe_log_calc_rom.c
    ${WIFI_DEVICE_DIR}/source/common/wifi_fe/calibrate/online_cali/cali_online_common.c
    ${WIFI_DEVICE_DIR}/source/common/wifi_fe/calibrate/online_cali/cali_online_iq_fsm.c
    ${WIFI_DEVICE_DIR}/source/common/wifi_fe/fe_hal/phy/ws53/fe_power_host.c
    ${WIFI_DEVICE_DIR}/source/common/wifi_fe/fe_hal/phy/ws53/fe_hal_phy_if_host.c
    ${WIFI_DEVICE_DIR}/source/common/wifi_fe/fe_hal/phy/ws53/fe_hal_phy_reg_if_host.c
    ${WIFI_DEVICE_DIR}/source/common/wifi_fe/fe_hal/phy/ws53/fe_hal_phy_daq.c
    ${WIFI_DEVICE_DIR}/source/common/wifi_fe/fe_hal/rf/ws53/fe_hal_gp_if.c
    ${WIFI_DEVICE_DIR}/source/common/wifi_fe/fe_hal/rf/ws53/fe_hal_rf_if_temperate.c
    ${WIFI_DEVICE_DIR}/source/common/wifi_fe/fe_hal/rf/ws53/fe_hal_equipment.c
    ${WIFI_DEVICE_DIR}/source/common/wifi_fe/power_ctrl/fe_init_pow.c
    ${WIFI_DEVICE_DIR}/source/common/wifi_fe/power_ctrl/fe_tpc_rate_pow.c
    ${WIFI_DEVICE_DIR}/source/common/wifi_fe/spec/ws53/power_ctrl_spec.c
    ${WIFI_DEVICE_DIR}/source/common/wifi_fe/spec/ws53/power_ppa_ctrl_spec.c
    ${WIFI_DEVICE_DIR}/source/common/wifi_fe/rf_customize/fe_rf_customize_rx_insert_loss.c
    ${WIFI_DEVICE_DIR}/source/common/wifi_fe/rf_customize/fe_rf_customize_power.c
    ${WIFI_DEVICE_DIR}/source/common/wifi_fe/rf_customize/fe_rf_customize_power_cali.c
    ${WIFI_DEVICE_DIR}/source/common/wifi_fe/equipment/fe_equipment.c
)
add_base_config()
build_component()

# FEATURE wifi_hal_tcm
set(COMPONENT_NAME "wifi_hal_tcm")
set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hal/hal_ws53/hh503/hal_gp_reg.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hal/hal_ws53/hal_reg_opt.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hal/hal_ws53/hh503/hal_pm.c
)
add_base_config()
build_component()

# FEATURE wifi_hal_ws53
set(COMPONENT_NAME "wifi_hal_ws53")
set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hal/hal_ws53/hal_chip.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hal/hal_ws53/hal_device.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hal/hal_ws53/hal_init.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hal/hal_ws53/hal_main.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hal/hal_ws53/hal_device_fsm.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hal/hal_ws53/hh503/hal_alg_rts.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hal/hal_ws53/hh503/hal_alg_tpc.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hal/hal_ws53/hh503/hal_alg_txbf.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hal/hal_ws53/hh503/hal_anti_intf.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hal/hal_ws53/hh503/hal_coex_reg.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hal/hal_ws53/hh503/hal_csi.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hal/hal_ws53/hh503/hal_mac.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hal/hal_ws53/hh503/hal_mfg.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hal/hal_ws53/hh503/hal_phy.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hal/hal_ws53/hh503/hal_power.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hal/hal_ws53/hh503/hal_reset.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hal/hal_ws53/hh503/hal_rf.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hal/hal_ws53/hh503/hal_tbtt.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hal/hal_ws53/hh503/hal_chan_mgmt.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hal/hal_ws53/hh503/hal_dscr.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hal/hal_ws53/hh503/hal_rx_filter.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hal/hal_ws53/hh503/hal_tpc.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hal/hal_ws53/hh503/hal_ant_sel_rom.c
    ${CMAKE_CURRENT_SOURCE_DIR}/source/host/hal/hal_ws53/hh503/hal_psd.c
)
add_base_config()
build_component()
