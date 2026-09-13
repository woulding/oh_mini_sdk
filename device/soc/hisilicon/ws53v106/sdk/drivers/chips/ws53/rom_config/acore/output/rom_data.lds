#ifdef _PRE_FEATURE_VENEER_ROM
#define VENEER_ROM_RAM_PLAT_D _SVENEER_ROM_RAM_PLAT_D = .;KEEP(*.o*(.data.strNullPointer));KEEP(*.o*(.data.strNullString));KEEP(*.o*(.data.wStrNullString));KEEP(*.o*(.data.g_hal_dma_lli_node_maxnum));KEEP(*.o*(.data.g_hal_dma_funcs));. += 4;KEEP(*.o*(.data.g_systick_ticks_per_sec));KEEP(*.o*(.data.g_hcc_handler_list));KEEP(*.o*(.data.g_loglevel));KEEP(*.o*(.data.g_hcc_long_packet_size));KEEP(*.o*(.data.g_tcxo_ticks_per_usec));KEEP(*.o*(.data.g_rtc_clock_value));. += 4;KEEP(*.o*(.data.g_rtc_quick_calc_value_1));KEEP(*.o*(.data.g_rtc_quick_calc_value_2));KEEP(*.o*(.data.g_hal_sdio_v151_funcs));KEEP(*.o*(.data.g_ipc_ctrl_base_addr));KEEP(*.o*(.data.g_ipc_memory_init_rx_config));KEEP(*.o*(.data.g_ipc_memory_init_tx_config));KEEP(*.o*(.data.g_hal_ipc_v150_funcs));KEEP(*.o*(.data.g_hal_rtc_v150_funcs));KEEP(*.o*(.data.g_hal_tcxo_v150_funcs));KEEP(*.o*(.data.g_hal_systick_v150_funcs));_EVENEER_ROM_RAM_PLAT_D = .;
#define VENEER_ROM_RAM_WIFI_D _SVENEER_ROM_RAM_WIFI_D = .;; _EVENEER_ROM_RAM_WIFI_D = .;
#define VENEER_ROM_RAM_BTC_D _SVENEER_ROM_RAM_BTC_D = .;; _EVENEER_ROM_RAM_BTC_D = .;
#define VENEER_ROM_RAM_BTH_D _SVENEER_ROM_RAM_BTH_D = .;; _EVENEER_ROM_RAM_BTH_D = .;
#else
#define VENEER_ROM_RAM_PLAT_D _SVENEER_ROM_RAM_PLAT_D = .;; _EVENEER_ROM_RAM_PLAT_D = .;
#define VENEER_ROM_RAM_WIFI_D _SVENEER_ROM_RAM_WIFI_D = .;; _EVENEER_ROM_RAM_WIFI_D = .;
#define VENEER_ROM_RAM_BTC_D _SVENEER_ROM_RAM_BTC_D = .;; _EVENEER_ROM_RAM_BTC_D = .;
#define VENEER_ROM_RAM_BTH_D _SVENEER_ROM_RAM_BTH_D = .;; _EVENEER_ROM_RAM_BTH_D = .;
#endif