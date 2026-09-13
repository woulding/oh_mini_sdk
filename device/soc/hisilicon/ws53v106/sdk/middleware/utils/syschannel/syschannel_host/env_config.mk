##############################CONFIGURATION##########################
CFG_3518EV300 = y
CFG_T23 = n
CFG_T41 = n
CFG_3519D = n
CFG_3516CV610 = n

SYSCHANNEL_DEBUG = n

###############################PLATFORM##############################
WLAN_CFLAGS +=-D_PRE_PLATFORM_JZ=1
WLAN_CFLAGS +=-D_PRE_PLATFORM_HISILICON=2
WLAN_CFLAGS +=-D_PRE_OS_PLATFORM=_PRE_PLATFORM_HISILICON

ifeq ($(SYSCHANNEL_DEBUG), y)
WLAN_CFLAGS += -D_PRE_SYSCHANNEL_DEBUG
endif
################################INCLUDE##############################
WLAN_CFLAGS += -I$(WLAN_DIR)/oal/linux
WLAN_CFLAGS += -I$(WLAN_DIR)/wal/linux
WLAN_CFLAGS += -I$(WLAN_DIR)/channel_host
WLAN_CFLAGS += -I$(WLAN_DIR)/../syschannel_common
WLAN_CFLAGS += -I$(WLAN_DIR)/../syschannel_api