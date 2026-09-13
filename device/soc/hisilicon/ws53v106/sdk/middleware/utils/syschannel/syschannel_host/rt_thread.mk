CFLAGS += -D__RTTHREAD__
CFLAGS += -DSYSCHANNEL_LITTLE_ENDIAN=1
CFLAGS += -DSYSCHANNEL_BIG_ENDIAN=2
CFLAGS += -DSYSCHANNEL_ENDIAN=SYSCHANNEL_LITTLE_ENDIAN
# CFLAGS += -DWSCFG_ONEIMAGE
CFLAGS += -D_PRE_OS_VERSION_LINUX=1
CFLAGS += -D_PRE_OS_VERSION_RTTHREAD=9
CFLAGS += -D_PRE_OS_VERSION=_PRE_OS_VERSION_RTTHREAD
CFLAGS += -I../syschannel/middleware/utils/syschannel/syschannel_host/oneimage -include ../syschannel/middleware/utils/syschannel/syschannel_host/oneimage/oneimage.h
CFLAGS += -std=gnu99 -Wno-declaration-after-statement -fsigned-char -freg-struct-return -Wtrampolines -Wfloat-equal -fvisibility=hidden
# CFLAGS += -DETH_PAD_SIZE=2
CFLAGS += -D_PRE_PLATFORM_JZ=1
CFLAGS += -D_PRE_PLATFORM_HISILICON=2
CFLAGS += -D_PRE_OS_PLATFORM=_PRE_PLATFORM_HISILICON
CFLAGS += -D_PRE_SYSCHANNEL_DEBUG
# CFLAGS += -DCONFIG_HCC_SUPPORT_REG_OPT=1
CFLAGS += -DCONFIG_HCC_SUPPORT_DFX
CFLAGS += -DCONFIG_HCC_SUPPORT_FLOW_CONTRL
CFLAGS += -DCONFIG_HCC_SUPPORT_UNC_POOL
CFLAGS += -DCONFIG_HCC_SUPPORT_SDIO
CFLAGS += -DCONFIG_HCC_SUPPORT_TEST
CFLAGS += -DCONFIG_HCC_SUPPORT_TEST_SYSCH
CFLAGS += -DCONFIG_HCC_CONFIG_DATA_FC

CFLAGS += -I../syschannel/middleware/utils/syschannel/syschannel_host
CFLAGS += -I../syschannel/kernel/osal/include
CFLAGS += -I../syschannel/middleware/utils/common_headers/osal
CFLAGS += -I../syschannel/kernel/osal_adapt/inc
CFLAGS += -I../syschannel/kernel/osal/src/linux/kernel
CFLAGS += -I../syschannel/kernel/osal/src/linux/kernel/media
CFLAGS += -I../syschannel/open_source/libboundscheck/include
CFLAGS += -I../syschannel/include
CFLAGS += -I../syschannel/middleware/utils/hcc/inc
CFLAGS += -I../syschannel/middleware/utils/hcc/cfg
CFLAGS += -I../syschannel/middleware/utils/hcc/comm
CFLAGS += -I../syschannel/middleware/utils/hcc/host
CFLAGS += -I../syschannel/middleware/utils/common_headers
CFLAGS += -I../syschannel/middleware/utils/common_headers/native
CFLAGS += -I../syschannel/middleware/utils/syschannel/syschannel_host/wal/rtthread
CFLAGS += -I../syschannel/middleware/utils/syschannel/syschannel_host/channel_host
CFLAGS += -I../syschannel/middleware/utils/syschannel/syschannel_host/../syschannel_common
CFLAGS += -I../syschannel/middleware/utils/syschannel/syschannel_host/../syschannel_api