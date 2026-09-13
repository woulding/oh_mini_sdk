src = $(PWD)
EXTRA_CFLAGS := -I$(src) -Wall -fno-aggressive-loop-optimizations -ldl -ffunction-sections -fdata-sections -O2 -fstack-protector-strong -fPIC -mcpu=cortex-a53
EXTRA_CFLAGS += -I$(SECUREC_INC) -I$(OSAL_INC) -I$(OSAL_SRC)/user -I$(DRVAL_IRQ_DIR)/include -I$(DRVAL_PROC_DIR)/include -I$(DRVAL_CHIPER_DIR)/$(DRVAL_CHIPER) -I$(DRVAL_INC)/linux
EXTRA_CFLAGS += -DUSER_BIT_64
EXTRA_CFLAGS += -Werror
OBJS += osal_addr.o
OBJS += osal_atomic.o
OBJS += osal_barrier.o
OBJS += osal_debug.o
OBJS += osal_fileops.o
OBJS += osal_init.o
OBJS += osal_math.o
OBJS += osal_mutex.o
OBJS += osal_schedule.o
OBJS += osal_semaphore.o
OBJS += osal_spinlock.o
OBJS += osal_string.o
OBJS += osal_task.o
OBJS += osal_timer.o
OBJS += osal_wait.o
OBJS += osal_workqueue.o
OBJS += osal_proc.o
OBJS += osal_device.o
OBJS += osal_interrupt.o

LIBS = libosal_user.so

CFLAGS += $(EXTRA_CFLAGS)
CFLAGS += $(LIBS_CFLAGS)
LIBS_LD_CFLAGS += -lpthread

all: $(OBJS) $(LIBS)

$(OBJS): %.o : %.c
	@$(CC) $(CFLAGS) -c $< -o $@
	@echo "$(CC) $<"

$(LIBS): $(OBJS)
	@$(CC) $(LIBS_LD_CFLAGS) -shared -o $(LIBS) $(OBJS)
	@$(RM) $(OBJS)

clean:
	@$(RM) $(OBJS) $(LIBS)
