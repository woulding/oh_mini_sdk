EXTRA_CFLAGS += -I$(OSAL_INC) -I$(SECUREC_INC)
EXTRA_CFLAGS += -I$(OSAL_SRC)/media
EXTRA_CFLAGS += -Werror
obj-m := soc_osal.o
soc_osal-y := osal_addr.o
soc_osal-y += osal_init.o
soc_osal-y += osal_atomic.o
soc_osal-y += osal_barrier.o
soc_osal-y += osal_bitmap.o
soc_osal-y += osal_cache.o
soc_osal-y += osal_completion.o
soc_osal-y += osal_debug.o
soc_osal-y += osal_delayedwork.o
soc_osal-y += osal_device.o
soc_osal-y += osal_fileops.o
soc_osal-y += osal_interrupt.o
soc_osal-y += osal_math.o
soc_osal-y += osal_mutex.o
soc_osal-y += osal_rwlock.o
soc_osal-y += osal_semaphore.o
soc_osal-y += osal_spinlock.o
soc_osal-y += osal_string.o
soc_osal-y += osal_task.o
soc_osal-y += osal_timer.o
soc_osal-y += osal_wait.o
soc_osal-y += osal_workqueue.o
soc_osal-y += osal_proc.o
soc_osal-y += osal_device.o
soc_osal-y += media/media.o
soc_osal-y += media/media_base.o

all:
	@make -C $(KERNEL_ROOT) M=$(OSAL_SRC) modules

clean: 
	@rm -rf .tmp_versions
	@rm -f soc_osal.ko $(soc_osal-y)
	@find . -name "*.o.d" |xargs rm -f
	@find . -name "*.cmd" |xargs rm -f
	@rm -f soc_osal.mod.c soc_osal.mod.o soc_osal.mod soc_osal.o modules.order Module.symvers -f
