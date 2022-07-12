MODULE_NAME	:= hook
# MODULE_NAME := kprobe_example
CONFIG_MODULE_SIG=n
#EXTRA_CFLAGS := -I$(src) -Wno-strict-prototypes
#依赖文件hook.o通过makefile的自动推导实现编译
obj-m += $(MODULE_NAME).o
#generate the path
CURRENT_PATH:=$(shell pwd)
#the current kernel version number
LINUX_KERNEL:=$(shell uname -r)
#the absolute path
LINUX_KERNEL_PATH:=/usr/src/linux-headers-$(LINUX_KERNEL)
#complie object
all:
	make -C $(LINUX_KERNEL_PATH) M=$(CURRENT_PATH) modules
#clean
clean:
	make -C $(LINUX_KERNEL_PATH) M=$(CURRENT_PATH) clean
install:
	sudo insmod $(MODULE_NAME).ko
remove:
	sudo dmesg -c & sudo rmmod $(MODULE_NAME).ko
new:
	sudo dmesg -c

