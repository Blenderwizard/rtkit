obj-m += rtkit.o

KERNEL_ROOT=/lib/modules/$(shell uname -r)/build

all: modules

modules:
	@$(MAKE) -C $(KERNEL_ROOT) M=$(shell pwd) modules

clean:
	@$(MAKE) -C $(KERNEL_ROOT) M=$(shell pwd) clean

install: rtkit.ko
	insmod rtkit.ko

uninstall:
	rmmod rtkit