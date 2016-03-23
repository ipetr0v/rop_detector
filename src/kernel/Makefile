CURRENT = $(shell uname -r)
KDIR = /lib/modules/$(CURRENT)/build
DEST = /lib/modules/$(CURRENT)/misc
PWD = $(shell pwd)
TARGET = rop

BIN = ../../bin
SRC = ../

obj-m    += $(TARGET).o
$(TARGET)-objs := kernel_main.o
$(TARGET)-objs += server.o

default:
	$(MAKE) -C $(KDIR) M=$(shell pwd) modules
	
	@mv $(TARGET).ko $(BIN)

install:	
	cp -v $(TARGET).ko $(DEST)
	/sbin/depmod -v | grep $(TARGET)
	/sbin/insmod $(TARGET).ko
	/sbin/lsmod | grep $(TARGET)

uninstall:	
	/sbin/rmmod $(TARGET)
	rm -v $(DEST)/$(TARGET).ko
	/sbin/depmod

clean:
	@rm -f *.o .*.cmd .*.flags *.mod.c *.order
	@rm -f .*.*.cmd *.symvers *~ *.*~
	@rm -fR .tmp*
	@rm -rf .tmp_versions

