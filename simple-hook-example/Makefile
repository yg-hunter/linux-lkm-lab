obj-m += my_lkm.o
my_lkm-objs := hook.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	 
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean