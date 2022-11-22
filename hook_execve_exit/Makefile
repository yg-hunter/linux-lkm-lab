obj-m += hook_demo.o
hook_demo-objs := hook.o handler.o

GCC_VER_GT_4 = $(shell expr `gcc -dumpversion | cut -f1 -d.` \> 4)
$(warning "debug info, GCC_VER_GT_4:" $(GCC_VER_GT_4))
ifeq ($(GCC_VER_GT_4),1)
        EXTRA_CFLAGS += -Wno-unused-but-set-variable -Wno-discarded-qualifiers -Wno-declaration-after-statement -Wno-unused-variable -Wno-unused-label
else
GCC_VER_GT_42 = $(shell expr `gcc -dumpversion | cut -f1-2 -d.` \>= 4.2 | sed -e 's/\./*100+/g')
$(warning "debug info, GCC_VER_GT_42:" $(GCC_VER_GT_42))
ifeq ($(GCC_VER_GT_42),1)
 $(warning "gcc version >= 4.2")
        EXTRA_CFLAGS += -Wno-unused-but-set-variable -Wno-discarded-qualifiers -Wno-declaration-after-statement -Wno-unused-variable -Wno-unused-label
endif
endif

local:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean;
