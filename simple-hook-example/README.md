# hook test on rhel/centos 6.x 7.x

## compile
make

## test
- see ko info
    modinfo my_lkm.ko
- watch the system log
        tailf /var/log/message
    or
        tail -f /var/log/message
- load ko to kernel
    insmod my_lkm.ko
- unload ko
    rmmod my_lkm

## cleanup
make clean