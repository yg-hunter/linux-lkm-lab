#include "hook.h"

#include <linux/module.h>

#include <linux/delay.h> //msleep
#include <linux/kprobes.h>
#include <linux/file.h> //fget fput
#include <linux/syscalls.h>

MODULE_AUTHOR("yg");
MODULE_DESCRIPTION("my-lkm-test");
MODULE_LICENSE("GPL");

// sys_call_table_ptr pointer
void** sys_call_table_ptr = NULL;
open_t old_open_func = NULL;

// record hacked_sys_call reference count. while module exit, it must be zero
atomic_t ref_count;

static struct kprobe kp={
	.symbol_name = "kallsyms_lookup_name",
};
static kallsyms_lookup_name_t orig_kallsyms_lookup_name = NULL;


void disable_write_protection(void)
{
  unsigned long cr0 = read_cr0();
  clear_bit(16, &cr0);
  write_cr0(cr0);
}

void enable_write_protection(void)
{
  unsigned long cr0 = read_cr0();
  set_bit(16, &cr0);
  write_cr0(cr0);
}

bool util_init(void)
{
	return true;
}

bool util_fini(void)
{
	return true;
}

int get_kallsyms_lookup_name(void)
{
    int ret = register_kprobe(&kp);
    if(unlikely(ret < 0)){
		printk(KERN_ERR "%s %s. register_kprobe failed, ret:%d\n", LKM_INFO, __FUNCTION__, ret);
		return ret;
    }
    printk("%s %s. kprobe at addr:%p, ret:%d\n", LKM_INFO, __FUNCTION__, kp.addr, ret);
	orig_kallsyms_lookup_name = (kallsyms_lookup_name_t)(void*)kp.addr;
    unregister_kprobe(&kp);

    return (orig_kallsyms_lookup_name!=NULL)?0:-1;
}

/* our hack open system call function */
asmlinkage int myhook_open(const char *filename, int flags, int mode)
{
	long value = old_open_func(filename, flags, mode);

	if(strcmp(my_current_proc_name(), "tailf") != 0) { // do not print tailf open log
		struct file* file = fget(value);
		if(NULL != file) {
			printk("%s myhook_open file. pid:%d, proccess:%s, file_name:%s, flags:%d\n", LKM_INFO, 
				current->tgid, my_current_proc_name(), my_get_file_shortname(file), flags);
			fput(file);
		}
	}	

	return value;
}

static int my_lkm_init(void)
{
	atomic_set(&ref_count, 1);

#ifdef RHEL_MAJOR // rhel/centos/ol
	printk("%s %s. RHEL:%d.%d\n", LKM_INFO, __FUNCTION__, RHEL_MAJOR, RHEL_MINOR);

	if (RHEL_MAJOR != 6 && RHEL_MAJOR != 7){
		printk(KERN_ERR "%s %s. current ko is not compatible for this os version.\n", LKM_INFO, __FUNCTION__);
		return -1;
	}
#else
	printk(KERN_ERR "%s %s. current ko is not compatible for this os version.\n", LKM_INFO, __FUNCTION__);
	return -1;
#endif

	/* get system call table addr. we will replace it*/
	if(get_kallsyms_lookup_name() < 0){
		printk(KERN_ERR "%s %s failed, load my lkm faild!\n", LKM_INFO, __FUNCTION__);
		return -1;
	}
	sys_call_table_ptr = (void**)orig_kallsyms_lookup_name("sys_call_table");
    printk("%s %s. kprobe sys_call_table:%p\n", LKM_INFO, __FUNCTION__, sys_call_table_ptr);
	if(unlikely(sys_call_table_ptr == NULL)){
		printk(KERN_ERR "%s %s failed, load my lkm faild!\n", LKM_INFO, __FUNCTION__);
		return -1;
	}

    // get the orign system call address
    old_open_func = (open_t)sys_call_table_ptr[__NR_open];
    printk("old_open_func:%p \n", old_open_func);

	// replace sys_call_table addr
    if(old_open_func != NULL) {
        disable_write_protection();
        sys_call_table_ptr[__NR_open] = (open_t)myhook_open;
        enable_write_protection();

        printk("hook sys_open success!\n");
        return 0;
    }

	printk("%s module load success!\n", LKM_INFO);
	return 0;
}

static void my_lkm_exit(void)
{
	util_fini();

	if(sys_call_table_ptr[__NR_open] == myhook_open) {
		disable_write_protection();
		sys_call_table_ptr[__NR_open] = old_open_func;
		enable_write_protection();

		printk(KERN_ALERT "revert sys_open success!\n");
	}

	while(atomic_read(&ref_count) > 1)
		msleep(10);

	printk("myhook module exit!\n");
}


module_init(my_lkm_init);
module_exit(my_lkm_exit);
