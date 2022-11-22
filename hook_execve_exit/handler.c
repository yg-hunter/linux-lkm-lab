#include <linux/kernel.h> // __func__
#include <linux/sched.h> // struct task


#include <linux/file.h> //fget fput
#include <linux/delay.h> //msleep
#include <asm/uaccess.h> // copy_from_user get_fs
#include <linux/slab.h> // kmalloc kfree
#include <linux/fs.h> // filp_open
#include <linux/kprobes.h>

#include "handler.h"
#include "hook.h"

extern atomic_t ref_count;

extern asmlinkage execve_t orig_execve_func;
extern profile_task_exit_t orig_profile_task_exit;


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
asmlinkage long my_hook_execve(const struct pt_regs *pt_regs){
	atomic_inc(&ref_count);
    long value = -1;

	const char __user *filename = (char*)get_arg1(pt_regs);
	const char __user *const __user *argv = (const char *const*)get_arg2(pt_regs);

     char absolutepath[256] = {0};
	 int ret_num = copy_from_user(absolutepath, filename, 255);

	 printk("[base] [info] %s. tgid:%d, tgcomm:%s, pid:%d, comm:%s. filename:%s.\n", __func__, 
	 	my_get_pid(), get_proc_name(), current->pid, current->comm, absolutepath);

    value = orig_execve_func(pt_regs);

execve_return:
    atomic_dec(&ref_count);
    return value;
}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)
asmlinkage long my_hook_execve(const char __user *filename, const char __user *const __user *argv, 
    const char __user *const __user *envp){
    atomic_inc(&ref_count);
    long value = -1;

     char absolutepath[360] = {0};
	 int ret_num = copy_from_user(absolutepath, filename, 360);

	 printk("[base] [info] %s. tgid:%d, tgcomm:%s, pid:%d, comm:%s. filename:%s.\n", __func__, 
	 	my_get_pid(), get_proc_name(), current->pid, current->comm, absolutepath);

    value = orig_execve_func(filename, argv, envp);

execve_return:
    atomic_dec(&ref_count);
    return value;
}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
asmlinkage long my_hook_execve(const char __user *filename, const char __user * const __user *argv,
    const char __user *const  __user *envp, struct pt_regs *regs){
	atomic_inc(&ref_count);
    long value = -1;

    value = orig_execve_func(filename, argv, envp, regs);

execve_return:
    atomic_dec(&ref_count);
    return value;
}
#endif

void my_profile_task_exit(struct task_struct * task){
    atomic_inc(&ref_count);

   //  if(task->pid == task->tgid)

	printk("[base] [info] %s. tgid:%d, ppid:%d, comm:%s exit!\n", __func__, 
		my_get_pid(), get_ppid(), get_proc_name());


	orig_profile_task_exit(task);

task_exit_ret:
    atomic_dec(&ref_count);
    return ;
}