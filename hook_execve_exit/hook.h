#ifndef _HOOK_H_
#define _HOOK_H_

#include <linux/syscalls.h>
#include <asm/unistd.h> 
#include <linux/version.h>

#define LKM_VERSION "v0.0.1"


// hook system call type defination 
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)
typedef asmlinkage long   (*execve_t)(const char __user *filename, const char __user *const __user *argv, 
    const char __user *const __user *envp);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
typedef asmlinkage long   (*execve_t)(const char __user *filename, const char __user * const __user *argv,
    const char __user *const  __user *envp, struct pt_regs *regs)
#endif

#else // kernel version >= 4.17
typedef asmlinkage long (*syscall_t)(const struct pt_regs *);

#define execve_t syscall_t
#endif

typedef void (*profile_task_exit_t)(struct task_struct * task);

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);

bool util_init(void);
bool util_fini(void);

#endif //_HOOK_H_
