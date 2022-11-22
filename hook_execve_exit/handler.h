#ifndef _HANDLER_H_
#define _HANDLER_H_

#include <linux/syscalls.h>
#include <asm/unistd.h> 
#include <linux/version.h>

#define get_parent() current->real_parent
#define get_dentry(file) file->f_path.dentry

#define get_proc_name() current->group_leader->comm
#define get_parent_proc_name() get_parent()->group_leader->comm
#define my_get_pid() current->tgid
#define get_ppid() get_parent()->tgid


void my_profile_task_exit(struct task_struct * task);


// hook sys call
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)
asmlinkage long my_hook_execve(const char __user *filename, const char __user *const __user *argv, 
    const char __user *const __user *envp);

#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
asmlinkage long my_hook_execve(const char __user *filename, const char __user * const __user *argv,
    const char __user *const  __user *envp, struct pt_regs *regs)
#endif

#else

asmlinkage long     my_hook_execve(const struct pt_regs *pt_regs);

#endif


#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 32)

#ifdef CONFIG_X86_64
static inline unsigned long get_arg1(struct pt_regs *p_regs) {
   return p_regs->di;
}

static inline unsigned long get_arg2(struct pt_regs *p_regs) {
   return p_regs->si;
}

static inline unsigned long get_arg3(struct pt_regs *p_regs) {
   return p_regs->dx;
}

static inline unsigned long get_arg4(struct pt_regs *p_regs) {
   return p_regs->r10;
}

static inline unsigned long get_arg5(struct pt_regs *p_regs) {
   return p_regs->r8;
}

static inline unsigned long get_arg6(struct pt_regs *p_regs) {
   return p_regs->r9;
}

#elif defined CONFIG_ARM64
static inline unsigned long get_arg1(struct pt_regs *p_regs) {
   return p_regs->regs[0];
}

static inline unsigned long get_arg2(struct pt_regs *p_regs) {
   return p_regs->regs[1];
}

static inline unsigned long get_arg3(struct pt_regs *p_regs) {
   return p_regs->regs[2];
}

static inline unsigned long get_arg4(struct pt_regs *p_regs) {
   return p_regs->regs[3];
}

static inline unsigned long get_arg5(struct pt_regs *p_regs) {
   return p_regs->regs[4];
}

static inline unsigned long get_arg6(struct pt_regs *p_regs) {
   return p_regs->regs[5];
}
#endif

#endif // >/ 2.6.32

#endif //_HOOK_H_
