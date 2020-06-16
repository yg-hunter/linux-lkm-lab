#ifndef _HOOK_H_
#define _HOOK_H_
#include <linux/kernel.h>
#include <linux/version.h>

#include <linux/fs.h>
//#include <linux/file.h>
#define LKM_INFO "MY_LKM"
#define LKM_VERSION "MY_LKM_TEST 1.0.0"

#if LINUX_VERSION_CODE > KERNEL_VERSION(3,10,0)
#define my_get_file_shortname(file) file->f_path.dentry->d_name.name
#else
#define my_get_file_shortname(file) file->f_dentry->d_name.name
#endif

#define my_current_proc_name() current->group_leader->comm

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);

typedef asmlinkage int (*open_t)(const char *filename, int flags, int mode);
asmlinkage int myhook_open(const char *filename, int flags, int mode);

bool util_init(void);
bool util_fini(void);

#endif //_HOOK_H_