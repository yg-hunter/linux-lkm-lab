#include "hook.h"
#include <linux/module.h>
#include <linux/delay.h> //msleep
#include <linux/kprobes.h>
#include <linux/kallsyms.h>

#include "handler.h"

MODULE_AUTHOR("epp@ygz.test");
MODULE_DESCRIPTION("HookExample");
MODULE_LICENSE("GPL");
MODULE_VERSION(LKM_VERSION);

// sys_call_table_ptr pointer
void** sys_call_table_ptr = NULL;

asmlinkage execve_t stub_execve_func = NULL;
asmlinkage execve_t orig_execve_func = NULL;

unsigned long original_do_exit_func = 0;
profile_task_exit_t orig_profile_task_exit = NULL;

#ifdef CONFIG_ARM64
void (*update_mapping_prot)(phys_addr_t phys, unsigned long virt, phys_addr_t size, pgprot_t prot);
unsigned long start_rodata;
unsigned long init_begin;
#define section_size  (init_begin - start_rodata)
#endif

// record hacked_sys_call reference count. 
// while module exit, it must be zero
atomic_t ref_count;

#if defined CONFIG_X86_64 && LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
unsigned long g_cr0;
#endif

static struct kprobe kp={
	.symbol_name = "kallsyms_lookup_name",
};
static kallsyms_lookup_name_t origin_kallsyms_lookup = NULL;

#if defined CONFIG_ARM64
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
int handler_pre_profile_task_exit(struct kprobe *p, struct pt_regs *regs)
{
	struct task_struct* task = (struct task_struct*)get_arg1(regs);
	printk("[info] %s. tgid:%d, ppid:%d, comm:%s exit!\n", __func__, 
		task->tgid, task->real_parent->tgid, task->group_leader->comm);

	return 0;
}

struct kprobe kp_profile_task_exit={
	.symbol_name = "profile_task_exit",
	.pre_handler = handler_pre_profile_task_exit,
};
#endif
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
static inline void write_cr0_forced(unsigned long val)
{
    unsigned long __force_order;

    asm volatile(
        "mov %0, %%cr0"
        : "+r"(val), "+m"(__force_order));
}
#endif

static int wpoff_cr0(void)
{
	unsigned int cr0 = 0, ret = 0;
	
#ifdef CONFIG_X86_64
	#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
		write_cr0_forced(g_cr0 & ~0x00010000);
	#else
		asm volatile ("movq %%cr0, %%rax":"=a"(cr0)); 
		ret = cr0;
		cr0 &= 0xfffeffff;                            
		asm volatile ("movq %%rax, %%cr0": :"a"(cr0));
	#endif
#elif defined CONFIG_ARM64
    update_mapping_prot(__pa_symbol(start_rodata), (unsigned long)start_rodata,
                        section_size, PAGE_KERNEL);
#endif

	return ret;               
}

static void set_cr0(int val)
{
#ifdef CONFIG_X86_64
	#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
		write_cr0_forced(g_cr0);
	#else
		asm volatile ("movq %%rax, %%cr0": :"a"(val));
	#endif
#elif defined CONFIG_ARM64
    update_mapping_prot(__pa_symbol(start_rodata), (unsigned long)start_rodata,
                        section_size, PAGE_KERNEL_RO);
#endif
    return ;
}

static int inline_hook(unsigned long handler, unsigned long original_func, unsigned long new_func)
{
	unsigned char *tmp = (unsigned char*)handler;
	printk("[info] %s enter. ------ handler:[0x%lx], original_func:[0x%lx], new_func:[0x%lx].\n", __func__,  handler, original_func, new_func);

	int i = 0;
	while(1){
		if(i++ > 512 || tmp == NULL)
			return 0;

#ifdef CONFIG_ARM64 //TODO: DEBUGING
#if 0 
		if(*tmp == 0x97 || *tmp == 0x94){ //the bl instruction, total occupy 4 bytes(E8+offset)     97fff724 or 94xxxxxx
			char* bl_instruction = (char*)(tmp-3);
			char ch_offset[4] = {0};
			ch_offset[0] = tmp[-3];
			ch_offset[1] = tmp[-2];
			ch_offset[2] = tmp[-1];
			printk("[impl] %s. tmp:0x%2x, bl_instruction:[0x%08lx, 0x%08x], ch_offset:0x%08lx.\n", __func__, *tmp, bl_instruction, *(int*)bl_instruction, *(int*)ch_offset);

			long offset = *(int*)ch_offset; //
			long off_l2 = (offset << 2);
			long bl_addr = off_l2 + (long)bl_instruction;

			printk("[impl] %s. offset:0x%lx, off_l2:0x%lx, bl_addr:0x%lx, original_func:0x%lx.\n", __func__, offset, off_l2, bl_addr, original_func);
			if(bl_addr == original_func){
				int real_bl = 0;
				long offset0 = 0, offset0_r2 = 0;

				offset0 = (new_func - (unsigned long)bl_instruction);
				offset0_r2 = offset0 >> 2;
				real_bl = (offset0_r2 & 0x0000000000ffffff) | 0x94000000;

				printk("[info] %s. offset0:0x%016lx, offset0_r2:%08lx, real_bl:%08lx.\n", __func__,  offset0, offset0_r2, real_bl);

//              *(int*)bl_instruction = real_bl;

				printk("[info] %s leave. --------- replace succ.\n", __func__);
				printk("[info] %s.\n", __func__);

				return 1;
			}
			printk("[info] %s.\n", __func__);
		}
#endif
#elif defined CONFIG_X86_64
		if(*tmp == 0xe8){ //the call instruction, total occupy 5 bytes(E8+offset)
			int* offset = (int*)(tmp+1);
			// printk("[info] %s. tmp:%08x, offset:%08x, call:0x%08x, original_func:%08x, new_func:%08x.\n", __func__, 
			// 	(unsigned long)tmp, (int)*offset, ((unsigned long)tmp + 5 + *offset), original_func, new_func);

			if((unsigned long)((unsigned long)tmp + 5 + *offset) == original_func){
				printk("[info] %s. call:0x%lx, offset:%08x, original_func:%lx.\n", __func__, 
					(unsigned long)tmp, *offset, (unsigned long)original_func);

				*offset = (int)(new_func - (unsigned long)tmp - 5); // replace with the new func relative addr

				printk("[info] %s leave. ----------- call:0x%lx, offset:%08x, new_func:%lx.\n", __func__, 
					(unsigned long)tmp, *offset, new_func);

				return 1;
			}
		}
#endif
		tmp++;
	}
	printk("[info] %s leave. ------ handler:0x%lx, original_func:0x%lx, new_func:0x%lx.\n", __func__,  handler, original_func, new_func);
}

long get_sys_call_addr(char* syscall_name)
{
	char real_name[80] = {0};
	if(origin_kallsyms_lookup == NULL || syscall_name == NULL || strlen(syscall_name) > 72)
		return 0;
	
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0)
	return origin_kallsyms_lookup(syscall_name);
#else
	#ifdef CONFIG_X86_64
		sprintf(real_name, "__x64_%s", syscall_name);
	#elif defined CONFIG_ARM64
		sprintf(real_name, "__arm64_%s", syscall_name);
	#endif

	return origin_kallsyms_lookup(real_name);
#endif
}

int get_origin_syscall_func(void)
{
	if (sys_call_table_ptr == NULL){
		printk("[err] %s. sys_call_table_ptr is NULL!\n", __func__);
		return -1;
	}

	if(origin_kallsyms_lookup){
		original_do_exit_func = (unsigned long)origin_kallsyms_lookup("do_exit");
    	printk("[info] %s. original_do_exit_func:%lx\n", __func__, original_do_exit_func);
    	orig_profile_task_exit = (profile_task_exit_t)origin_kallsyms_lookup("profile_task_exit");
    	printk("[info] %s. orig_profile_task_exit:%lx\n", __func__, (long unsigned int)orig_profile_task_exit);

    	if (0 == original_do_exit_func || NULL == orig_profile_task_exit){
    		printk("[err] %s. original_do_exit_func or orig_profile_task_exit is NULL\n", __func__);
			return -1;
    	}

		stub_execve_func = (execve_t)origin_kallsyms_lookup("stub_execve");
    	orig_execve_func = (execve_t)get_sys_call_addr("sys_execve");
    	printk("[info] %s. stub_execve:%lx, orig_execve_func:%lx\n", __func__, (long unsigned int)stub_execve_func, (long unsigned int)orig_execve_func);
	}

	printk("[info] %s leave. success.\n", __func__);
	return 0;
}

int hook_origin_syscall(void)
{
	int ret = 0, cr0 = 0;

	if(sys_call_table_ptr == NULL){
		printk("[err] %s. sys_call_table_ptr is NULL.\n", __func__);
		return -1;
	}

	preempt_disable();
	cr0 = wpoff_cr0();

	if (original_do_exit_func && orig_profile_task_exit){
		ret = inline_hook(original_do_exit_func, (unsigned long)orig_profile_task_exit, (unsigned long)my_profile_task_exit);
		printk("[info] %s. @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ inline_hook(do_exit) ret:%d.\n", __func__, ret);
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32) //&& LINUX_VERSION_CODE <= KERNEL_VERSION(3, 10, 0)
	if(stub_execve_func == NULL || orig_execve_func == stub_execve_func){ // no stub_execve in kernel version 4.14 of ol7.7
		sys_call_table_ptr[__NR_execve] = (execve_t)my_hook_execve;
	}
	else if(orig_execve_func){
		printk("[info] %s. stub_execve_func:%08x, orig_execve_func:%08x, my_hook_execve:%08x.\n", 
			__func__, stub_execve_func, orig_execve_func, my_hook_execve);

		ret = inline_hook(stub_execve_func, orig_execve_func, (unsigned long)my_hook_execve);
		printk("[info] %s. inline_hook(execve) ret:%d.\n", __func__, ret);
		if(ret < 0)
			goto hook_exit;
	}
#endif

hook_exit:
	set_cr0(cr0);
	preempt_enable();
	return ret;
}

int revert_origin_syscall(void)
{
	printk("[info] %s enter.\n", __func__);
	if(sys_call_table_ptr == NULL){
		printk("[err] %s leave. sys_call_table_ptr is NULL.\n", __func__);
		return 0;
	}
	
	preempt_disable();
	int cr0 = wpoff_cr0(), ret = 0;

	if(original_do_exit_func && orig_profile_task_exit){
		printk("[info] %s. begin unpatch profile_task_exit.\n", __func__);
		ret = inline_hook(original_do_exit_func, (unsigned long)my_profile_task_exit, (unsigned long)orig_profile_task_exit);
		if(ret < 0)
			printk("[wrn] %s.profile_task_exit is unpatched! ret:%d.\n", __func__, ret);
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
	if(sys_call_table_ptr[__NR_execve] == my_hook_execve){
		sys_call_table_ptr[__NR_execve] = orig_execve_func;	
	}
	else if(orig_execve_func){
		ret = inline_hook(stub_execve_func, (unsigned long)my_hook_execve, orig_execve_func);
		if(ret < 0)
			printk("[wrn] %s. execve is unpatched. ret:%d.\n", __func__, ret);				
	}
#endif

	set_cr0(cr0);
	preempt_enable();

#if defined CONFIG_ARM64
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
    unregister_kprobe(&kp_profile_task_exit);
#endif
#endif
	printk("[info] %s leave. all sys_calls are unpatched!\n", __func__);
	return 0;
}


#include <linux/slab.h>
#define MAX_ENTRY_LEN   256
bool get_kernel_version(char *kernel_version, int len) 
{
	if(kernel_version == NULL || len <= 0)
		return false;
	
	memset(kernel_version, 0, len);
    struct file *proc_version = filp_open("/proc/version", O_RDONLY, 0);
    if(proc_version == NULL){
		printk("[err] filp_open:[/proc/version NULL].\n");
        return false;
	}
	
  	char tmp_version[80] = {0};
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
    int ret = kernel_read(proc_version, 0, tmp_version, 78);
#else
    int ret = kernel_read(proc_version, tmp_version, 78, &(proc_version->f_pos));
#endif
	if(ret < 0){
		printk("[err] kernel_read:%d.\n", ret);
		goto out;
	}
	
	printk("[info] kernel_read:%d, current os_version:%s.\n", ret, tmp_version);
	
	char *tmp_version_ptr = tmp_version;
	// Linux version 4.19.90-17.ky10.aarch64 (YHKYLIN-OS@....
    if(NULL == strsep(&tmp_version_ptr, " ") || NULL == strsep(&tmp_version_ptr, " "))
		goto out;

	// get the string between the 2th and 3th white space
    char *tmp_buf = strsep(&tmp_version_ptr, " ");
	if(tmp_buf == NULL)
		goto out;
	
	if(strlen(tmp_buf) > len-1){
		printk("[err] %s. kernerl version too long(%s), lkm will quit.\n", __func__, tmp_buf);
		goto out;
	}
	printk("[info] %s. kernel version:[%d, %s].\n", __func__, (int)strlen(tmp_buf), tmp_buf);
	strcpy(kernel_version, tmp_buf);

out:
    filp_close(proc_version, 0);
    return (kernel_version[0]==0);
}

static unsigned long get_func_addr_from_system_map(char *kern_ver, char *func_name) 
{
    char system_map_entry[MAX_ENTRY_LEN] = {0};
    unsigned long func_addr = 0;
	if(kern_ver == NULL || kern_ver[0] == 0 || func_name == NULL || func_name[0] == 0)
		return func_addr;
     
    size_t len = strlen(kern_ver)+strlen("/boot/System.map-")+1;
    char *filename = kzalloc(len, GFP_KERNEL);
    if(filename == NULL){
        printk("[err] %s. kmalloc size:%d failed.\n", __func__, (int)len);
        return func_addr;
    }
	sprintf(filename, "/boot/System.map-%s", kern_ver);

    struct file *system_map = filp_open(filename, O_RDONLY, 0);
    if(system_map == NULL){
        printk("[err] %s. open %s failed.\n", __func__, filename);
        goto out1;
    }
	//printk("[info] %s. open %s succ.\n", __func__, filename);
 
   	int i = 0, j = 0;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
    while(kernel_read(system_map, j, system_map_entry+i, 1) == 1){ 
		j++;
#else
    while(kernel_read(system_map, system_map_entry+i, 1, &system_map->f_pos) == 1){
#endif
		if(system_map_entry[i] == '\n'){
//			printk("[info] %s. i:%d, j:%d, system_map_entry:%s.\n", __func__, i, j, system_map_entry);
			
			i = 0;
			//ffff000008a40688 D sys_call_table
			char *system_map_entry_ptr = system_map_entry;
			char *tmp_addr = strsep(&system_map_entry_ptr, " "); //ffff000008a40688
//			printk("[info] %s. i:%d, j:%d, system_map_entry:%s, tmp_addr:%s, system_map_entry_ptr:%s.\n", __func__, i, j, system_map_entry, tmp_addr!=NULL?tmp_addr:"NULL", system_map_entry_ptr);
			if(tmp_addr == NULL || NULL == strsep(&system_map_entry_ptr, " ") || system_map_entry_ptr == NULL)
				goto con1;
			
			char *tmp_func_name = system_map_entry_ptr; //sys_call_table
			tmp_func_name[strlen(tmp_func_name)-1] = 0; // repalce /n with /0 at the end of the string
			//printk("[info] %s. tmp_func_name:%s entry_str:%s, func_addr:%p.\n", __func__, tmp_func_name, tmp_addr);
			if(strcmp(tmp_func_name, func_name) == 0){
				int ret = kstrtoul(tmp_addr, 16, (unsigned long*)&func_addr);
				printk("[%s] %s. %s retrieved, tmp_addr:%s, func_addr:%lx.\n", (ret==0)?"info":"err", __func__, func_name, tmp_addr, (long unsigned int)func_addr);
				break;
			}
con1:
			memset(system_map_entry, 0, MAX_ENTRY_LEN);
			continue;
        }
		else if(i == MAX_ENTRY_LEN){
			//more than max_entry_len in this line, drop the rest of the line
			printk("[wrn] more than max_entry_len in this line, drop the rest of the line.\n");
			i = 0;
		#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
			while(kernel_read(system_map, j, system_map_entry+i, 1) == 1){
				j++;
		#else
			while(kernel_read(system_map, system_map_entry+i, 1, &system_map->f_pos) == 1){
		#endif
				if(system_map_entry[i] == '\n')
					break;
			}
			memset(system_map_entry, 0, MAX_ENTRY_LEN);
			continue;
		}
        i++;
    }
 
 out:
    filp_close(system_map, 0);
 out1:
    kfree(filename);
 
    return func_addr;
}

static int hook_demo_init(void)
{
	int ret = 0;
	
	atomic_set(&ref_count, 1);

#ifdef RHEL_MAJOR // rhel/centos
	printk("[info] %s. RHEL:%d.%d\n", __func__, RHEL_MAJOR, RHEL_MINOR);

	if (RHEL_MAJOR < 6 || RHEL_MAJOR > 8){
		printk("[err] %s. current ko is not compatible for this os version.\n", __func__);
		return -1;
	}
#endif
	printk("[info] %s. hook_demo lkm version: %s\n", __func__, LKM_VERSION);


#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 32)
	printk("[err] %s. current ko is not compatible for this os version.\n", __func__);
	return -1;
#endif

    ret = register_kprobe(&kp);
    if(ret < 0){
    	// kernel must config kprobe.
        printk("[err] %s. register_kprobe failed, ret:%d\n", __func__, ret);
        return ret;
    }
    printk("[info] %s. kprobe at addr:%p, ret:%d\n", __func__, kp.addr, ret);
    origin_kallsyms_lookup = (kallsyms_lookup_name_t)(void*)kp.addr;
    unregister_kprobe(&kp);
    if (NULL == origin_kallsyms_lookup)
    {
    	printk("[err] %s.  origin_kallsyms_lookup addr null \n", __func__);
    	ret = -1;
    }

	char kernel_version[64] = {0};
	get_kernel_version(kernel_version, 64);
	printk("[info] kernel version:%s.\n", kernel_version);

#ifdef CONFIG_ARM64
	update_mapping_prot = (void *)kallsyms_lookup_name("update_mapping_prot");
	start_rodata = (unsigned long)kallsyms_lookup_name("__start_rodata");
	if(start_rodata == 0){
		start_rodata = get_func_addr_from_system_map(kernel_version, "__start_rodata");
	}

	init_begin = (unsigned long)kallsyms_lookup_name("__init_begin");
	if(init_begin == 0){
		init_begin = get_func_addr_from_system_map(kernel_version, "__init_begin");
	}
	
	printk("[info] %s. update_mapping_prot:%lx, start_rodata:%lx, init_begin:%lx.\n", __func__, (long unsigned int)update_mapping_prot, start_rodata, init_begin);

	if(update_mapping_prot == NULL || start_rodata == 0 || init_begin == 0){
		printk("[err] %s. update_mapping_prot or start_rodata or init_begin is NULL!\n", __func__);
		return -1;
	}
#endif

#if defined CONFIG_ARM64
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
	ret = register_kprobe(&kp_profile_task_exit);
	if (ret < 0) {
			pr_err("register_kprobe kp_profile_task_exit failed, returned %d\n", ret);
			return ret;
	}
#endif
#endif

#if defined CONFIG_X86_64 && LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
	g_cr0 = read_cr0();
#endif

	sys_call_table_ptr = (void**)origin_kallsyms_lookup("sys_call_table");
	if(sys_call_table_ptr == NULL){
        printk("[wrn] %s. origin_kallsyms_lookup failed, get from system.map\n", __func__);
        sys_call_table_ptr = (void**)get_func_addr_from_system_map(kernel_version, "sys_call_table");
		printk("[info] %s. kallsyms_lookup_name failed, get from system.map, sys_call_table[%lx].\n", 
			__func__, (long unsigned int)sys_call_table_ptr);
	}
		
	if(sys_call_table_ptr)
	{
		// get the orign system call addr
		ret = get_origin_syscall_func();
		if(ret < 0){
			printk("[err] %s, get_orign_system_call failed!\n", __func__);
			return -1;
		}

		/* replace sys_call_table_ptr addr*/
		ret = hook_origin_syscall();
		if(ret < 0)
			return -1;

		printk("[info] %s, module load successful!\n", __func__);
		return 0;
	}

	printk("[err] %s. no sys call table found\n", __func__);
	return -1;
}

static void hook_demo_exit(void)
{
	bool anti_bm_enable = false;
	bool mc_encryption_enable = false;

	/* revert sys call addr. */
	revert_origin_syscall();

	//util_fini();

	int s_ref_count = 1;
	int ref_en_count = atomic_read(&ref_count);
	printk("[info] %s.hook module is unloading! ref_count:%d - 02\n", __func__, ref_en_count);
	printk("[info] delete_module-%s. ref:%d, hook_demo.ko unloading...\n",
	 __func__, ref_en_count);
	while(ref_en_count > 1)
	{
		if(s_ref_count%150 == 0){
			printk("[info] delete_module-%s. ref:%d, hook_demo.ko unloading...\n", 
				__func__, ref_en_count);
			
			s_ref_count = 0;
		}
		s_ref_count++;
		ref_en_count = atomic_read(&ref_count);
		msleep(30);
	}

	printk("[info] %s.hook module is unloaded! - finish\n", __func__);
}

module_init(hook_demo_init);
module_exit(hook_demo_exit);
