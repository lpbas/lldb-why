#include "LegacyAPI.h"
#include <alloca.h>
#include <dispatch/dispatch.h>
#include <pthread.h>
#include <stddef.h>
#include <string.h>

static struct legacy_header known = { 0x4c454731, 1, 0, 0, 0, 3 };

struct legacy_header *legacy_find_header(const char *name) {
    return strcmp(name, "known") == 0 ? &known : NULL;
}

void legacy_run_on_background(void (^block)(void)) {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), block);
}

void demo_call_with_stack_left(size_t bytes, void (^block)(void)) {
    pthread_t self = pthread_self();
    char *bottom = (char *)pthread_get_stackaddr_np(self) - pthread_get_stacksize_np(self);
    char here;
    size_t left = (size_t)(&here - bottom);
    size_t pad = left > bytes ? left - bytes : 0;
    volatile char *p = alloca(pad + 16);
    p[0] = 0;
    block();
}
