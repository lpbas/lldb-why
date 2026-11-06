#include "LegacyAPI.h"
#include <dispatch/dispatch.h>
#include <stddef.h>
#include <string.h>

static struct legacy_header known = { 0x4c454731, 1, 0, 0, 0, 3 };

struct legacy_header *legacy_find_header(const char *name) {
    return strcmp(name, "known") == 0 ? &known : NULL;
}

void legacy_run_on_background(void (^block)(void)) {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), block);
}
