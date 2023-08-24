#pragma once

#if defined(__APPLE__)
#include <malloc/malloc.h>
#elif defined(__linux__)
#include <malloc.h>
#elif defined(__FreeBSD__)
#include <malloc_np.h>
#endif

#include "quickjs.h"

// See quickjs-exports.c for details.

extern "C" {

int JS_GetModuleExportEntriesCount(JSModuleDef *m);
JSValue JS_GetModuleExportEntry(JSContext *ctx, JSModuleDef *m, int idx);
JSAtom JS_GetModuleExportEntryName(JSContext *ctx, JSModuleDef *m, int idx);

void *js_def_malloc(JSMallocState *s, size_t size);
void js_def_free(JSMallocState *s, void *ptr);
void *js_def_realloc(JSMallocState *s, void *ptr, size_t size);

static inline size_t js_def_malloc_usable_size(const void *ptr)
{
#if defined(__APPLE__)
    return malloc_size(ptr);
#elif defined(_WIN32)
    return _msize(ptr);
#elif defined(EMSCRIPTEN)
    return 0;
#elif defined(__linux__)
    // For reasons unclear, this needs to be a (size_t (*)(const void *))
    // in QuickJS, despite it forwarding the call to malloc_usable_size.
    return malloc_usable_size(const_cast<void *>(ptr));
#else
    /* change this to `return 0;` if compilation fails */
    return malloc_usable_size(ptr);
#endif
}

}
