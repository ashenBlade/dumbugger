#ifndef DEBUG_SYMS_H
#define DEBUG_SYMS_H

typedef struct DebugInfo DebugInfo;

int debug_syms_init(const char *filename, DebugInfo **debug_info);

typedef struct ContextInfo {
    char *src_filename;
    int src_line;
} ContextInfo;

int debug_syms_get_all_function(DebugInfo *debug_info, char ***functions, int *funcs_count);

int debug_syms_get_function_addr(DebugInfo *debug_info, const char *func_name, long *addr);

int debug_syms_context_info_get(DebugInfo *debug_info, 
                                long addr,
                                ContextInfo *context);

int debug_syms_context_info_free(ContextInfo *info);

int debug_syms_free(DebugInfo *debug_info);

#endif