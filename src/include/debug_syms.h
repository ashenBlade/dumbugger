#ifndef DEBUG_SYMS_H
#define DEBUG_SYMS_H

typedef struct FunctionInfo
{
    const char *name;
    long low_pc;
    long high_pc;
} FunctionInfo;

typedef struct DebugInfo
{
    FunctionInfo *functions;
    int functions_count;
} DebugInfo;

int debug_syms_get(const char *filename, DebugInfo *debug_info);

int debug_syms_free(DebugInfo *debug_info);

#endif