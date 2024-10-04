#ifndef DEBUG_SYMS_H
#define DEBUG_SYMS_H

#include "list.h"

/*
 * Данные о строке исходного кода
 */
typedef struct SourceLineInfo {
    /* Машинный адрес этой строки */
    long addr;
    /* Номер строки */
    unsigned long logical_line_no;
    /* Строка - конец пролога (ставить точку останова сюда для входа функции) */
    bool is_prologue;
    /* Строка - начало пролога (ставить точку останова сюда при выходе из функции) */
    bool is_epilogue;
} SourceLineInfo;

LIST_DEFINE(SourceLineInfo, SourceLineList)

/* Информация о функции */
typedef struct FunctionInfo {
    /* Файл в котором объявлена функция. Путь полный */
    char *decl_filename;
    /* Название функции */
    char *name;
    /* Верхний адрес функции, начало */
    long low_pc;
    /* Нижний адрес функции, конец */
    long high_pc;
    /* Таблица строк */
    SourceLineList *line_table;
} FunctionInfo;

LIST_DEFINE(FunctionInfo, FunctionInfoList)

typedef struct DebugInfo {
    /* Список функций в исполняемом файле */
    FunctionInfoList *functions;
} DebugInfo;

int debug_syms_init(const char *filename, DebugInfo **debug_info);
int debug_syms_get_function_by_name(DebugInfo *debug_info,
                                    const char *func_name,
                                    FunctionInfo **out_finfo);
int debug_syms_get_function_at_addr(DebugInfo *debug_info, long addr,
                                    FunctionInfo **function);
int debug_syms_get_address_at_line(DebugInfo *debug_info, const char *filename,
                                   int line_no, long *addr);
int debug_syms_get_line_bounds(DebugInfo *state, long addr, long *out_start,
                               long *out_end);
int debug_syms_get_context(DebugInfo *debug_info, long addr,
                           FunctionInfo **out_finfo,
                           SourceLineInfo **out_slinfo);
int debug_syms_free(DebugInfo *debug_info);

int funcinfo_get_addr(FunctionInfo *finfo, long *addr);

#endif