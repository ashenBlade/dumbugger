#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>

#include "libdwarf-0/dwarf.h"
#include "libdwarf-0/libdwarf.h"

#include "list.h"
#include "debug_syms.h"

LIST_DECLARE(SourceLineInfo, SourceLineList)
LIST_DECLARE(FunctionInfo, FunctionInfoList)

#define FUNC_INFO_CONTAINS_INSTRUCTION(func_info, instr_addr) \
    ((func_info)->low_pc <= (instr_addr) &&                   \
     (instr_addr) <= (func_info)->high_pc)

/*
 * Получить информацию о функции из переданного DIE для функции
 * (DW_TAG_subprogram).
 *
 * Возвращает:
 * 0  - успешно обработано
 * 1  - это внешняя функция, которая нам не интересна (например, printf из libc)
 * -1 - ошибка
 */
static int fill_function_info(Dwarf_Die subprog_die, Dwarf_Error *err,
                              FunctionInfo *info) {
    int res = 0;
    char *name = "\0";
    Dwarf_Addr low_pc = 0;
    Dwarf_Addr high_pc = 0;
    Dwarf_Half high_pc_form = 0;
    enum Dwarf_Form_Class high_pc_form_class = 0;

    res = dwarf_diename(subprog_die, &name, err);
    if (res == DW_DLV_ERROR) {
        return -1;
    }

    if (res == DW_DLV_NO_ENTRY) {
        return 1;
    }

    res = dwarf_lowpc(subprog_die, &low_pc, err);
    if (res == DW_DLV_ERROR) {
        return -1;
    }
    if (res == DW_DLV_NO_ENTRY) {
        return 1;
    }

    res = dwarf_highpc_b(subprog_die, &high_pc, &high_pc_form,
                         &high_pc_form_class, err);
    if (res == DW_DLV_ERROR) {
        return -1;
    }

    if (res == DW_DLV_NO_ENTRY) {
        return 1;
    }

    /* Поддерживается только константное смещение */
    if (high_pc_form_class == DW_FORM_CLASS_CONSTANT) {
        high_pc += low_pc;
    } else {
        high_pc = low_pc;
    }

    memset(info, 0, sizeof(FunctionInfo));
    info->name = strdup(name);
    info->low_pc = (long) low_pc;
    info->high_pc = (long) high_pc;
    SourceLineList_init(&info->line_table);
    return 0;
}

static int fill_functions_info_recurse(Dwarf_Die cu_die, Dwarf_Error *err,
                                       DebugInfo *di) {
    int ret = 0;
    int res = 0;
    Dwarf_Die sib_die = 0;
    Dwarf_Half tag = 0;

    FunctionInfoList_init(&di->functions);

    do {
        /* Обрабатываем текущий DIE - находим функцию */
        if (dwarf_tag(cu_die, &tag, err) != DW_DLV_OK) {
            ret = -1;
            break;
        }

        if (tag == DW_TAG_subprogram) {
            FunctionInfo info;
            memset(&info, 0, sizeof(FunctionInfo));
            SourceLineList_init(&info.line_table);

            res = fill_function_info(cu_die, err, &info);
            if (res == -1) {
                ret = -1;
                break;
            }

            if (res == 0) {
                /* Функция имеет все необходимые данные - добавляем в свой
                 * список */
                if (FunctionInfoList_add(di->functions, &info) == -1) {
                    ret = -1;
                    free((void *) info.name);
                    break;
                }
            } else if (res == 1) {
                /* Невалидная функция */
                free((void *) info.name);
            }
        }

        /* Переходим к следующему DIE */
        res = dwarf_siblingof_c(cu_die, &sib_die, err);
        if (res == DW_DLV_ERROR) {
            ret = -1;
            break;
        }

        if (res == DW_DLV_NO_ENTRY) {
            /* Это был последний DIE */
            ret = 0;
            break;
        }

        dwarf_dealloc_die(cu_die);
        cu_die = sib_die;
    } while (true);

    if (ret == -1) {
        FunctionInfoList_free(di->functions);
        dwarf_dealloc_die(cu_die);
        return -1;
    }

    return 0;
}

/* Проверить что suffix является суффиксом строки str */
static int is_suffix(const char *str, const char *suffix) {
    int suffix_len = strlen(suffix);
    int str_len = strlen(str);

    /*
     * Длина пути указанного файла не может быть
     * больше длины пути файла исходного кода
     */
    if (str_len < suffix_len) {
        return 0;
    }

    /*
     * Сравнивать надо только конец строк
     */
    if (strcmp(str + str_len - suffix_len, suffix) == 0) {
        return 1;
    }

    return 0;
}

static int function_info_contains_address_predicate(void *context,
                                                    FunctionInfo *fi) {
    Dwarf_Addr address = (Dwarf_Addr) context;
    if (FUNC_INFO_CONTAINS_INSTRUCTION(fi, address)) {
        return 1;
    }
    return 0;
}

static int debug_syms_fill_line_table(Dwarf_Debug dbg, Dwarf_Error *err,
                                      DebugInfo *info) {
    int res;
    Dwarf_Unsigned header_length;
    Dwarf_Half version;
    Dwarf_Off abbrev_offset;
    Dwarf_Half address_size;
    Dwarf_Half length_size;
    Dwarf_Half extension_size;
    Dwarf_Unsigned next_header;
    Dwarf_Sig8 sig;
    Dwarf_Unsigned type_offset;
    Dwarf_Unsigned next_cu_offset;
    Dwarf_Half header_cu_type;
    Dwarf_Bool is_info = true;

    /*
     * Заполняем общую информацию о функциях
     */
    while (true) {
        Dwarf_Half tag;
        Dwarf_Die cu_die;
        Dwarf_Die cu_child;

        /*
         * Заполняем информацию из текущего compilation unit
         */
        res = dwarf_next_cu_header_e(
            dbg, is_info, &cu_die, &header_length, &version, &abbrev_offset,
            &address_size, &length_size, &extension_size, &sig, &type_offset,
            &next_cu_offset, &header_cu_type, err);
        if (res == DW_DLV_ERROR) {
            return -1;
        }

        if (res == DW_DLV_NO_ENTRY) {
            dwarf_dealloc_die(cu_die);
            break;
        }

        res = dwarf_tag(cu_die, &tag, err);
        if (res == DW_DLV_ERROR) {
            return -1;
        }

        if (tag != DW_TAG_compile_unit) {
            dwarf_dealloc_die(cu_die);
            continue;
        }

        res = dwarf_child(cu_die, &cu_child, err);
        if (res == DW_DLV_ERROR) {
            return -1;
        }

        if (res == DW_DLV_OK /* != DW_DLV_NO_ENTRY */) {
            if (fill_functions_info_recurse(cu_child, err, info) == -1) {
                return -1;
            }
        } else {
            /*
             * Нет смысла заполнять информацию далее, т.к.
             * текущий CU не найден. Нового ничего не добавим
             * */
            dwarf_dealloc_die(cu_child);
            dwarf_dealloc_die(cu_die);
            continue;
        }

        /*
         * Заполняем информацию об исходном коде (строки)
         */
        Dwarf_Unsigned version;
        Dwarf_Small table_count;
        Dwarf_Line_Context line_context;

        if (dwarf_srclines_b(cu_die, &version, &table_count, &line_context,
                             err) != DW_DLV_OK) {
            return -1;
        }

        /*
         * Работаем только с 1-уровневой таблицей
         */
        if (table_count == 0 || table_count == 2) {
            dwarf_srclines_dealloc_b(line_context);
            dwarf_dealloc_die(cu_die);
            continue;
        }

        /*
         * Кэшируем последний function_info, чтобы заново не искать каждый раз.
         * Т.к. строки идут последовательно и мы скорее всего окажемся в той же
         * функции
         */
        FunctionInfo *cached_fi = NULL;

        /* Храним */
        SourceLineInfo *prev_sl_info = NULL;

        Dwarf_Line *lines;
        Dwarf_Signed lines_count;

        int vres = 0;

        if (dwarf_srclines_from_linecontext(
                line_context, &lines, &lines_count, err) != DW_DLV_OK) {
            return -1;
        }

        for (int i = 0; i < lines_count; ++i) {
            Dwarf_Line line = lines[i];
            char *src_filename;
            Dwarf_Unsigned line_no;
            Dwarf_Addr line_addr;
            Dwarf_Bool prologue_end;
            Dwarf_Bool epilogue_begin;
            Dwarf_Unsigned isa;
            Dwarf_Unsigned discriminator;
            Dwarf_Bool is_statement;

            /* 
             * Обрабатываем только стейтменты - остальные записи 
             * могут быть простыми инструкциями внутри стейтмента
             */
            if (dwarf_linebeginstatement(line, &is_statement, err) != DW_DLV_OK) {
                return -1;
            }

            if (!is_statement) {
                continue;
            }

            /* Имя файла с исходным кодом */
            if (dwarf_linesrc(line, &src_filename, err) != DW_DLV_OK) {
                return -1;
            }

            /* Номер строки в файле */
            if (dwarf_linelogical(line, &line_no, err) != DW_DLV_OK) {
                return -1;
            }

            /* Адрес инструкции, с которой начинается строка */
            if (dwarf_lineaddr(line, &line_addr, err) != DW_DLV_OK) {
                return -1;
            }

            /* Флаг эпилога и пролога */
            if (dwarf_prologue_end_etc(line, &prologue_end, &epilogue_begin,
                                        &isa, &discriminator, err) == -1) {
                return -1;
            }

            /*
             * Находим function_info, для которого текущая инструкция
             * находится в его диапазоне
             */
            FunctionInfo *cur_line_fi = NULL;
            if (cached_fi != NULL &&
                FUNC_INFO_CONTAINS_INSTRUCTION(cached_fi, line_addr)) {
                cur_line_fi = cached_fi;
            } else {
                if (!FunctionInfoList_contains(
                        info->functions,
                        function_info_contains_address_predicate,
                        (void *) line_addr, &cur_line_fi)) {
                    cur_line_fi = NULL;
                }
            }

            if (cur_line_fi == NULL) {
                /*
                 * Не нашли подходящей функции. Такое может быть если
                    * функция объявлена не нами. Например, взята из
                    * заголовочного файла.
                    */
                continue;
            }

            SourceLineInfo sli = {
                .addr = line_addr,
                .logical_line_no = line_no,
            };

            if (cur_line_fi->decl_filename == NULL) {
                /*
                 * Небольшой хак, т.к. не нашел удобного способа выставить
                    * название файла исходника ранее
                    */
                cur_line_fi->decl_filename = strdup(src_filename);
                if (cur_line_fi->decl_filename == NULL) {
                    return -1;
                }
            }

            if (SourceLineList_add(cur_line_fi->line_table, &sli) == -1) {
                return -1;
            }
        }

        dwarf_srclines_dealloc_b(line_context);
        dwarf_dealloc_die(cu_die);
    }

    return 0;
}

int debug_syms_init(const char *filename, DebugInfo **debug_info) {
    Dwarf_Debug dbg;
    Dwarf_Error err;
    if (dwarf_init_path(filename, NULL, 0, DW_GROUPNUMBER_ANY, NULL, NULL, &dbg,
                        &err) != DW_DLV_OK) {
        return -1;
    }

    DebugInfo *info = calloc(1, sizeof(DebugInfo));
    if (info == NULL) {
        return -1;
    }

    if (debug_syms_fill_line_table(dbg, &err, info) == -1) {
        dwarf_finish(dbg);
        free(info);
        return -1;
    }

    if (dwarf_finish(dbg) != DW_DLV_OK) {
        free(info);
        return -1;
    }

    *debug_info = info;

    return 0;
}

static int function_info_by_name_equal_predicate(void *context,
                                                 FunctionInfo *fi) {
    if (strcmp((const char *) context, fi->name) == 0) {
        return 1;
    }
    return 0;
}

int debug_syms_get_function_by_name(DebugInfo *debug_info,
                                    const char *func_name,
                                    FunctionInfo **out_finfo) {
    FunctionInfo *fi;
    if (FunctionInfoList_contains(debug_info->functions,
                                  function_info_by_name_equal_predicate,
                                  (void *) func_name, &fi) == 1) {
        *out_finfo = fi;
        return 1;
    }

    return 0;
}

static int source_line_by_logical_line_predicate(void *context,
                                                 SourceLineInfo *sli) {
    if (sli->logical_line_no == (Dwarf_Unsigned) context) {
        return 1;
    }
    return 0;
}

int debug_syms_get_address_at_line(DebugInfo *debug_info, const char *filename,
                                   int line_no, long *addr) {
    FunctionInfo *fi;
    foreach (fi, debug_info->functions) {
        /*
         * В символах отладки хранится полный путь до файла, а нам передается,
         * скорее всего, только название файла, без всего пути.
         */
        if (is_suffix(fi->decl_filename, filename) == 0) {
            continue;
        }

        SourceLineInfo *sli;
        if (SourceLineList_contains(
                fi->line_table, source_line_by_logical_line_predicate,
                (void *) (Dwarf_Unsigned) line_no, &sli) == 0) {
            continue;
        }

        *addr = sli->addr;
        return 0;
    }

    return 1;
}

int debug_syms_get_context(DebugInfo *debug_info, long addr,
                           FunctionInfo **out_finfo, 
                           SourceLineInfo **out_slinfo) {
    FunctionInfo *fi;
    foreach (fi, debug_info->functions) {
        if (!FUNC_INFO_CONTAINS_INSTRUCTION(fi, addr)) {
            continue;
        }

        SourceLineInfo *prev_sl_info = NULL;
        SourceLineInfo *sl_info = NULL;
        Dwarf_Addr addr_dwarf = (Dwarf_Addr) addr;
        foreach (sl_info, fi->line_table) {
            if (prev_sl_info != NULL) {
                if (prev_sl_info->addr <= addr && addr < sl_info->addr) {
                    *out_slinfo = prev_sl_info;
                    *out_finfo = fi;
                    return 0;
                }
            }

            prev_sl_info = sl_info;
        }

        if (prev_sl_info != NULL && prev_sl_info->addr <= addr) {
            *out_slinfo = prev_sl_info;
            *out_finfo = fi;
            return 0;
        }

        break;
    }

    errno = ENOENT;
    return -1;
}

int debug_syms_get_line_bounds(DebugInfo *state, long addr, long *out_start,
                    long *out_end) {
    FunctionInfo *cur_function;
    if (debug_syms_get_function_at_addr(state, addr, &cur_function) == -1) {
        return -1;
    }

    SourceLineInfo *prev_line = NULL;
    SourceLineInfo *sl_info;
    foreach (sl_info, cur_function->line_table) {
        if (prev_line != NULL)
        {
            if (prev_line->addr <= addr && addr < sl_info->addr) {
                *out_start = prev_line->addr;
                *out_end = sl_info->addr;
                return 0;
            }
        }

        prev_line = sl_info;
    }

    if (prev_line == NULL) {
        /* Не нашли соответствующую строку */
        errno = ENOENT;
        return -1;
    }

    /* 
     * В случае, если это была последняя строка, то
     * считаем, что ее конец - это конец функции
     */
    *out_start = prev_line->addr;
    *out_end = cur_function->high_pc;
    return 0;
}

int debug_syms_free(DebugInfo *debug_info) {
    FunctionInfo *fi;
    foreach (fi, debug_info->functions) {
        free(fi->name);
        free(fi->decl_filename);
        SourceLineList_free(fi->line_table);
    }

    FunctionInfoList_free(debug_info->functions);
    free(debug_info);
    return -1;
}

int funcinfo_get_addr(FunctionInfo *finfo, long *addr) {
    *addr = finfo->low_pc;
    return 0;
}

int debug_syms_get_function_at_addr(DebugInfo *debug_info, long addr,
                                    FunctionInfo **function) {
    if (FunctionInfoList_contains(debug_info->functions,
                                  function_info_contains_address_predicate,
                                  (void *) addr, function)) {
        return 1;
    }
    return 0;
}