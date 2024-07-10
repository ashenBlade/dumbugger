#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "libdwarf-0/dwarf.h"
#include "libdwarf-0/libdwarf.h"

#include "list.h"
#include "debug_syms.h"

/* 
 * Данные о строке исходного кода
 */
typedef struct source_line_info {
    Dwarf_Addr addr;
    Dwarf_Unsigned logical_line_no;
} source_line_info;

LIST_DEFINE(source_line_info, source_line_list)

typedef struct function_info {
    char *decl_filename;
    char *name;
    long low_pc;
    long high_pc;
    source_line_list src_lines;
} function_info;

#define FUNC_INFO_CONTAINS_INSTRUCTION(func_info, instr_addr) ((func_info)->low_pc <= (instr_addr) && (instr_addr) <= (func_info)->high_pc)

LIST_DEFINE(function_info, func_info_list)

struct DebugInfo {
    func_info_list functions;
};


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
                              function_info *info) {
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

    if (high_pc_form_class == DW_FORM_CLASS_CONSTANT) {
        high_pc += low_pc;
    }

    memset(info, 0, sizeof(function_info));
    info->name = strdup(name);
    info->low_pc = (long) low_pc;
    info->high_pc = (long) high_pc;
    source_line_list_init(&info->src_lines);
    return 0;
}

static int fill_functions_info_recurse(Dwarf_Die cu_die, Dwarf_Error *err,
                                   DebugInfo *di) {
    int ret = 0;
    int res = 0;
    Dwarf_Die sib_die = 0;
    Dwarf_Half tag = 0;

    func_info_list_init(&di->functions);

    do {
        /* Обрабатываем текущий DIE - находим функцию */
        if (dwarf_tag(cu_die, &tag, err) != DW_DLV_OK) {
            ret = -1;
            break;
        }

        if (tag == DW_TAG_subprogram) {
            function_info info;
            memset(&info, 0, sizeof(function_info));
            source_line_list_init(&info.src_lines);

            res = fill_function_info(cu_die, err, &info);
            if (res == -1) {
                ret = -1;
                break;
            }

            if (res == 0) {
                /* Функция имеет все необходимые данные - добавляем в свой
                 * список */
                if (func_info_list_add(&di->functions, &info) == -1) {
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
        func_info_list_free(&di->functions);
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

static int function_info_contains_address_predicate(void *context, function_info *fi) {
    Dwarf_Addr address = (Dwarf_Addr) context;
    if (FUNC_INFO_CONTAINS_INSTRUCTION(fi, address))
    {
        return 1;
    }
    return 0;
}

static int debug_syms_fill_debug_info(Dwarf_Debug dbg, Dwarf_Error *err,
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

        if (dwarf_srclines_b(cu_die, &version, &table_count, &line_context, err) != DW_DLV_OK) {
            return -1;
        }

        /* 
         * Работаем только с 1-уровневой таблицей (дефолт).
         * Так проще код писать.
         */
        if (table_count == 0 || table_count == 2)        
        {
            dwarf_srclines_dealloc_b(line_context);
            dwarf_dealloc_die(cu_die);
            continue;
        }

        /* table_count == 1 */
        Dwarf_Signed i = 0;
        Dwarf_Signed base_index = 0;
        Dwarf_Signed files_count = 0;
        Dwarf_Signed end_index = 0;

        res = dwarf_srclines_files_indexes(line_context, &base_index,
                                           &files_count, &end_index, err);
        if (res != DW_DLV_OK) {
            return -1;
        }

        /* 
         * Кэшируем последний function_info, чтобы заново не искать каждый раз.
         * Т.к. строки идут последовательно и мы скорее всего окажемся в той же функции
         */
        function_info *cached_fi = NULL;

        for (i = base_index; i < end_index; i++) {
            Dwarf_Unsigned dir_index = 0;
            Dwarf_Unsigned mod_time = 0;
            Dwarf_Unsigned file_length = 0;
            Dwarf_Form_Data16 *md5_data = 0;
            Dwarf_Line *lines;
            Dwarf_Signed lines_count;

            int vres = 0;
            const char *name = NULL;

            if (dwarf_srclines_files_data_b(line_context, i, &name, &dir_index,
                                            &mod_time, &file_length, &md5_data,
                                            err) != DW_DLV_OK) {
                return -1;
            }

            if (dwarf_srclines_from_linecontext(
                    line_context, &lines, &lines_count, err) != DW_DLV_OK) {
                return -1;
            }

            for (i = 0; i < lines_count; ++i) {
                Dwarf_Line line = lines[i];
                char *src_filename;
                Dwarf_Unsigned line_no;
                Dwarf_Addr line_addr;
                
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

                /* Находим function_info, для которого текущая инструкция находится в его диапазоне */
                function_info *cur_line_fi = NULL;
                if (cached_fi != NULL && FUNC_INFO_CONTAINS_INSTRUCTION(cached_fi, line_addr))
                {
                    cur_line_fi = cached_fi;
                } else {
                    func_info_list_contains(
                        &info->functions,
                        function_info_contains_address_predicate,
                        (void *) line_addr, &cur_line_fi);
                }

                if (cur_line_fi == NULL)
                {
                    /* 
                     * Не нашли подходящей функции. Такое может быть если функция 
                     * объявлена не нами. Например, взята из заголовочного файла.
                     */
                    continue;
                }

                source_line_info sli;
                sli.addr = line_addr;
                sli.logical_line_no = line_no;

                if (cur_line_fi->decl_filename == NULL)
                {
                    /* 
                     * Небольшой хак, т.к. не нашел удобного способа выставить название 
                     * файла исходника ранее
                     */
                    cur_line_fi->decl_filename = strdup(src_filename);
                    if (cur_line_fi->decl_filename == NULL) {
                        return -1;
                    }
                }

                if (source_line_list_add(&cur_line_fi->src_lines, &sli) == -1)
                {
                    return -1;
                }
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
    
    if (debug_syms_fill_debug_info(dbg, &err, info) == -1) {
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

int debug_syms_get_all_function(DebugInfo *debug_info, char ***functions, int *funcs_count) {
    char **func_names = calloc(list_size(&debug_info->functions), sizeof(char *));
    if (func_names == NULL)
    {
        return -1;
    }

    int i = 0;
    function_info *fi = NULL;
    foreach (fi, &debug_info->functions) {
        char *cur_name = strdup(fi->name);
        if (cur_name == NULL)
        {
            for (int j = 0; j < i; ++j)
            {
                free(func_names[j]);
            }

            free(func_names);
            return -1;
        }

        func_names[i] = cur_name;
        ++i;
    }

    *functions = func_names;
    *funcs_count = list_size(&debug_info->functions);
    return 0;
}

static int function_info_by_name_equal_predicate(void *context, function_info *fi)
{
    if (strcmp((const char*)context, fi->name) == 0)
    {
        return 1;
    }
    return 0;
}

int debug_syms_get_function_addr(DebugInfo *debug_info, const char *func_name,
                                 long *addr) {
    function_info *fi;
    if (func_info_list_contains(&debug_info->functions,
                                function_info_by_name_equal_predicate,
                                (void *) func_name, &fi) == 1) {
        *addr = fi->low_pc;
        return 0;
    }

    return 1;
}

static int source_line_by_logical_line_predicate(void *context, source_line_info *sli)
{
    if (sli->logical_line_no == (Dwarf_Unsigned)context)
    {
        return 1;
    }
    return 0;
}

int debug_syms_get_address_at_line(DebugInfo *debug_info,
                                   const char *filename, int line_no,
                                   long *addr) {
    function_info *fi;
    foreach (fi, &debug_info->functions) {
        /*
         * В символах отладки хранится полный путь до файла, а нам передается,
         * скорее всего, только название файла, без всего пути.
         */
        if (is_suffix(fi->decl_filename, filename) == 0) {
            continue;
        }

        source_line_info *sli;
        if (source_line_list_contains(&fi->src_lines, source_line_by_logical_line_predicate, (void*)(Dwarf_Unsigned)line_no, &sli) == 0)
        {
            continue;
        }

        *addr = sli->addr;
        return 0;
    }

    return 1;
}

int debug_syms_context_info_get(DebugInfo *debug_info, long addr,
                                ContextInfo *context) {
    function_info *fi;
    foreach (fi, &debug_info->functions)
    {
        if (!FUNC_INFO_CONTAINS_INSTRUCTION(fi, addr))
        {
            continue;
        }   

        /* 
         * Для поиска нужной инструкции находим функцию, которая содержит указанный адрес.
         * После, пробегаемся по всем строкам исходного кода и ищем подходящую.
         * Мы ищем наиболее подходящую, т.к. адрес может находиться не в начале строки, а где-то посередине.
         * Поэтому логика поиска - сужение диапазона возможных строк, находим строку
         * которая расположена дальше последней лучшей строки, но чтобы ее начало не превосходило 
         * адрес, указанный пользователем.
         */
        source_line_info *most_likely_sli = NULL;
        source_line_info *sli = NULL;
        Dwarf_Addr addr_dwarf = (Dwarf_Addr) addr;
        foreach (sli, &fi->src_lines) {
            if (most_likely_sli == NULL)
            {
                most_likely_sli = sli;
                continue;
            }

            if (most_likely_sli->addr < sli->addr && sli->addr <= addr_dwarf)
            {
                most_likely_sli = sli;
                if (sli->addr == addr_dwarf)
                {
                    /* Наши идеальный адрес - в самом начале строки */
                    break;
                }
            }
        }

        if (most_likely_sli == NULL)
        {
            continue;
        }

        context->src_filename = strdup(fi->decl_filename);
        context->src_line = (int) most_likely_sli->logical_line_no;
        
        return 0;
    }

    return -1;
}

int debug_syms_context_info_free(ContextInfo *info) {
    free(info->src_filename);
    memset(info, 0, sizeof(ContextInfo));
    return 0;
}

int debug_syms_free(DebugInfo *debug_info) {
    function_info *fi;
    foreach (fi, &debug_info->functions)
    {
        free(fi->name);
        free(fi->decl_filename);
        source_line_list_free(&fi->src_lines);
    }

    func_info_list_free(&debug_info->functions);
    free(debug_info);
    return -1;
}
