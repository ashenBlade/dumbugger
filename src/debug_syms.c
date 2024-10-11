#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>

#include "libdwarf-0/dwarf.h"
#include "libdwarf-0/libdwarf.h"

#include "list.h"
#include "debug_syms.h"

/* 
 * Реализации списков, используемые в интерфейсе
 */

LIST_DECLARE(SourceLineInfo, SourceLineList)
LIST_DECLARE(FunctionInfo, FunctionInfoList)
LIST_DECLARE(Variable, VariableList)
LIST_DECLARE(StructMember, StructMemberList)

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

    VariableList *variables;
    if (VariableList_init(&variables) == -1) {
        return -1;
    }

    Dwarf_Die variable_die;
    res = dwarf_child(subprog_die, &variable_die, err);

    if (res == DW_DLV_OK) {
        do {
            Dwarf_Die next_die;
            Dwarf_Half tag;
            res = dwarf_tag(variable_die, &tag, err);
            if (res == DW_DLV_ERROR) {
                break;
            }

            if (tag != DW_TAG_variable && tag != DW_TAG_formal_parameter) {
                goto next_member;
            }

            Dwarf_Off type_offset;
            Dwarf_Bool is_info_section;
            res = dwarf_dietype_offset(variable_die, &type_offset,
                                       &is_info_section, err);

            if (res == DW_DLV_ERROR) {
                break;
            }

            if (res == DW_DLV_NO_ENTRY) {
                goto next_member;
            }

            char *name;
            res = dwarf_diename(variable_die, &name, err);
            if (res == DW_DLV_ERROR) {
                break;
            }
            if (res == DW_DLV_NO_ENTRY) {
                goto next_member;
            }
            
            /* Находим расположение переменной относительно начала стека.
             * Это должна быть операция DW_OP_fbreg с единственным аргументом -
             * смещение относительно начала фрейма. 
             * Ищем в атрибуте DW_AT_location.
             */
            Dwarf_Attribute location_attr;
            res = dwarf_attr(variable_die, DW_AT_location, &location_attr, err);
            if (res == DW_DLV_ERROR) {
                break;
            }
            if (res == DW_DLV_NO_ENTRY) {
                goto next_member;
            }

            /* DW_FORM_exprloc */
            Dwarf_Loc_Head_c head;
            Dwarf_Unsigned locs_count;
            res = dwarf_get_loclist_c(location_attr, &head, &locs_count, err);
            if (res == DW_DLV_ERROR) {
                break;
            }
            if (res == DW_DLV_NO_ENTRY || locs_count != 1) {
                goto next_member;
            }
            /* 
             * Пока обрабатываем только смещение относительно начала фрейма.
             * Это должна быть операция DW_OP_fbreg с единственным аргументом -
             * смещение относительно начала фрейма. 
             * Ищем в атрибуте 
             */
            Dwarf_Small loclist_source = 0;
            Dwarf_Small lle_value = 0;
            Dwarf_Unsigned rawlowpc = 0;
            Dwarf_Unsigned rawhighpc = 0;
            Dwarf_Bool debug_addr_unavailable = false;
            Dwarf_Addr low_pc_cooked = 0;
            Dwarf_Addr high_pc_cooked = 0;
            Dwarf_Unsigned locexprs_count = 0;
            Dwarf_Locdesc_c locdesc_entry = 0;
            Dwarf_Unsigned expr_offset = 0;
            Dwarf_Unsigned locdesc_offset = 0;

            res = dwarf_get_locdesc_entry_d(head, 0,
                                            &lle_value,
                                            &rawlowpc, &rawhighpc,
                                            &debug_addr_unavailable,
                                            &low_pc_cooked, &high_pc_cooked,
                                            &locexprs_count,
                                            &locdesc_entry,
                                            &loclist_source,
                                            &expr_offset,
                                            &locdesc_offset,
                                            err);
            if (res == DW_DLV_ERROR) {
                dwarf_dealloc_loc_head_c(head);
                break;
            }
            if (res == DW_DLV_NO_ENTRY) {
                dwarf_dealloc_loc_head_c(head);
                goto next_member;
            }

            if (locexprs_count != 1) {
                dwarf_dealloc_loc_head_c(head);
                goto next_member;
            }

            Dwarf_Small operation;
            Dwarf_Unsigned operand1;
            Dwarf_Unsigned operand2;
            Dwarf_Unsigned operand3;
            Dwarf_Unsigned offset_for_branch;
            res = dwarf_get_location_op_value_c(locdesc_entry, 0, &operation, 
                                                &operand1, &operand2, &operand3,
                                                &offset_for_branch, err);
            if (res == DW_DLV_ERROR) {
                dwarf_dealloc_loc_head_c(head);
                break;
            }
            if (res == DW_DLV_NO_ENTRY) {
                dwarf_dealloc_loc_head_c(head);
                goto next_member;
            }

            if (operation != DW_OP_fbreg) {
                dwarf_dealloc_loc_head_c(head);
                goto next_member;
            }

            dwarf_dealloc_loc_head_c(head);

            /* 
             * Создаем саму переменную 
             */
            Variable var;
            var.name = strdup(name);
            if (var.name == NULL) {
                res = DW_DLV_ERROR;
                break;
            }
            /* 
             * В указателе храним ID самого типа.
             * Проставим реальный после всех манипуляций.
             * Сейчас эта информация нам не нужна, к счастью.
             */
            var.type = (BaseType *) type_offset;
            /*
             * На самом деле, операнд для DW_OP_fbreg - Dwarf_Signed,
             * но в api это Dwarf_Unsiged.
             * Сделаю каст на укороченный знаковый int здесь, а не там,
             * чтобы компилятор не ругался.
             */
            var.frame_offset = (int) operand1;

            if (VariableList_add(variables, &var) == -1) {
                VariableList_free(variables);
                res = DW_DLV_ERROR;
                break;
            }

        next_member:     
            res = dwarf_siblingof_c(variable_die, &next_die, err);
            if (res != DW_DLV_OK) {
                break;
            }

            dwarf_dealloc_die(variable_die);
            variable_die = next_die;
        } while (true);

        dwarf_dealloc_die(variable_die);
    }

    if (res == DW_DLV_ERROR) {
        return -1;
    }
    memset(info, 0, sizeof(FunctionInfo));
    info->name = strdup(name);
    info->low_pc = (long) low_pc;
    info->high_pc = (long) high_pc;
    info->variables = variables;
    SourceLineList_init(&info->line_table);
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

static int fill_cu_line_table(Dwarf_Die cu_die, Dwarf_Error *err, DebugInfo *di) {
    /* Заполняем информацию об исходном коде(строки) */
    Dwarf_Unsigned version;
    Dwarf_Small table_count;
    Dwarf_Line_Context line_context;

    if (dwarf_srclines_b(cu_die, &version, &table_count, &line_context, err) !=
        DW_DLV_OK) {
        return -1;
    }

    /*
     * Работаем только с 1-уровневой таблицей
     */
    if (table_count == 0 || table_count == 2) {
        dwarf_srclines_dealloc_b(line_context);
        dwarf_dealloc_die(cu_die);
        return 0;
    }

    /*
     * Кэшируем последний function_info, чтобы заново не искать каждый раз.
     * Т.к. строки идут последовательно и мы скорее всего окажемся в той же
     * функции
     */
    FunctionInfo *cached_fi = NULL;

    SourceLineInfo *prev_sl_info = NULL;

    Dwarf_Line *lines;
    Dwarf_Signed lines_count;

    int vres = 0;

    if (dwarf_srclines_from_linecontext(line_context, &lines, &lines_count,
                                        err) != DW_DLV_OK) {
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
        if (dwarf_prologue_end_etc(line, &prologue_end, &epilogue_begin, &isa,
                                   &discriminator, err) == -1) {
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
                    di->functions, function_info_contains_address_predicate,
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
    return 0;
}

typedef struct struct_member {
    char *name;
    Dwarf_Signed offset;
    Dwarf_Off type_offset;
} struct_member;

LIST_DEFINE(struct_member, struct_member_list)
LIST_DECLARE(struct_member, struct_member_list)

typedef struct type_info {
    /* Тэг типа - DW_TAG_primitive/pointer/structure/const */
    Dwarf_Half tag;
    /* Смещение записи в таблице. Используется как идентификатор */
    Dwarf_Off offset;
    /* Название типа */
    char *name;

    /* Знаковый или нет, если примитив */
    Dwarf_Bool is_signed;

    /* Размер в байтах, если примитив */
    Dwarf_Unsigned byte_size;

    /* Тип, на который указывает указатель, если DW_TAG_pointer */
    Dwarf_Off pointer_type_offset;

    /* Поля структуры, если структура */
    struct_member_list *members;

    /* Тип, на который указывает этот декоратор ('const', 'typedef' и т.д.) */
    Dwarf_Off decorated_type_offset;

    /* 
     * Созданный тип на основании этого type_info.
     * Если NULL - еще не создан.
     */
    BaseType *build_type;
    /* 
     * Данный узел находится в обработке.
     * Используется во время создания типов 
     * для предотвращения бесконечной рекурсии.
     */
    bool is_processing;
} type_info;

LIST_DEFINE(type_info, type_list)
LIST_DECLARE(type_info, type_list)

static int fill_subprogram_die(Dwarf_Die die, Dwarf_Error *err, type_list *types,
                                DebugInfo *di) {
    FunctionInfo info;
    memset(&info, 0, sizeof(FunctionInfo));
    if (SourceLineList_init(&info.line_table) == -1) {
        return -1;
    }

    switch (fill_function_info(die, err, &info)) {
        case -1:
            SourceLineList_free(info.line_table);
            return -1;
        case 0:
            /* 
             * Функция имеет все необходимые данные - добавляем в свой
             * список 
             */
            if (FunctionInfoList_add(di->functions, &info) == -1) {
                SourceLineList_free(info.line_table);
                free((void *) info.name);
                return -1;
            }
            return 0;
        case 1:
            /* Невалидная функция, возможно, внешняя, поэтому не ошибка */
            SourceLineList_free(info.line_table);
            free((void *) info.name);
            return 0;
        default:
            assert(false);
            return -1;
    }
}

static int fill_base_type_die(Dwarf_Die die, Dwarf_Error *err, type_list *types, 
                              DebugInfo *di) {
    Dwarf_Off global_offset;
    Dwarf_Off local_offset;
    if (dwarf_die_offsets(die, &global_offset, &local_offset, err) != DW_DLV_OK) {
        return -1;
    }

    Dwarf_Unsigned byte_size;
    switch (dwarf_bytesize(die, &byte_size, err) ) {
        case DW_DLV_ERROR:
            return -1;
        case DW_DLV_NO_ENTRY:
            return 0;
    }

    char *name;
    switch (dwarf_diename(die, &name, err)) {
        case DW_DLV_ERROR:
            return -1;
        case DW_DLV_NO_ENTRY:
            return 0;
    }

    Dwarf_Attribute encoding_attr;
    switch (dwarf_attr(die, DW_AT_encoding, &encoding_attr, err)) {
        case DW_DLV_ERROR:
            return -1;
        case DW_DLV_NO_ENTRY:
            return 0;
    }

    Dwarf_Signed encoding;
    if (dwarf_formsdata(encoding_attr, &encoding, err) != DW_DLV_OK) {
        dwarf_dealloc_attribute(encoding_attr);
        return 0;
    }
    dwarf_dealloc_attribute(encoding_attr);

    type_info type;
    memset(&type, 0, sizeof(type_info));

    type.name = strdup(name);
    if (type.name == NULL) {
        return -1;
    }
    type.tag = DW_TAG_base_type;
    type.offset = global_offset;

    type.byte_size = (int) byte_size;
    type.is_signed = encoding == DW_ATE_signed | 
                     encoding == DW_ATE_signed_char;

    type_list_add(types, &type);
    return 0;
}

static int fill_pointer_type_die(Dwarf_Die die, Dwarf_Error *err, type_list *types,
                                 DebugInfo *di) {
    Dwarf_Off offset;
    Dwarf_Bool is_info_section;
    if (dwarf_dieoffset(die, &offset, err) != DW_DLV_OK) {
        return -1;
    }

    Dwarf_Off pointed_type;
    switch (dwarf_dietype_offset(die, &pointed_type, &is_info_section, err)) {
        case DW_DLV_ERROR:
            return -1;
        case DW_DLV_NO_ENTRY:
            return 0;
    }

    type_info type;
    memset(&type, 0, sizeof(type_info));

    type.tag = DW_TAG_pointer_type;
    /* У указателя нет названия типа */
    type.name = NULL;
    type.offset = offset;
    type.pointer_type_offset = pointed_type;

    if (type_list_add(types, &type) == -1) {
        return -1;
    }

    return 0;
}

static int fill_struct_type_die(Dwarf_Die die, Dwarf_Error *err, type_list *types,
                                DebugInfo *di) {
    /* Собираем информацию по структуре */
    Dwarf_Off global_offset;
    if (dwarf_dieoffset(die, &global_offset, err) !=
        DW_DLV_OK) {
        return -1;
    }

    char *struct_name;
    switch (dwarf_diename(die, &struct_name, err)) {
        case DW_DLV_ERROR:
            return -1;
        case DW_DLV_NO_ENTRY:
            return 0;
    }

    struct_member_list *members;
    if (struct_member_list_init(&members) == -1) {
        return -1;
    }

    Dwarf_Die member_die;
    int ret = dwarf_child(die, &member_die, err);

    /* Собираем информацию по каждому полю структуры */
    if (ret == DW_DLV_OK) {
        Dwarf_Die next_member_die;

        do {
            /* Обрабатываем только поля структуры */
            Dwarf_Half tag;
            if (dwarf_tag(member_die, &tag, err) == DW_DLV_ERROR) {
                ret = DW_DLV_ERROR;
                break;
            }

            if (tag != DW_TAG_member) {
                goto next_member;
            }

            /* Смещение DIE поля TODO: неправильно определяю смещение поля */
            Dwarf_Attribute data_location_attribute;
            ret = dwarf_attr(member_die, DW_AT_data_member_location, &data_location_attribute, err);
            if (ret == DW_DLV_ERROR) {
                break;
            }
            if (ret == DW_DLV_NO_ENTRY) {
                continue;
            }

            Dwarf_Signed member_offset;
            ret = dwarf_formsdata(data_location_attribute, &member_offset, err);
            dwarf_dealloc_attribute(data_location_attribute);
            if (ret == DW_DLV_ERROR) {
                break;
            }
            if (ret == DW_DLV_NO_ENTRY) {
                continue;
            }

            /* Название поля */
            char *member_name;
            ret = dwarf_diename(member_die, &member_name, err);
            if (ret == DW_DLV_ERROR) {
                break;
            }

            if (ret == DW_DLV_NO_ENTRY) {
                continue;
            }

            /* Тип поля */
            Dwarf_Off member_type;
            Dwarf_Bool is_info_section;
            ret = dwarf_dietype_offset(member_die, &member_type,
                                       &is_info_section, err);
            if (ret == DW_DLV_ERROR) {
                break;
            }
            if (ret == DW_DLV_NO_ENTRY) {
                continue;
            }
            
            struct_member member;
            member.name = strdup(member_name);
            if (member.name == NULL) {
                free(member.name);
                ret = DW_DLV_ERROR;
                break;
            }
            member.offset = member_offset;
            member.type_offset = member_type;

            if (struct_member_list_add(members, &member) == -1) {
                free(member.name);
                ret = DW_DLV_ERROR;
                break;
            }

        next_member:
            ret = dwarf_siblingof_c(member_die, &next_member_die, err);
            if (ret != DW_DLV_OK) {
                break;
            }
            dwarf_dealloc_die(member_die);
            member_die = next_member_die;
        } while (true);

        dwarf_dealloc_die(member_die);
    }

    if (ret == DW_DLV_ERROR) {
        struct_member_list_free(members);
        return -1;
    }

    type_info type;
    memset(&type, 0, sizeof(type_info));

    type.tag = DW_TAG_structure_type;
    type.name = strdup(struct_name);
    if (type.name == NULL) {
        struct_member_list_free(members);
        return -1;
    }
    type.offset = global_offset;
    type.members = members;

    if (type_list_add(types, &type) == -1) {
        struct_member_list_free(members);
        free(struct_name);
        return -1;
    }

    return 0;
}

static int fill_const_type_die(Dwarf_Die die, Dwarf_Error *err, type_list *types,
                               DebugInfo *di) {
    Dwarf_Off offset;
    int ret = dwarf_dieoffset(die, &offset, err);
    if (ret == DW_DLV_ERROR) {
        return -1;
    }
    if (ret == DW_DLV_NO_ENTRY) {
        return 0;
    }
    
    Dwarf_Off type_offset;
    Dwarf_Bool is_info_section;
    ret = dwarf_dietype_offset(die, &type_offset, &is_info_section, err);
    if (ret == DW_DLV_ERROR) {
        return -1;
    }
    if (ret == DW_DLV_NO_ENTRY) {
        return 0;
    }

    type_info info;
    memset(&info, 0, sizeof(type_info));
    info.tag = DW_TAG_const_type;
    info.offset = offset;
    info.name = strdup("");
    info.decorated_type_offset = type_offset;
    if (info.name == NULL) {
        return -1;
    }
    if (type_list_add(types, &info) == -1) {
        free(info.name);
        return -1;
    }
    return 0;
}

static int fill_typedef_die(Dwarf_Die die, Dwarf_Error *err, type_list *types,
                            DebugInfo *di) {
    Dwarf_Off offset;
    int res = dwarf_dieoffset(die, &offset, err);
    if (res == DW_DLV_ERROR) {
        return -1;
    }
    if (res == DW_DLV_NO_ENTRY) {
        return 0;
    }

    Dwarf_Off type;
    Dwarf_Bool is_info_section;
    res = dwarf_dietype_offset(die, &type, &is_info_section, err);
    if (res == DW_DLV_ERROR) {
        return -1;
    }
    if (res == DW_DLV_NO_ENTRY) {
        return 0;
    }

    type_info info;
    memset(&info, 0, sizeof(type_info));
    info.offset = offset;
    info.name = strdup("");
    info.tag = DW_TAG_typedef;
    info.decorated_type_offset = type;
    if (info.name == NULL) {
        return -1;
    }

    if (type_list_add(types, &info) == -1) {
        free(info.name);
        return -1;
    }

    return 0;
}

static int fill_cu_debug_info(Dwarf_Die cu_die, Dwarf_Error *err, type_list *types,
                              DebugInfo *di) {
    /* TODO: создаем внутреннюю структуру, которая хранит значения всех типов, 
     * а в конце создаем готовый список типов и собираем FunctionInfo переменные
     */
    int ret = 0;
    int res = 0;
    Dwarf_Die sib_die = 0;
    Dwarf_Half tag = 0;

    do {
        /* Обрабатываем текущий DIE - находим функцию */
        if (dwarf_tag(cu_die, &tag, err) != DW_DLV_OK) {
            ret = -1;
            break;
        }

        if (tag == DW_TAG_subprogram) {
            if (fill_subprogram_die(cu_die, err, types, di) == -1) {
                ret = -1;
                break;
            }
        } else if (tag == DW_TAG_base_type) {
            if (fill_base_type_die(cu_die, err, types, di) == -1) {
                ret = -1;
                break;
            }
        } else if (tag == DW_TAG_pointer_type) {
            if (fill_pointer_type_die(cu_die, err, types, di) == -1) {
                ret = -1;
                break;
            }
        } else if (tag == DW_TAG_structure_type) {
            if (fill_struct_type_die(cu_die, err, types, di) == -1) {
                ret = -1;
                break;
            }
        } else if (tag == DW_TAG_const_type) {
            if (fill_const_type_die(cu_die, err, types, di) == -1) {
                ret = -1;
                break;
            }
        } else if (tag == DW_TAG_typedef) {
            if (fill_typedef_die(cu_die, err, types, di) == -1) {
                ret = -1;
                break;
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

static int debug_syms_fill(Dwarf_Debug dbg, Dwarf_Error *err,
                           type_list *types, DebugInfo *info) {
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

        if (res != DW_DLV_OK) {
            /*
             * Нет смысла заполнять информацию далее, т.к.
             * текущий CU не найден. Нового ничего не добавим
             */
            dwarf_dealloc_die(cu_child);
            dwarf_dealloc_die(cu_die);
            continue;
        }

        if (fill_cu_debug_info(cu_child, err, types, info) == -1) {
            return -1;
        }

        if (fill_cu_line_table(cu_die, err, info) == -1) {
            dwarf_dealloc_die(cu_die);
            return -1;
        }

        dwarf_dealloc_die(cu_die);
    }

    return 0;
}

static int type_info_id_equal_predicate(void *context, type_info *type) {
    if ((long)context == type->offset) {
        return 1;
    }
    return 0;
}

static BaseType *get_type(long id, type_list *types) {
    type_info *type;
    if (type_list_contains(types, type_info_id_equal_predicate, (void *)id, &type) == 0) {
        return NULL;
    }

    if (type->build_type != NULL) {
        return type->build_type;
    }

    if (type->is_processing) {
        /* Для предотвращения рекурсии возвращаем NULL */
        return NULL;
    }

    type->is_processing = true;

    BaseType *result = NULL;
    PrimitiveType *primitive;
    PointerType *pointer;
    StructType *structure;
    TypeKind kind = -1;

    switch (type->tag) {
        case DW_TAG_base_type:
            kind = TypeKindPrimitive;
            primitive = malloc(sizeof(PrimitiveType));
            if (primitive == NULL) {
                break;
            }
            primitive->byte_size = (int) type->byte_size;
            primitive->is_signed = (bool) type->is_signed;
            result = (BaseType *)primitive;
            break;
        case DW_TAG_pointer_type:
            kind = TypeKindPointer;
            pointer = malloc(sizeof(PointerType));
            if (pointer == NULL) {
                break;
            }

            BaseType *pointed_type = get_type((long)type->pointer_type_offset, types);
            pointer->type = pointed_type;
            result = (BaseType *)pointer;
            break;
        case DW_TAG_structure_type:
            kind = TypeKindStruct;
            structure = malloc(sizeof(StructType));
            if (structure == NULL) {
                break;
            }
            if (StructMemberList_init(&structure->members) == -1) {
                free(structure);
                break;
            }
            
            struct_member *member;
            foreach (member, type->members) {
                StructMember m;
                memset(&m, 0, sizeof(StructMember));
                m.name = member->name;
                m.byte_offset = (int) member->offset;
                BaseType *member_type = get_type((long) member->type_offset, types);
                if (member_type != NULL) {
                    m.type = member_type;
                } else {
                    m.type = (void *)member->type_offset;
                }

                if (StructMemberList_add(structure->members, &m) == -1) {
                    StructMemberList_free(structure->members);
                    free(structure);
                    break;
                }
            }

            result = (BaseType *)structure;
            break;
        case DW_TAG_const_type:
        case DW_TAG_typedef:
            /* Всякие декораторы обрабатываются единообразно */
            result = get_type(type->decorated_type_offset, types);
            type->is_processing = false;
            type->build_type = result;
            return result;
        default:
            assert(false);
            result = NULL;
            break;
    }

    if (result != NULL) {
        assert(kind != -1);
        result->kind = kind;
        result->name = type->name;
    }
    type->build_type = result;
    type->is_processing = false;
    return result;
}

static int build_debug_syms(DebugInfo *di, type_list *types) { 
    /* 
     * Здесь мы собираем всю информацию о типах,
     * которые представлены в функциях.
     * 
     * В поле type у Variable хранится ID типа, который его представляет.
     * Сами типы в сыром виде хранятся в списке types.
     * Проходим по каждой переменной
     */
    FunctionInfo *func;
    foreach (func, di->functions) {
        Variable *var;
        foreach (var, func->variables) {
            BaseType *type = get_type((long)var->type, types);
            if (type != NULL) {
                var->type = type;
            }
        }
    }

    /* 
     * Пройдемся 2 раз, когда основные типы уже созданы,
     * чтобы обработать ситуации рекурсии.
     */
    foreach (func, di->functions) {
        Variable *var;
        foreach (var, func->variables) {
            /* Небольшой хак, чтобы проверить, что тип был инициализирован */
            if ((void *) var->type < (void *) 0x10000) {
                var->type = get_type((long)var->type, types);
            }
        }
    }

    /* Дополнительно проверяем поля структур */
    type_info *ti;
    foreach (ti, types) {
        if (ti->tag != DW_TAG_structure_type) {
            continue;
        }

        if (ti->build_type == NULL) {
            continue;
        }

        StructMember *member;
        foreach (member, ((StructType *)ti->build_type)->members) {
            if ((void *) member->type < (void *) 0x10000) {
                member->type = get_type((long)member->type, types);
            }
        }
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

    type_list *types;
    if (type_list_init(&types) == -1) {
        free(info);
        return -1;
    }

    if (FunctionInfoList_init(&info->functions) == -1) {
        free(info);
        return -1;
    }

    if (debug_syms_fill(dbg, &err, types, info) == -1) {
        dwarf_finish(dbg);
        free(info);
        return -1;
    }

    if (dwarf_finish(dbg) != DW_DLV_OK) {
        free(info);
        return -1;
    }

    if (build_debug_syms(info, types) == -1) {
        type_list_free(types);
        free(info);
        return -1;
    }
    type_list_free(types);

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

static int variable_name_equal_predicate(void *context, Variable *var) {
    if (strcmp((const char *)context, var->name) == 0) {
        return 1;
    }
    return 0;
}

int debug_syms_get_variable(DebugInfo *debug_info, const char *name,
                            Variable **var) {
    FunctionInfo *func;
    foreach (func, debug_info->functions) {
        if (VariableList_contains(func->variables, variable_name_equal_predicate, 
                                  (void *)name, var) == 1) {
            return 1;
        }
    }
    errno = ENOENT;
    return -1;
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