#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "libdwarf-0/dwarf.h"
#include "libdwarf-0/libdwarf.h"

#include "list.h"
#include "debug_syms.h"

LIST_DEFINE(FunctionInfo, func_info_list)

/*
 * Получить информацию о функции из переданного DIE для функции (DW_TAG_subprogram).
 *
 * Возвращает:
 * 0  - успешно обработано
 * 1  - это внешняя функция, которая нам не интересна (например, printf из libc)
 * -1 - ошибка
 */
static int fill_function_info(Dwarf_Die subprog_die, Dwarf_Error *err, FunctionInfo *info)
{
    int res = 0;
    char *name = "\0";
    Dwarf_Addr low_pc = 0;
    Dwarf_Addr high_pc = 0;
    Dwarf_Half high_pc_form = 0;
    enum Dwarf_Form_Class high_pc_form_class = 0;

    res = dwarf_diename(subprog_die, &name, err);
    if (res == DW_DLV_ERROR)
    {
        return -1;
    }

    if (res == DW_DLV_NO_ENTRY)
    {
        return 1;
    }

    res = dwarf_lowpc(subprog_die, &low_pc, err);
    if (res == DW_DLV_ERROR)
    {
        return -1;
    }
    if (res == DW_DLV_NO_ENTRY)
    {
        return 1;
    }

    res = dwarf_highpc_b(subprog_die, &high_pc, &high_pc_form, &high_pc_form_class, err);
    if (res == DW_DLV_ERROR)
    {
        return -1;
    }

    if (res == DW_DLV_NO_ENTRY)
    {
        return 1;
    }

    if (high_pc_form_class == DW_FORM_CLASS_CONSTANT)
    {
        high_pc += low_pc;
    }

    memset(info, 0, sizeof(FunctionInfo));
    info->name = strdup(name);
    info->low_pc = (long) low_pc;
    info->high_pc = (long) high_pc;
    return 0;
}

static int fill_debug_info_recurse(Dwarf_Die cur_die, Dwarf_Error *err, DebugInfo *di)
{
    int ret = 0;
    int res = 0;
    func_info_list funcs;
    Dwarf_Die sib_die = 0;
    Dwarf_Half tag = 0;

    func_info_list_init(&funcs);

    do
    {
        /* Обрабатываем текущий DIE - находим функцию */
        if (dwarf_tag(cur_die, &tag, err) != DW_DLV_OK)
        {
            ret = -1;
            break;
        }

        if (tag == DW_TAG_subprogram)
        {
            FunctionInfo info;
            memset(&info, 0, sizeof(FunctionInfo));
            res = fill_function_info(cur_die, err, &info);
            if (res == -1)
            {
                ret = -1;
                break;
            }

            if (res == 0)
            {
                /* Функция имеет все необходимые данные - добавляем в свой список */
                if (func_info_list_add(&funcs, &info) == -1)
                {
                    ret = -1;
                    free((void*)info.name);
                    break;
                }
            }
            else if (res == 1)
            {
                /* Невалидная функция */
                free((void *)info.name);
            }
        }

        /* Переходим к следующему DIE */
        res = dwarf_siblingof_c(cur_die, &sib_die, err);
        if (res == DW_DLV_ERROR)
        {
            ret = -1;
            break;
        }

        if (res == DW_DLV_NO_ENTRY)
        {
            /* Это был последний DIE */
            ret = 0;
            break;
        }

        dwarf_dealloc_die(cur_die);
        cur_die = sib_die;
    } while (true);

    if (ret == -1)
    {
        func_info_list_free(&funcs);
        dwarf_dealloc_die(cur_die);
        return -1;
    }

    di->functions = list_data_raw(&funcs);
    di->functions_count = list_size(&funcs);
    return 0;
}

static int debug_syms_fill_debug_info(Dwarf_Debug dbg, Dwarf_Error *err, DebugInfo *info)
{
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

    while (true)
    {
        Dwarf_Half tag;
        Dwarf_Die cu_die;
        Dwarf_Die cu_child;

        res = dwarf_next_cu_header_e(dbg, is_info, &cu_die, &header_length, &version, &abbrev_offset, &address_size, &length_size, &extension_size, &sig, &type_offset, &next_cu_offset, &header_cu_type, err);
        if (res == DW_DLV_ERROR)
        {
            return -1;
        }

        if (res == DW_DLV_NO_ENTRY)
        {
            dwarf_dealloc_die(cu_die);
            break;
        }

        res = dwarf_tag(cu_die, &tag, err);
        if (res == DW_DLV_ERROR)
        {
            return -1;
        }

        if (tag != DW_TAG_compile_unit)
        {
            dwarf_dealloc_die(cu_die);
            continue;
        }

        res = dwarf_child(cu_die, &cu_child, err);
        if (res == DW_DLV_ERROR)
        {
            return -1;
        }

        if (res == DW_DLV_OK /* != DW_DLV_NO_ENTRY */)
        {
            if (fill_debug_info_recurse(cu_child, err, info) == -1)
            {
                return -1;
            }
        }

        dwarf_dealloc_die(cu_die);
    }
}

int debug_syms_get(const char *filename, DebugInfo *debug_info)
{
    Dwarf_Debug dbg;
    Dwarf_Error err;
    if (dwarf_init_path(filename, NULL, 0, DW_GROUPNUMBER_ANY, NULL, NULL, &dbg, &err) != DW_DLV_OK)
    {
        return -1;
    }

    memset(debug_info, 0, sizeof(DebugInfo));
    if (debug_syms_fill_debug_info(dbg, &err, debug_info) == -1)
    {
        return -1;
    }

    return 0;
}

int debug_syms_free(DebugInfo *debug_info)
{
    return -1;
}
