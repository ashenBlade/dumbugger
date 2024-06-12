#include <stdlib.h>
#include <ctype.h>

#include "utils.h"
#include "list.h"

LIST_DEFINE(char *, str_list)

int split_str(int length, const char *str, int *argc, char ***argv)
{
    if (length == 0)
    {
        *argc = 0;
        *argv = NULL;
        return 0;
    }

    str_list list;
    str_list_init(&list);

    int start = 0, cur = 0;
    while (cur < length)
    {
        while (cur < length && isspace(str[cur]))
        {
            ++cur;
        }

        if (cur == length)
        {
            break;
        }

        start = cur;
        cur++;

        while (cur < length &&  !isspace(str[cur]))
        {
            ++cur;
        }

        int new_str_len = cur - start + 1;
        char *new_str = (char *)calloc(new_str_len, sizeof(char));
        if (new_str == NULL)
        {
            str_list_free(&list);
            return -1;
        }

        memcpy(new_str, str + start, new_str_len - 1);
        new_str[new_str_len - 1]  = '\0';

        if (str_list_add(&list, &new_str) == -1)
        {
            free(new_str);
            str_list_free(&list);
            return -1;
        }
    }

    *argv = list_data_raw(&list);
    *argc = list_size(&list);
    return 0;
}