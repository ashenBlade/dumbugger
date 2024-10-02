#include <stdlib.h>
#include <ctype.h>

#include "utils.h"
#include "list.h"

LIST_DEFINE(char *, str_list)
LIST_DECLARE(char *, str_list)

int split_str(int length, const char *str, int *argc, char ***argv) {
    if (length == 0) {
        *argc = 0;
        *argv = NULL;
        return 0;
    }

    str_list *list;
    if (str_list_init(&list) == -1) {
        return -1;
    }

    int start = 0, cur = 0;
    while (cur < length) {
        /* Пропускаем начальные пробелы */
        while (cur < length && isspace(str[cur])) {
            ++cur;
        }

        if (cur == length) {
            /* В конце были только пробелы */
            break;
        }

        start = cur;
        cur++;

        /* Идем до следующих пробелов */
        while (cur < length && !isspace(str[cur])) {
            ++cur;
        }

        /* Выделяем место для новой строки */
        int new_str_len = cur - start + 1;
        char *new_str = (char *) calloc(new_str_len, sizeof(char));
        if (new_str == NULL) {
            str_list_free(list);
            return -1;
        }

        memcpy(new_str, str + start, new_str_len - 1);
        new_str[new_str_len - 1] = '\0';

        if (str_list_add(list, &new_str) == -1) {
            free(new_str);
            str_list_free(list);
            return -1;
        }
    }

    int argv_count = list_size(list);
    char **argv_arr = malloc(argv_count * sizeof(char *));
    if (argv_arr == NULL) {
        str_list_free(list);
        return -1;
    }

    for (int i = 0; i < argv_count; ++i) {
        argv_arr[i] = list_get(list, i);
    }

    *argv = argv_arr;
    *argc = argv_count;
    str_list_free(list);
    return 0;
}