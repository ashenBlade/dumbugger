#ifndef LIST_H
#define LIST_H

#include <stdlib.h>
#include <string.h>

#define LIST_DEFINE(type, typename)                                                                        \
    typedef struct typename                                                                                \
    {                                                                                                      \
        type *data;                                                                                        \
        int count;                                                                                         \
        int capacity;                                                                                      \
    }                                                                                                      \
    typename;                                                                                              \
    void typename##_init(typename *list)                                                                   \
    {                                                                                                      \
        memset(list, 0, sizeof(typename));                                                                 \
    }                                                                                                      \
    int typename##_add(typename *list, type *value)                                                        \
    {                                                                                                      \
        if (list->capacity == 0)                                                                           \
        {                                                                                                  \
            list->capacity = 4;                                                                            \
            list->data = (type *)malloc(sizeof(type) * list->capacity);                                    \
        }                                                                                                  \
        else if (list->count == list->capacity)                                                            \
        {                                                                                                  \
            list->capacity *= 2;                                                                           \
            list->data = (type *)realloc(list->data,                                                       \
                                         sizeof(type) * list->capacity);                                   \
        }                                                                                                  \
                                                                                                           \
        if (list->data == NULL)                                                                            \
        {                                                                                                  \
            return -1;                                                                                     \
        }                                                                                                  \
                                                                                                           \
        memcpy(&list->data[list->count], value, sizeof(type));                                             \
        ++list->count;                                                                                     \
        return 0;                                                                                          \
    }                                                                                                      \
                                                                                                           \
    int typename##_remove(typename *list, int index)                                                       \
    {                                                                                                      \
        if (list->count <= index)                                                                          \
        {                                                                                                  \
            return -1;                                                                                     \
        }                                                                                                  \
        if (list->count == index + 1)                                                                      \
        {                                                                                                  \
            --list->count;                                                                                 \
            return 0;                                                                                      \
        }                                                                                                  \
        memcpy(&list->data[index], &list->data[index + 1],                                                 \
               sizeof(type) * (list->count - index - 1));                                                  \
        --list->count;                                                                                     \
        return 0;                                                                                          \
    }                                                                                                      \
    /* 1 - условие выполняется \
     * 0 - условие НЕ выполняется  \
     */                                                                                                    \
    typedef int typename##_predicate(void *context, type *element);                                        \
    /* Найти элемент в списке, который удовлетворяет условию \
     * 1 - элемент найден \
     * 0 - НЕ найден \
     * Если элемент найден и result != NULL, то \
     * в result сохраняется указатель на найденное значение \
     */                                                                                                    \
    int typename##_contains(typename *list, typename##_predicate predicate, void *context,                 \
                            type **result)                                                                 \
    {                                                                                                      \
        type *element;                                                                                     \
        foreach (element, list)                                                                            \
        {                                                                                                  \
            if (predicate(context, element))                                                               \
            {                                                                                              \
                if (result != NULL)                                                                        \
                {                                                                                          \
                    *result = element;                                                                     \
                }                                                                                          \
                return 1;                                                                                  \
            }                                                                                              \
        }                                                                                                  \
        return 0;                                                                                          \
    }                                                                                                      \
                                                                                                           \
    int typename##_free(typename *list)                                                                    \
    {                                                                                                      \
        if (list->data != NULL)                                                                            \
        {                                                                                                  \
            free(list->data);                                                                              \
        }                                                                                                  \
        memset(list, 0, sizeof(typename));                                                                 \
        return 0;                                                                                          \
    }

#define foreach(elem, list) for (int __##elem##__i = 0; __##elem##__i < (list)->count ? ((elem) = &(list)->data[__##elem##__i], 1) : 0; ++__##elem##__i)

#define list_get(list, index) ((list)->data[index])

#define list_size(list) ((list)->count)

#define list_data_raw(list) ((list)->data)

#endif