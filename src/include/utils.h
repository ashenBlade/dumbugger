#ifndef UTILS_H
#define UTILS_H

/* 
 * Разбить переданную строку по пробельным символам.
 * Результат помещается в argc и argv.
 * После работы необходимо освободить память из argv (используется динамическая память)
 */
int split_str(int length, const char *str, int *argc, char ***argv);

#endif