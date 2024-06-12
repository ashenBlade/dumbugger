#ifndef COMMANDS_H
#define COMMANDS_H

/* 
 * Функция обработки пользовательской команды 
 * state - указатель на структуру с контекстом, может быть любым
 * argc - количество входных аргументов
 * argv - массив аргументов, первым аргументом включает название команды
 */
typedef int (*command_func)(void *state, int argc, char **argv);

/* 
 * Реестр пользовательских команд
 */
typedef struct CommandsRegistry CommandsRegistry;

/* 
 * Создать новый реестр пользовательских команд 
 */
CommandsRegistry* cmdreg_new();

/* 
 * Освободить ресурсы, выделенные для работу реестра и очистить состояние 
 */
int cmdreg_free(CommandsRegistry* reg);

/* 
 * Зарегистрировать новую команду в список команд 
 */
int cmdreg_add(CommandsRegistry* reg, const char* name, command_func func);

/* 
 * Найти указанную команду по названию
 */
command_func cmdreg_find(CommandsRegistry *reg, const char *name);

#endif