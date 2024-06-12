#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>

#include "commands.h"
#include "list.h"

typedef struct command
{
    command_func func;
    const char *name;
} command;

LIST_DEFINE(command, cmd_list)

struct CommandsRegistry
{
    bool init;
    cmd_list list;
};

CommandsRegistry *cmdreg_new()
{
    CommandsRegistry *reg = malloc(sizeof(CommandsRegistry));
    if (reg == NULL)
    {
        return NULL;
    }
    memset(reg, 0, sizeof(CommandsRegistry));
    return reg;
}

int cmdreg_free(CommandsRegistry *reg)
{
    if (reg == NULL)
    {
        return 0;
    }

    if (!reg->init)
    {
        return 0;
    }

    if (cmd_list_free(&reg->list) == -1)
    {
        return -1;
    }

    return 0;
}

int cmdreg_add(CommandsRegistry *reg, const char *name, command_func func)
{
    if (reg == NULL || name == NULL || func == NULL)
    {
        errno = EINVAL;
        return -1;
    }

    command cmd = {
        .func = func,
        .name = name,
    };

    if (cmd_list_add(&reg->list, &cmd) == -1)
    {
        return -1;
    }

    return 0;
}

command_func cmdreg_find(CommandsRegistry *reg, const char *name)
{
    if (reg == NULL || name == NULL)
    {
        errno = EINVAL;
        return NULL;
    }

    if (list_size(&reg->list) == 0)
    {
        return NULL;
    }

    command *cmd;
    foreach (cmd, &reg->list)
    {
        if (strcasecmp(name, cmd->name) == 0)
        {
            return cmd->func;
        }
    }

    return NULL;
}
