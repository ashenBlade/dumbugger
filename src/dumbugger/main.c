#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdlib.h>
#include <assert.h>

#include "dumbugger.h"
#include "commands.h"
#include "utils.h"

#define DMBG_USER_PROMPT "(dmbg) "

typedef struct program_state
{
    int argc;
    const char** argv;
    DumbuggerState *dmbg_state;
    CommandsRegistry *cmdreg;
} program_state;

static void print_help(const char *progname)
{
    printf("Usage: %s PROGRAM [ARGS...]\n", progname);
    printf("Dumbugger, dumb(de)bugger - simple debugger with **very** limited set of real debugger features.\n");
}

static int print_help_cmd(program_state *state, int argc, const char** argv)
{
    printf("help\t- show this help message\n"
           "regs\t- show registers state\n"
           "list [N]\t- show next N assembler instructions, 5 by default\n"
           "continue\t- continue execution\n");
}

static int show_regs_cmd(program_state* state, int argc, const char** argv)
{
    Registers regs;
    if (dmbg_get_regs(state->dmbg_state, &regs) == -1)
    {
        return -1;
    }

    if (argc == 1)
    {
        printf("registers:\n"
               "\trdi:\t%llu\n"
               "\trsi:\t%llu\n"
               "\trdx:\t%llu\n",
              regs.rdi, regs.rsi, regs.rdx);
        return 0;
    }

    /* FIXME: пока не знаю надо ли отдельный регистр показывать */
    printf("registers:\n"
           "\trdi:\t%llu\n"
           "\trsi:\t%llu\n"
           "\trdx:\t%llu\n",
           regs.rdi, regs.rsi, regs.rdx);

    return 0;
}

static int list_assembler_cmd(program_state* state, int argc, const char** argv)
{
    int length;
    if (argc == 1)
    {
        length = 5;
    }
    else if (argc == 2)
    {
        errno = 0;
        length = (int) strtol(argv[1], NULL, 10);
        if (errno != 0)
        {
            printf("could not parse number \"%s\": %s\n", argv[1], strerror(errno));
            return 0;
        }
    }
    else
    {
        printf("provide only number\n");
        return 0;
    }

    if (length < 1)
    {
        printf("number of lines must be positive\n");
        return 0;
    }

    DumbuggerAssemblyDump dump;
    if (dmbg_disassemble(state->dmbg_state, length, &dump) == -1)
    {
        return -1;
    }

    dprintf(STDOUT_FILENO, "\n");
    for (int i = 0; i < dump.length; i++)
    {
        dprintf(STDOUT_FILENO, "0x%08lx:\t%s\n", dump.insns[i].addr, dump.insns[i].str);
    }
    dprintf(STDOUT_FILENO, "\n");

    if (dumb_assembly_dump_free(&dump) == -1)
    {
        return -1;
    }

    return 0;
}

static int stop_running_process_cmd(program_state* state, int argc, const char** argv)
{
    do 
    {
        if (write(STDOUT_FILENO, "stop runnning process? y\\n: ", sizeof("stop runnning process? y\\n")) == -1)
        {
            return -1;
        }

        char confirm;
        if (read(STDIN_FILENO, &confirm, sizeof(confirm)) == -1)
        {
            return -1;
        }

        if (confirm == 'n' || confirm == 'N')
        {
            return 0;
        }

        if (confirm == 'y' || confirm == 'Y')
        {
            break;
        }
    } while (true);

    if (dmbg_stop(state->dmbg_state) == -1)
    {
        return -1;
    }
    
    return 0;
}

static int continue_cmd(program_state* state, int argc, const char** argv)
{
    if (dmbg_continue(state->dmbg_state) == -1)
    {
        return -1;
    }

    return 1;
}

static CommandsRegistry *build_commands_registry()
{
    CommandsRegistry *reg = cmdreg_new();
    if (reg == NULL)
    {
        return NULL;
    }

#define CMDREG_ADD(name, func) if (cmdreg_add(reg, name, (command_func) &func) == -1) { return NULL; }

    CMDREG_ADD("help", print_help_cmd);
    CMDREG_ADD("regs", show_regs_cmd);
    CMDREG_ADD("list", list_assembler_cmd);
    CMDREG_ADD("stop", stop_running_process_cmd);
    CMDREG_ADD("continue", continue_cmd);
    
    return reg;
}

static int process_user_input(program_state *state)
{
    char buf[1024];
    int input_len;

    while (true)
    {
        /* Читаем команду пользователя - чистая строка */
        if (write(STDOUT_FILENO, DMBG_USER_PROMPT, sizeof(DMBG_USER_PROMPT)) == -1)
        {
            return 1;
        }

        do
        {
            memset(buf, '\0', sizeof(buf));
            input_len = read(STDIN_FILENO, buf, sizeof(buf));
            if (input_len == -1)
            {
                if (errno == EINTR)
                {
                    continue;
                }

                return -1;
            }

            break;
        } while (1);

        if (input_len == 0)
        {
            errno = EBADFD;
            return -1;
        }

        /* Разделяем строку на отдельные слова */
        char **argv;
        int argc;
        if (split_str(input_len, buf, &argc, &argv) == -1)
        {
            return -1;
        }

        assert(0 <= argc);
        if (argc == 0)
        {
            continue;
        }

        /* Находим команду по первому слову */
        command_func cmd = cmdreg_find(state->cmdreg, argv[0]);
        if (cmd == NULL)
        {
            printf("unknown command: %s\n", argv[0]);
            continue;
        }

        int result = cmd((void *)state, argc, argv);
        /* 
         * -1 - ошибка
         *  1 - следует завершить обработку команд (работа продолжилась, single step и т.д.)
         *  0 - продолжаем обрабатывать команды пользователя
         */
        if (result == -1)
        {
            return -1;
        }

        if (result == 1)
        {
            break;
        }

        assert(result == 0);
    }

    return 1;
}

int main(int argc, const char **argv)
{
    if (argc == 1)
    {
        print_help(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)
    {
        print_help(argv[0]);
        return 0;
    }


    DumbuggerState *dmbg;
    CommandsRegistry *reg;

    if ((reg = build_commands_registry()) == NULL)
    {
        printf("failed to register commands: %s\n", strerror(errno));
        return 1;
    }


    if ((dmbg = dmbg_run(argv[1], argv + 1)) == NULL)
    {
        printf("failed to start debugger: %s\n", strerror(errno));
        return 1;
    }

    program_state prog_state = {
        .argc = argc,
        .argv = argv,
        .dmbg_state = dmbg,
        .cmdreg = reg,
    };

    while (true)
    {
        if (dmbg_wait(dmbg) == -1)
        {
            perror("dmbg_wait");
            return 1;
        }

        DmbgStopReason reason;
        if (dmbg_stop_reason(dmbg, &reason) == -1)
        {
            perror("dmbg_stop_reason");
            return 1;
        }

        if (reason == DMBG_STOP_EXITED)
        {
            printf("program finished execution\n");
            break;
        }

        if (process_user_input(&prog_state) == -1)
        {
            printf("error processing command: %s\n", strerror(errno));
            return 1;
        }
    }

    if (dmbg_stop(dmbg) == -1)
    {
        perror("dmbg_stop");
        return 1;
    }

    if (dmbg_free(dmbg) == -1)
    {
        perror("dmbg_free");
        return 1;
    }

    return 0;
}
