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
    const char **argv;
    DumbuggerState *dmbg_state;
    CommandsRegistry *cmdreg;
} program_state;

static void print_help(const char *progname)
{
    printf("Usage: %s PROGRAM [ARGS...]\n", progname);
    printf("Dumbugger, dumb(de)bugger - simple debugger with **very** limited set of real debugger features.\n");
}

static int print_help_cmd(program_state *state, int argc, const char **argv)
{
    printf("help\t\t\t- show this help message\n"
           "regs show\t\t- show registers state\n"
           "regs set REG VALUE\t- set value of register REG to VALUE\n"
           "list [N]\t\t- show next N assembler instructions, 5 by default\n"
           "functions show\t\t- show functions in process \n"
           "continue\t\t- continue execution\n");
    return 0;
}

static int show_regs_cmd(program_state  *state, int argc, const char **argv)
{
    Registers regs;
    if (dmbg_get_regs(state->dmbg_state, &regs) == -1)
    {
        return -1;
    }

    printf("registers:\n"
            "\trdi:\t%llu\n"
            "\trsi:\t%llu\n"
            "\trdx:\t%llu\n",
            regs.rdi, regs.rsi, regs.rdx);

    return 0;
}

static int functions_cmd(program_state *state, int argc, const char **argv)
{
    const char **functions;
    int functions_count;
    if (dmbg_functions_get(state->dmbg_state, &functions, &functions_count) == -1)
    {
        return -1;
    }

    if (functions_count == 0)
    {
        printf("no functions found in process\n");
        dmbg_function_list_free(functions, functions_count);
        return 0;
    }

    printf("functions:\n");
    for (size_t i = 0; i < functions_count; i++)
    {
        printf("\t%s\n", functions[i]);
    }
    printf("\n");

    dmbg_function_list_free(functions, functions_count);
    return 0;
}

static int set_reg_cmd(program_state *state, int argc, const char **argv)
{
    if (argc != 4)
    {
        printf("usage: regs set REG VALUE\n");
        return 0;
    }

    /* Парсим число в соответствии с его основанием */
    long base = 10;
    const char *start_pos = argv[3];
    if (strncmp(start_pos, "0x", sizeof("0x") - 1) == 0 ||
        strncmp(start_pos, "0X", sizeof("0X") - 1) == 0)
    {
        base = 16;
        start_pos += sizeof("0x") - 1;
    }
    else if (strncmp(start_pos, "0b", sizeof("0b") - 1) == 0 || 
            strncmp(start_pos, "0B", sizeof("0B") - 1) == 0)
    {
        base = 2;
        start_pos += sizeof("0b") - 1;
    }
    else if (strncmp(start_pos, "0", sizeof("0") - 1) == 0)
    {
        base = 8;
        start_pos += sizeof("0") - 1;
    }

    long value = strtol(start_pos, NULL, base);
    if (errno != 0)
    {
        printf("error parsing number \"%s\": %s\n", argv[3], strerror(errno));
        return 0;
    }

    /* Обновляем значение регистра */
    Registers regs;
    if (dmbg_get_regs(state->dmbg_state, &regs) == -1)
    {
        return -1;
    }
    
    const char *reg = argv[2];
    if (strcasecmp(reg, "rdi") ==  0)
    {
        regs.rdi = value;
    }
    else if (strcasecmp(reg, "rsi") == 0)
    {
        regs.rsi = value;
    }
    else if (strcasecmp(reg, "rdx") == 0)
    {
        regs.rdx = value;
    }
    else
    {
        printf("register \"%s\" not supported yet, only: rdi, rsi rdx\n", reg);
        return 0;
    }

    if (dmbg_set_regs(state->dmbg_state, &regs) == -1)
    {
        return -1;
    }

    return 0;
}

static int regs_cmd(program_state *state, int argc, const char **argv)
{
    if (argc == 1)
    {
        printf("command for \"regs\" not specified: use \"show\" or \"set\"\n");
        return 0;
    }

    if (strncasecmp(argv[1], "show", sizeof("show") - 1) == 0)
    {
        return show_regs_cmd(state, argc, argv);
    }

    if (strncasecmp(argv[1], "set", sizeof("set") - 1) == 0)
    {
        return set_reg_cmd(state, argc, argv);
    }

    printf("unknown command \"%s\": use \"show\" or \"set\"\n", argv[1]);
    return 0;
}

static int list_assembler_cmd(program_state *state, int argc, const char **argv)
{
    int length;
    if (argc == 1)
    {
        length = 5;
    }
    else if (argc == 2)
    {
        errno = 0;
        length = (int)strtol(argv[1], NULL, 10);
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
        dprintf(STDOUT_FILENO, "%ld\t0x%08lx:\t%s\n", dump.insns[i].addr, dump.insns[i].addr, dump.insns[i].str);
    }
    dprintf(STDOUT_FILENO, "\n");

    if (dumb_assembly_dump_free(&dump) == -1)
    {
        return -1;
    }

    return 0;
}

static int stop_running_process_cmd(program_state *state, int argc, const char **argv)
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

static int set_breakpoint_cmd(program_state *state, int argc, const char **argv)
{
    if (argc != 2)
    {
        printf("breakpoint address not specified\n");
        return 0;
    }

    /* Если в начале 0x, то пропускаем */
    const char *start_addr = argv[1];
    if (strncmp(start_addr, "0x", 2) == 0 || strncmp(start_addr, "0X", 2) == 0)
    {
        start_addr += 2;
    }

    errno = 0;
    long addr = strtol(start_addr, NULL, 16);
    if (errno != 0)
    {
        printf("could not parse address \"%s\": %s\n", argv[1], strerror(errno));
        return 0;
    }

    if (dmbg_set_breakpoint(state->dmbg_state, addr) == -1)
    {
        printf("bp error: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

static int continue_cmd(program_state *state, int argc, const char **argv)
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

#define CMDREG_ADD(name, func)                              \
    if (cmdreg_add(reg, name, (command_func) & func) == -1) \
    {                                                       \
        return NULL;                                        \
    }

    CMDREG_ADD("help", print_help_cmd);
    CMDREG_ADD("regs", regs_cmd);
    CMDREG_ADD("list", list_assembler_cmd);
    CMDREG_ADD("stop", stop_running_process_cmd);
    CMDREG_ADD("continue", continue_cmd);
    CMDREG_ADD("set-breakpoint", set_breakpoint_cmd);
    CMDREG_ADD("functions", functions_cmd);

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
