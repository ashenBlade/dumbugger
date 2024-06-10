#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "dumbugger.h"

static void print_help(int argc, const char **argv)
{
    printf("Usage: %s PROGRAM [ARGS...]\n", argv[0]);
    printf("Dumbugger, dumb(de)bugger - simple debugger with **very** limited set of real debugger features.\n");
}

int main(int argc, const char **argv)
{
    if (argc == 1)
    {
        print_help(argc, argv);
        return 1;
    }

    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)
    {
        print_help(argc, argv);
        return 0;
    }

    DumbuggerState *state;

    state = dmbg_run(argv[1], argv + 1);
    if (state == NULL)
    {
        printf("failed to start debugger: %s\n", strerror(errno));
        return 1;
    }

    while (1)
    {
        if (dmbg_wait(state) == -1)
        {
            perror("dmbg_wait");
            return 1;
        }

        DmbgStopReason reason;
        if (dmbg_stop_reason(state, &reason) == -1)
        {
            perror("dmbg_stop_reason");
            return 1;
        }

        if (reason == DMBG_STOP_EXITED)
        {
            printf("program exited normally\n");
            break;
        }

        printf("program stopped at breakpoint\n");
        Registers regs;
        if (dmbg_get_regs(state, &regs) == -1)
        {
            perror("dmbg_get_regs");
            return 1;
        }

        printf("registers:\n"
               "\trdi:\t%llu\n"
               "\trsi:\t%llu\n"
               "\trdx:\t%llu\n"
               "\n",
               regs.rdi, regs.rsi, regs.rdx);

        DumbuggerAssemblyDump dump;
        if (dmbg_disassemble(state, 5, &dump) == -1)
        {
            perror("dmbg_disassemble");
            return -1;
        }

        printf("assembler:\n");
        for (int i = 0; i < dump.length; i++)
        {
            printf("\t%s\n", dump.as[i]);
        }
        printf("\n");

        if (dumb_assembly_dump_free(&dump) == -1)
        {
            perror("dumb_assembly_dump_free");
            return -1;
        }

        if (regs.rdx == 3)
        {
            regs.rdx = 0;
            if (dmbg_set_regs(state, &regs) == -1)
            {
                perror("dmbg_set_regs");
                return -1;
            }
        }

        if (dmbg_continue(state) == -1)
        {
            perror("dmbg_continue");
            return 1;
        }
    }

    if (dmbg_stop(state) == -1)
    {
        perror("dmbg_stop");
        return 1;
    }

    return 0;
}
