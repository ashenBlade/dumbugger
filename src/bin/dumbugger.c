#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>

#include "dumbugger.h"

#define WIFBREAKPOINT(wstatus) (WIFSTOPPED(wstatus) && WSTOPSIG(wstatus) == SIGTRAP)

typedef enum ProcessState
{
    PROCESS_STATE_RUNNING = 0,
    PROCESS_STATE_STOPPED = 1,
    PROCESS_STATE_FINISHED = 2,
} ProcessState;

struct DumbuggerState
{
    /* pid отлаживаемого процесса */
    pid_t pid;

    /*
     * Текущее состояние процесса
     */
    ProcessState state;

    /*
     * Статус, возвращенный после последнего waitpid.
     * Используется для получения различных состояний процесса.
     */
    int wstatus;
};

static
__attribute__((noreturn)) void run_child(const char **args)
{
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1)
    {
        exit(errno);
    }

    execvp(args[0], (char *const *)args);
    exit(errno);
}

DumbuggerState *
dmbg_run(const char *prog_name, const char **args)
{
    assert(prog_name != NULL);
    assert(args != NULL);

    if (strcmp(prog_name, args[0]) != 0)
    {
        errno = EINVAL;
        return NULL;
    }

    DumbuggerState *state = (DumbuggerState *) calloc(sizeof(DumbuggerState), 1);
    if (state == NULL)
    {
        errno = ENOMEM;
        return NULL;
    }

    pid_t child_pid = fork();
    if (child_pid == -1)
    {
        free(state);
        return NULL;
    }

    if (child_pid == 0)
    {
        run_child(args);
        exit(1);
    }

    state->pid = child_pid;
    state->wstatus = 0;
    state->state = PROCESS_STATE_RUNNING;

    if (waitpid(child_pid, &state->wstatus, 0) != child_pid)
    {
        kill(child_pid, SIGKILL);
        free(state);
        return NULL;
    }

    if (WIFEXITED(state->wstatus))
    {
        /* 
         * Первая остановка происходит при запуске execvp.
         * Но если это не так и процесс завершился заранее, то код возврата - код ошибки
         */
        errno = WEXITSTATUS(state->wstatus);
        free(state);
        return NULL;
    }

    /* 
     * Работу не продолжаю, чтобы клиент мог 
     * поставить точки останова, просмотреть другую информацию и т.д.
     */
    state->state = PROCESS_STATE_STOPPED;

    return state;
}

int dmbg_stop(DumbuggerState *state)
{
    bool is_running = false;
    switch (state->state)
    {
    case PROCESS_STATE_FINISHED:
        return 0;
    case PROCESS_STATE_RUNNING:
    case PROCESS_STATE_STOPPED:
        break;
    default:
        assert(false);
        break;
    }

    if (kill(state->pid, SIGKILL) == -1)
    {
        return -1;
    }

    int wstatus;
    if (waitpid(state->pid, &wstatus, 0) != state->pid)
    {
        return -1;
    }

    if (!WIFEXITED(wstatus))
    {
        /* Не удалось остановить, хотя SIGKILL невозможно перехватить */
        return -1;
    }

    state->state = PROCESS_STATE_FINISHED;
    state->wstatus = wstatus;
    return 0;
}

int dmbg_free(DumbuggerState *state)
{
    if (state->state != PROCESS_STATE_FINISHED)
    {
        errno = EINPROGRESS;
        return -1;
    }

    memset(state, 0, sizeof(DumbuggerState));
    free(state);
    return 0;
}

int dmbg_stop_reason(DumbuggerState *state, DmbgStopReason *reason)
{
    if (state->state == PROCESS_STATE_FINISHED || WIFEXITED(state->wstatus))
    {
        *reason = DMBG_STOP_EXITED;
    }
    else
    {
        *reason = DMBG_STOP_BP;
    }

    return 0;
}

int dmbg_wait(DumbuggerState *state)
{
    if (state->state != PROCESS_STATE_RUNNING)
    {
        return 0;
    }

    /* 
     * Процесс может быть остановлен по различным причинам. 
     * В частности, его останавливает каждый сигнал, поэтому нам 
     * необходимо проверять, что сигнал остановки вызван точкой останова
     */
    while (true)
    {
        if (waitpid(state->pid, &state->wstatus, 0) != state->pid)
        {
            return -1;
        }

        if (WIFEXITED(state->wstatus))
        {
            state->state = PROCESS_STATE_FINISHED;
        }
        else if (WIFBREAKPOINT(state->wstatus))
        {
            state->state = PROCESS_STATE_STOPPED;
        }
        else 
        {
            if (ptrace(PTRACE_CONT, state->pid, NULL, NULL) == -1)
            {
                return -1;
            }

            continue;
        }

        break;
    }

    return 0;
}

int dmbg_continue(DumbuggerState *state)
{
    assert(state != NULL);
    if (state->state == PROCESS_STATE_RUNNING)
    {
        return 0;
    }

    if (state->state == PROCESS_STATE_FINISHED)
    {
        errno = ESRCH;
        return -1;
    }

    struct user_regs_struct s;

    if (ptrace(PTRACE_CONT, state->pid, NULL, NULL) == -1)
    {
        return -1;
    }

    state->state = PROCESS_STATE_RUNNING;

    return 0;
}

int dmbg_get_regs(DumbuggerState *state, Registers *regs)
{
    assert(state != NULL);
    if (state->state == PROCESS_STATE_RUNNING)
    {
        errno = EINPROGRESS;
        return -1;
    }

    if (state->state == PROCESS_STATE_FINISHED)
    {
        errno = ESRCH;
        return -1;
    }

    struct user_regs_struct s;
    if (ptrace(PTRACE_GETREGS, state->pid, NULL, &s)  ==  -1)
    {
        return -1;
    }

    regs->r8 = s.r8; 
    regs->r9 = s.r9; 
    regs->r10 = s.r10; 
    regs->r11 = s.r11;
    regs->r12 = s.r12;
    regs->r13 = s.r13;
    regs->r14 = s.r14;
    regs->r15 = s.r15;
    regs->rax = s.rax;
    regs->rbp = s.rbp;
    regs->rdi = s.rdi;
    regs->rsi = s.rsi;
    regs->rdx = s.rdx;
    regs->rcx = s.rcx;
    regs->rbx = s.rbx;
    regs->rip = s.rip;
    regs->rsp = s.rsp;

    return 0;
}

int dmbg_set_regs(DumbuggerState *state, Registers *regs)
{
    assert(state != NULL);
    if (state->state == PROCESS_STATE_RUNNING)
    {
        errno = EINPROGRESS;
        return -1;
    }

    if (state->state == PROCESS_STATE_FINISHED)
    {
        errno = ESRCH;
        return -1;
    }

    struct user_regs_struct s;
    if (ptrace(PTRACE_GETREGS, state->pid, NULL, &s) == -1)
    {
        return -1;
    }

    s.r8 = regs->r8;
    s.r9 = regs->r9;
    s.r10 = regs->r10;
    s.r11 = regs->r11;
    s.r12 = regs->r12;
    s.r13 = regs->r13;
    s.r14 = regs->r14;
    s.r15 = regs->r15;
    s.rax = regs->rax;
    s.rbp = regs->rbp;
    s.rdi = regs->rdi;
    s.rsi = regs->rsi;
    s.rdx = regs->rdx;
    s.rcx = regs->rcx;
    s.rbx = regs->rbx;
    s.rip = regs->rip;
    s.rsp = regs->rsp;

    if (ptrace(PTRACE_SETREGS, state->pid, NULL, &s)  ==  -1)
    {
        return -1;
    }

    return 0;
}