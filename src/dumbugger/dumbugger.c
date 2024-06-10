#include "config.h"

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>

#include "dis-asm.h"

#include "dumbugger.h"

#define WIFBREAKPOINT(wstatus) (WIFSTOPPED(wstatus) && WSTOPSIG(wstatus) == SIGTRAP)

#define STOPPED_PROCESS_GUARD(state)            \
    if (state->state == PROCESS_STATE_RUNNING)  \
    {                                           \
        errno = EINPROGRESS;                    \
        return -1;                              \
    }                                           \
                                                \
    if (state->state == PROCESS_STATE_FINISHED) \
    {                                           \
        errno = ESRCH;                          \
        return -1;                              \
    }

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
    __attribute__((noreturn)) void
    run_child(const char **args)
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

    DumbuggerState *state = (DumbuggerState *)calloc(sizeof(DumbuggerState), 1);
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
    STOPPED_PROCESS_GUARD(state);

    struct user_regs_struct s;
    if (ptrace(PTRACE_GETREGS, state->pid, NULL, &s) == -1)
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
    STOPPED_PROCESS_GUARD(state);

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

    if (ptrace(PTRACE_SETREGS, state->pid, NULL, &s) == -1)
    {
        return -1;
    }

    return 0;
}

typedef struct dumbugger_assembly_dump_buffer
{
    /* Текущий индекс, который заполняется в dump */
    int insn_index;
    /* Позиция в строке, начиная с которой необходимо записывать строку ассемблера */
    int asm_str_index;
    /* Объект, в который записываем новые ассемблерные инструкции */
    DumbuggerAssemblyDump *dump;
    /* pid отслеживаемого процесса */
    pid_t child_pid;
} dumbugger_assembly_dump_buffer;

static int fprintf_dumbugger_assembly_dump(void *stream, const char *fmt, ...)
{
    int written;
    va_list argp;
    dumbugger_assembly_dump_buffer *buf = (dumbugger_assembly_dump_buffer *)stream;
    if (buf->dump->length <= buf->insn_index)
    {
        return -1;
    }

    va_start(argp, fmt);
    written = snprintf(&buf->dump->as[buf->insn_index][buf->asm_str_index], sizeof(buf->dump->as[buf->insn_index]) - buf->asm_str_index, fmt, argp);
    va_end(argp);

    if (written < 0)
    {
        return -1;
    }
    buf->asm_str_index += written;
    return 0;
}

static int fprintf_styled_dumbugger_assembly_dump(void *stream, enum disassembler_style style, const char *fmt, ...)
{
    if (style == dis_style_text)
    {
        /* 
         * Тут всякие управляющие последовательности и так далее.
         * Они (как минимум у меня) не отображаются и мешают обзору
         */
        return 0;
    }
    
    int res;
    va_list argp;
    va_start(argp, fmt);
    res = fprintf_dumbugger_assembly_dump(stream, fmt);
    va_end(argp);
    return res;
}

static int get_rip_reg(DumbuggerState *state, long *rip)
{
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, state->pid, NULL, &regs) == -1)
    {
        return -1;
    }

    long value = ptrace(PTRACE_PEEKUSER, state->pid, sizeof(long) * REG_RIP, NULL);
    if (value == -1 && errno != 0)
    {
        return -1;
    }

    *rip = value;
    return 0;
}

/* Function used to get bytes to disassemble.  MEMADDR is the
   address of the stuff to be disassembled, MYADDR is the address to
   put the bytes in, and LENGTH is the number of bytes to read.
   INFO is a pointer to this struct.
   Returns an errno value or 0 for success.  */
static int read_tracee_memory_func(bfd_vma memaddr, bfd_byte *myaddr, unsigned int length,
                                   struct disassemble_info *dinfo)
{
    if (length == 0)
    {
        return 0;
    }

    unsigned int left = length;
    
    /* Каждый раз мы читаем машинное слово, поэтому каждый цикл будем загружать  */
    while (0 < left)
    {
        long read = ptrace(PTRACE_PEEKDATA, ((dumbugger_assembly_dump_buffer *)dinfo->stream)->child_pid, (void *)memaddr, NULL);
        if (read == -1 && errno != 0)
        {
            return errno;
        }

        if (left < sizeof(long))
        {
            memcpy(myaddr, &read, left);
            break;
        }

        memcpy(myaddr, &read, sizeof(long));
        myaddr += sizeof(long);
        left -= sizeof(long);
        memaddr += sizeof(long);
    }

    return 0;
}

/*
 * Дизассемблировать length следующих машинных инструкций
 */
int dmbg_disassemble(DumbuggerState *state, int length, DumbuggerAssemblyDump *result)
{
    assert(state != NULL);
    STOPPED_PROCESS_GUARD(state);

    if (length < 0)
    {
        errno = EINVAL;
        return -1;
    }

    if (length == 0)
    {
        memset(result, 0, sizeof(DumbuggerAssemblyDump));
        return 0;
    }

    long rip;
    if (get_rip_reg(state, &rip) == -1)
    {
        return -1;
    }

    dumbugger_assembly_dump_buffer buf = {
        .insn_index = 0,
        .asm_str_index = 0,
        .dump = result,
        .child_pid = state->pid,
    };

    memset(result, 0, sizeof(DumbuggerAssemblyDump));
    size_t asdf = (size_t)length * sizeof(result->as[0]);
    result->as = (char(*)[DMBG_MAX_ASSEMBLY_STR_LEN])malloc((size_t)length * sizeof(result->as[0]));
    if (result->as == NULL)
    {
        return -1;
    }
    result->length = length;

    struct disassemble_info di;
    init_disassemble_info(&di, &buf, (fprintf_ftype)fprintf_dumbugger_assembly_dump, (fprintf_styled_ftype)fprintf_styled_dumbugger_assembly_dump);
    di.arch = bfd_arch_i386;
    di.mach = bfd_mach_x86_64_intel_syntax;
    di.endian = BFD_ENDIAN_LITTLE;
    disassemble_init_for_target(&di);

    di.read_memory_func = read_tracee_memory_func;
    di.buffer = NULL;
    di.buffer_length = 0;
    di.buffer_vma = 0;
    di.disassembler_options = "att-mnemonic";

    disassembler_ftype disasmler = disassembler(di.arch, di.endian == BFD_ENDIAN_BIG, di.mach, NULL);

    int left = length;
    while (0 < left)
    {
        int processed = disasmler((bfd_vma)rip, &di);
        if (processed == -1)
        {
            return -1;
        }
        rip += processed;
        --left;
        ++buf.insn_index;
        buf.asm_str_index = 0;
    }

    return 0;
}

/*
 * Освободить место, выделенное для процесса дизассемблирования
 */
int dumb_assembly_dump_free(DumbuggerAssemblyDump *dump)
{
    if (0 < dump->length)
    {
        free(dump->as);
    }

    memset(dump, 0, sizeof(DumbuggerAssemblyDump));
    return 0;
}