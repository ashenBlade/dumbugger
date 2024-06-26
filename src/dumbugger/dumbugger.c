#include "config.h"
#include "dumbugger.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <libdwarf-0/dwarf.h>
#include <libdwarf-0/libdwarf.h>
#include <linux/limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>

#include "debug_syms.h"
#include "dis-asm.h"
#include "list.h"

#define WIFBREAKPOINT(wstatus) \
    (WIFSTOPPED(wstatus) && WSTOPSIG(wstatus) == SIGTRAP)

#define STOPPED_PROCESS_GUARD(state)              \
    if (state->state == PROCESS_STATE_RUNNING) {  \
        errno = EINPROGRESS;                      \
        return -1;                                \
    }                                             \
                                                  \
    if (state->state == PROCESS_STATE_FINISHED) { \
        errno = ESRCH;                            \
        return -1;                                \
    }

typedef enum process_state {
    PROCESS_STATE_RUNNING = 0,
    PROCESS_STATE_STOPPED = 1,
    PROCESS_STATE_FINISHED = 2,
} process_state;

typedef struct breakpoint_info {
    /* Адрес точки останова */
    long address;
    /*
     * Сохраненный по этому адресу байт.
     * Использовать надо только байт, а не весь long
     */
    long saved_text;
} breakpoint_info;

LIST_DEFINE(breakpoint_info, bp_list)

struct DumbuggerState {
    /*
     * pid отлаживаемого процесса
     */
    pid_t pid;

    /*
     * Путь до выполняемого процесса
     */
    char *exe_path;

    /*
     * Адрес, по которому загружен выполняемый файл в адресное пространство
     */
    long load_addr;

    /*
     * Текущее состояние процесса
     */
    process_state state;

    /*
     * Статус, возвращенный после последнего waitpid.
     * Используется для получения различных состояний процесса.
     */
    int wstatus;

    /*
     * Массив точек останова
     */
    bp_list breakpoints;

    /*
     * Отладочная информация процесса
     */
    DebugInfo debug_info;
};

static void run_child(const char **args) {
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
        exit(errno);
    }

    execvp(args[0], (char *const *) args);
    exit(errno);
}

static int get_rip(DumbuggerState *state, long *rip) {
    long value =
        ptrace(PTRACE_PEEKUSER, state->pid, sizeof(long) * REG_RIP, NULL);
    if (value == -1 && errno != 0) {
        return -1;
    }

    *rip = value;
    return 0;
}

static int set_rip(DumbuggerState *state, long rip) {
    return ptrace(PTRACE_POKEUSER, state->pid, sizeof(long) * REG_RIP, rip);
}

static int peek_text(DumbuggerState *state, long addr, long *text) {
    errno = 0;
    long data = ptrace(PTRACE_PEEKTEXT, state->pid, addr, NULL);
    if (data == -1 && errno != 0) {
        return -1;
    }
    *text = data;
    return 0;
}

static int poke_text(DumbuggerState *state, long addr, long text) {
    return ptrace(PTRACE_POKETEXT, state->pid, addr, text);
}

static int get_load_addr(pid_t pid, const char *exe_name, long *load_addr) {
    long start, end;
    long offset;
    int major, minor;
    long inode;
    char filepath[PATH_MAX + 1];

    int res;
    char maps_path[32];
    FILE *maps_file;

    /*
     * Для нахождения адреса загрузки парсим /proc/id/maps файл.
     * Находим первое упоминание exe_name в этом файле и возвращаем первый его
     * адрес. Обычно, нужный адрес самый первый, но лучше пройдем по всем
     * строкам и найдем нужный.
     */
    res = snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", (int) pid);
    if (res == -1) {
        return -1;
    }

    maps_file = fopen(maps_path, "r");
    if (maps_file == NULL) {
        return -1;
    }

    while (fscanf(maps_file, "%lx-%*x %*c%*c%*c%*c %*d %*d:%*d %*d%*c %s",
                  &start, filepath) == 2) {
        if (strcmp(filepath, exe_name) != 0) {
            continue;
        }

        *load_addr = start;
        if (fclose(maps_file) == EOF) {
            return -1;
        }

        return 0;
    }

    if (fclose(maps_file) == EOF) {
        return -1;
    }

    return 1;
}

static int get_exe_path(pid_t pid, char *exe_path, int exe_path_len) {
    int len;
    char link_path[32];

    memset(link_path, 0, sizeof(link_path));
    len = snprintf(link_path, sizeof(link_path), "/proc/%d/exe", (int) pid);
    if (len == -1) {
        return -1;
    }

    if ((len = readlink(link_path, exe_path, exe_path_len)) == -1) {
        return -1;
    }
    exe_path[len + 1] = '\0';

    return 0;
}

static int fill_debug_info(DumbuggerState *state, pid_t child_pid) {
    char exe_path[PATH_MAX];
    long load_addr;

    /*
     * Получаем полный путь до исполняемого файла
     */
    if (get_exe_path(child_pid, exe_path, sizeof(exe_path)) == -1) {
        return -1;
    }

    /*
     * Находим загрузочный адрес
     */
    switch (get_load_addr(child_pid, exe_path, &load_addr)) {
        case 1:
            errno = EIO;
        case -1:
            return -1;
        default:
            break;
    }

    /*
     * Инициализируем отладочную информацию
     */
    if (debug_syms_get(exe_path, &state->debug_info) == -1) {
        return -1;
    }

    state->exe_path = strdup(exe_path);
    state->load_addr = load_addr;

    if (state->exe_path == NULL) {
        return -1;
    }

    return 0;
}

DumbuggerState *dmbg_run(const char *prog_name, const char **args) {
    assert(prog_name != NULL);
    assert(args != NULL);

    if (strcmp(prog_name, args[0]) != 0) {
        errno = EINVAL;
        return NULL;
    }

    DumbuggerState *state =
        (DumbuggerState *) calloc(1, sizeof(DumbuggerState));
    if (state == NULL) {
        errno = ENOMEM;
        return NULL;
    }

    /* Сразу выставим все поля в 0 */
    memset(state, 0, sizeof(DumbuggerState));

    pid_t child_pid = fork();
    if (child_pid == -1) {
        free(state);
        return NULL;
    }

    if (child_pid == 0) {
        run_child(args);
        exit(EXIT_FAILURE);
    }

    state->pid = child_pid;
    state->wstatus = 0;

    if (waitpid(child_pid, &state->wstatus, 0) != child_pid) {
        kill(child_pid, SIGKILL);
        free(state);
        return NULL;
    }

    if (WIFEXITED(state->wstatus)) {
        /*
         * Первая остановка происходит при запуске execvp.
         * Но если это не так и процесс завершился заранее, то код возврата -
         * код ошибки
         */
        errno = WEXITSTATUS(state->wstatus);
        free(state);
        return NULL;
    }

    /* Получаем отладочную информацию */
    if (fill_debug_info(state, child_pid) == -1) {
        kill(child_pid, SIGKILL);
        (void) waitpid(child_pid, NULL, 0);
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

int dmbg_stop(DumbuggerState *state) {
    bool is_running = false;
    switch (state->state) {
        case PROCESS_STATE_FINISHED:
            return 0;
        case PROCESS_STATE_RUNNING:
        case PROCESS_STATE_STOPPED:
            break;
        default:
            assert(false);
            break;
    }

    if (kill(state->pid, SIGKILL) == -1) {
        return -1;
    }

    int wstatus;
    if (waitpid(state->pid, &wstatus, 0) != state->pid) {
        return -1;
    }

    if (!WIFEXITED(wstatus)) {
        /* Не удалось остановить, хотя SIGKILL невозможно перехватить */
        return -1;
    }

    state->state = PROCESS_STATE_FINISHED;
    state->wstatus = wstatus;
    return 0;
}

int dmbg_free(DumbuggerState *state) {
    if (state->state != PROCESS_STATE_FINISHED) {
        errno = EINPROGRESS;
        return -1;
    }

    memset(state, 0, sizeof(DumbuggerState));
    free(state);
    return 0;
}

int dmbg_stop_reason(DumbuggerState *state, DmbgStopReason *reason) {
    if (state->state == PROCESS_STATE_FINISHED || WIFEXITED(state->wstatus)) {
        *reason = DMBG_STOP_EXITED;
    } else {
        *reason = DMBG_STOP_BP;
    }

    return 0;
}

static int breakpoint_equals_address_predicate(void *context,
                                               breakpoint_info *info) {
    long address = (long) context;
    return info->address == address;
}

/*
 * Восстановить секцию кода, после того, как произошла остановка при полученном
 * SIGTRAP. Возвращаемые значения:
 *
 * -1 - ошибка
 *  0 - точка останова не найдена (возможно это пользовательская точка)
 *  1 - успешно восстановлено
 */
static int restore_after_breakpoint(DumbuggerState *state) {
    /*
     * Мы уже выполнили int 0x3, но точка останова была на _начале_ инструкции,
     * а не после - надо откатиться
     */
    long rip;
    if (get_rip(state, &rip) == -1) {
        return -1;
    }
    --rip;

    breakpoint_info *info;
    if (!bp_list_contains(&state->breakpoints,
                          breakpoint_equals_address_predicate, (void *) rip,
                          &info)) {
        printf("not exists\n");
        return 0;
    }

    assert(info->address == rip);
    if (set_rip(state, rip) == -1) {
        return -1;
    }

    long data;
    if (peek_text(state, rip, &data) == -1) {
        return -1;
    }

    if ((data & ((long) 0xFF)) != ((long) 0xCC)) {
        printf("not equal\n");
    }

    data = (data & ((long) ~0xFF)) | (info->saved_text & ((long) 0xFF));

    if (poke_text(state, rip, data) == -1) {
        return -1;
    }

    return 1;
}

/*
 * Обработать остановку отслеживаемого процесса - проверить достижение точек
 * останова
 *
 * Возвращаемые значения:
 * -1 - ошибка
 *  0 - точка останова не найдена
 *  1 - точка останова успешно обработана
 */
static int handle_child_stopped(DumbuggerState *state) {
    siginfo_t si;
    if (ptrace(PTRACE_GETSIGINFO, state->pid, NULL, &si) == -1) {
        return -1;
    }

    if (si.si_signo != SIGTRAP) {
        return 0;
    }

    if (si.si_code == SI_KERNEL || si.si_code == TRAP_BRKPT) {
        return restore_after_breakpoint(state);
    }

    /*
     * Другой вариант - TRAP_TRACE, когда SINGLESTEP.
     * От него восстанавливаться не надо.
     * Случаи отличные от выше перечисленных не рассматриваю для простоты.
     */
    if (si.si_code == TRAP_TRACE) {
        /*
         * В случае SINGLESTEP возвращаем 1,
         * чтобы выполнение процесса не продолжалось
         */
        return 1;
    }

    return 0;
}

int dmbg_wait(DumbuggerState *state) {
    if (state->state != PROCESS_STATE_RUNNING) {
        return 0;
    }

    /*
     * Процесс может быть остановлен по различным причинам.
     * В частности, его останавливает каждый сигнал, поэтому нам
     * необходимо проверять, что сигнал остановки вызван точкой останова
     */
    while (true) {
        if (waitpid(state->pid, &state->wstatus, 0) != state->pid) {
            return -1;
        }

        if (WIFEXITED(state->wstatus) || WIFSIGNALED(state->wstatus)) {
            state->state = PROCESS_STATE_FINISHED;
            return 0;
        }

        switch (handle_child_stopped(state)) {
            case -1 /* ошибка */:
                return -1;
            case 0 /* ложное срабатывание */:
                break;
            case 1 /* точка останова */:
                state->state = PROCESS_STATE_STOPPED;
                return 0;
            default:
                assert(false);
        }

        if (ptrace(PTRACE_CONT, state->pid, NULL, NULL) == -1) {
            return -1;
        }
    }

    /* Не должны сюда попасть */
    assert(false);
    return -1;
}

int dmbg_continue(DumbuggerState *state) {
    assert(state != NULL);
    if (state->state == PROCESS_STATE_RUNNING) {
        return 0;
    }

    if (state->state == PROCESS_STATE_FINISHED) {
        errno = ESRCH;
        return -1;
    }

    if (ptrace(PTRACE_CONT, state->pid, NULL, NULL) == -1) {
        return -1;
    }

    state->state = PROCESS_STATE_RUNNING;

    return 0;
}

int dmbg_single_step_i(DumbuggerState *state) {
    STOPPED_PROCESS_GUARD(state);

    if (ptrace(PTRACE_SINGLESTEP, state->pid, NULL, NULL) == -1) {
        return -1;
    }

    if (waitpid(state->pid, &state->wstatus, 0) != state->pid) {
        return -1;
    }

    if (WIFEXITED(state->wstatus) || WIFSIGNALED(state->wstatus)) {
        state->state = PROCESS_STATE_FINISHED;
        return 0;
    }

    /*
     * В данном случае не важно - точка останова или трейс.
     * Мы останавливаемся в любом случае.
     */
    if (handle_child_stopped(state) == -1) {
        return -1;
    }

    state->state = PROCESS_STATE_STOPPED;
    return 0;
}

int dmbg_get_regs(DumbuggerState *state, Registers *regs) {
    assert(state != NULL);
    STOPPED_PROCESS_GUARD(state);

    struct user_regs_struct s;
    if (ptrace(PTRACE_GETREGS, state->pid, NULL, &s) == -1) {
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

int dmbg_set_regs(DumbuggerState *state, Registers *regs) {
    assert(state != NULL);
    STOPPED_PROCESS_GUARD(state);

    struct user_regs_struct s;
    if (ptrace(PTRACE_GETREGS, state->pid, NULL, &s) == -1) {
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

    if (ptrace(PTRACE_SETREGS, state->pid, NULL, &s) == -1) {
        return -1;
    }

    return 0;
}

typedef struct dumbugger_assembly_dump_buffer {
    /* Текущий индекс, который заполняется в dump */
    int insn_index;
    /*
     * Позиция в строке, начиная с которой необходимо записывать строку
     * ассемблера
     */
    int asm_str_index;
    /* Объект, в который записываем новые ассемблерные инструкции */
    DumbuggerAssemblyDump *dump;
    /* pid отслеживаемого процесса */
    pid_t child_pid;
    /*
     * Служебное поле для отслеживания обработки dis_style_address_offset.
     * С ним проблемы, см. fprintf_styled
     */
    bool in_addr_offset_process_state;
} dumbugger_assembly_dump_buffer;

static int fprintf_dumbugger_assembly_dump(void *stream, const char *fmt, ...) {
    int written;
    va_list argp;
    dumbugger_assembly_dump_buffer *buf =
        (dumbugger_assembly_dump_buffer *) stream;

    if (buf->dump->length <= buf->insn_index) {
        return -1;
    }

    if (buf->asm_str_index < sizeof(buf->dump->insns[buf->insn_index].str)) {
        va_start(argp, fmt);
        written = snprintf(
            &buf->dump->insns[buf->insn_index].str[buf->asm_str_index],
            sizeof(buf->dump->insns[buf->insn_index].str) - buf->asm_str_index,
            fmt, argp);
        va_end(argp);

        if (written < 0) {
            return -1;
        }
        buf->asm_str_index += written;
    }

    return 0;
}

static int write_cleanup_escape(char *buf, int buf_len, const char *fmt,
                                va_list argp) {
    /*
     * libopcodes добавляет в результирующую строку управляющие символы
     * в формате
     * \002X\002, где X - любой символ.
     * Это добавляет в вывод лишние символы и мешают. Поэтому удаляем эти
     * последовательности. Как по другому их убрать - не знаю.
     */

    int written;

    written = snprintf(buf, buf_len, fmt, argp);

    if (written < 0) {
        return -1;
    }

    int cur = 0;
    while (cur < written) {
        /*
         * Тупой способ - находим первый '\' и удаляем 7 следующих символов
         * включительно
         */
        if (buf[cur] != '\002') {
            ++cur;
            continue;
        }

        int to_move = written - cur - 3;
        if (to_move <= 0) {
            memset(buf + cur, 0, written - cur);
            written -= written - cur;
            break;
        }

        memmove(buf + cur, buf + cur + 3, to_move);
        written -= 3;
    }
    buf[written] = '\0';
    if (written == 1 && buf[0] == ')') {
        /* Встречалась единственная закрывающая скобка - она не нужна */
        return 0;
    }
    return written;
}

static int fprintf_styled_dumbugger_assembly_dump(void *stream,
                                                  enum disassembler_style style,
                                                  const char *fmt, ...) {
    int res;
    int written;
    int current_length;
    int left_space;
    char temp_buf[64];
    va_list argp;
    dumbugger_assembly_dump_buffer *buf;

    // if (style != dis_style_text || style != dis_style_mnemonic) {
    /*
     * Печатаем только необходимые символы
     */
    // return 0;
    // }

    buf = (dumbugger_assembly_dump_buffer *) stream;

    if (buf->in_addr_offset_process_state) {
        if (style == dis_style_register) {
            buf->in_addr_offset_process_state = false;
        }

        return 0;
    } else if (style == dis_style_address_offset) {
        buf->in_addr_offset_process_state = true;
    }

    if (!(style == dis_style_mnemonic || style == dis_style_text)) {
        return 0;
    }

    if (buf->dump->length <= buf->insn_index) {
        return -1;
    }

    memset(temp_buf, 0, sizeof(temp_buf));
    va_start(argp, fmt);
    written = write_cleanup_escape(temp_buf, sizeof(temp_buf), fmt, argp);
    va_end(argp);

    if (written == -1) {
        return -1;
    }

    /* Если вернул 0, то оставшееся значение надо выбросить */
    if (written == 0) {
        return 0;
    }

    current_length = buf->asm_str_index;
    left_space = sizeof(buf->dump->insns[buf->insn_index].str) - current_length;
    if (left_space <= 0) {
        return 0;
    }

    if (left_space < written) {
        written = left_space;
    }

    strncpy(&buf->dump->insns[buf->insn_index].str[current_length], temp_buf,
            written);

    buf->asm_str_index += written;
    return 0;
}

/* Function used to get bytes to disassemble.  MEMADDR is the
   address of the stuff to be disassembled, MYADDR is the address to
   put the bytes in, and LENGTH is the number of bytes to read.
   INFO is a pointer to this struct.
   Returns an errno value or 0 for success.  */
static int read_tracee_memory_func(bfd_vma memaddr, bfd_byte *myaddr,
                                   unsigned int length,
                                   struct disassemble_info *dinfo) {
    if (length == 0) {
        return 0;
    }

    unsigned int left = length;

    /* Каждый раз мы читаем машинное слово, поэтому каждый цикл будем загружать
     */
    while (0 < left) {
        long read = ptrace(
            PTRACE_PEEKDATA,
            ((dumbugger_assembly_dump_buffer *) dinfo->stream)->child_pid,
            (void *) memaddr, NULL);
        if (read == -1 && errno != 0) {
            return errno;
        }

        if (left < sizeof(long)) {
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
int dmbg_disassemble(DumbuggerState *state, int length,
                     DumbuggerAssemblyDump *result) {
    assert(state != NULL);
    STOPPED_PROCESS_GUARD(state);

    if (length < 0) {
        errno = EINVAL;
        return -1;
    }

    if (length == 0) {
        memset(result, 0, sizeof(DumbuggerAssemblyDump));
        return 0;
    }

    long rip;
    if (get_rip(state, &rip) == -1) {
        return -1;
    }

    dumbugger_assembly_dump_buffer buf = {
        .insn_index = 0,
        .asm_str_index = 0,
        .dump = result,
        .child_pid = state->pid,
    };

    memset(result, 0, sizeof(DumbuggerAssemblyDump));
    result->insns = malloc((size_t) length * sizeof(result->insns[0]));
    if (result->insns == NULL) {
        return -1;
    }
    result->length = length;

    struct disassemble_info di;
    init_disassemble_info(
        &di, &buf, (fprintf_ftype) fprintf_dumbugger_assembly_dump,
        (fprintf_styled_ftype) fprintf_styled_dumbugger_assembly_dump);
    di.arch = bfd_arch_i386;
    di.mach = bfd_mach_x86_64;
    di.endian = BFD_ENDIAN_LITTLE;

    di.disassembler_options = "att-mnemonic,att";
    disassemble_init_for_target(&di);

    di.read_memory_func = read_tracee_memory_func;
    di.buffer = NULL;
    di.buffer_length = 0;
    di.buffer_vma = 0;

    disassembler_ftype disasmler =
        disassembler(di.arch, di.endian == BFD_ENDIAN_BIG, di.mach, NULL);

    while (buf.insn_index < length) {
        int processed = disasmler((bfd_vma) rip, &di);
        if (processed == -1) {
            return -1;
        }
        buf.dump->insns[buf.insn_index].addr = rip;
        buf.dump->insns[buf.insn_index].str[buf.asm_str_index] = '\0';
        rip += processed;
        ++buf.insn_index;
        buf.asm_str_index = 0;
    }

    return 0;
}

/*
 * Освободить место, выделенное для процесса дизассемблирования
 */
int dumb_assembly_dump_free(DumbuggerAssemblyDump *dump) {
    if (0 < dump->length) {
        free(dump->insns);
    }

    memset(dump, 0, sizeof(DumbuggerAssemblyDump));
    return 0;
}

static int dumbugger_state_add_breakpoint(DumbuggerState *state,
                                          breakpoint_info *info) {
    return bp_list_add(&state->breakpoints, info);
}

static int set_breakpoint_at_addr(DumbuggerState *state, long addr) {
    assert(state->state == PROCESS_STATE_STOPPED);

    long text;
    if (peek_text(state, addr, &text) == -1) {
        return -1;
    }

    breakpoint_info bi = {
        .address = addr,
        .saved_text = text,
    };

    long new_text = (text & ~0xFF) | ((long) 0xCC);
    if (poke_text(state, addr, new_text) == -1) {
        return -1;
    }

    if (dumbugger_state_add_breakpoint(state, &bi) == -1) {
        return -1;
    }

    return 0;
}

int dmbg_set_breakpoint_addr(DumbuggerState *state, long addr) {
    STOPPED_PROCESS_GUARD(state);

    return set_breakpoint_at_addr(state, addr);
}

int dmbg_set_breakpoint_function(DumbuggerState *state, const char *function) {
    STOPPED_PROCESS_GUARD(state);

    if (function == NULL) {
        errno = EINVAL;
        return -1;
    }

    FunctionInfo *info = NULL;

    for (size_t i = 0; i < state->debug_info.functions_count; i++) {
        FunctionInfo *cur_info = &state->debug_info.functions[i];
        if (strcmp(cur_info->name, function) == 0) {
            info = cur_info;
            break;
        }
    }

    if (info == NULL) {
        errno = ENOENT;
        return -1;
    }

    long runtime_addr = state->load_addr + info->low_pc;
    return set_breakpoint_at_addr(state, runtime_addr);
}

static int dumbugger_state_remove_breakpoint(DumbuggerState *state, long addr) {
    if (list_size(&state->breakpoints) == 0) {
        return 0;
    }

    breakpoint_info *info;
    int index = 0;
    foreach (info, &state->breakpoints) {
        if (info->address == addr) {
            if (bp_list_remove(&state->breakpoints, index) == -1) {
                return -1;
            }
            return 1;
        }
        ++index;
    }

    return 0;
}

int dmbg_remove_breakpoint(DumbuggerState *state, long addr) {
    int result = dumbugger_state_remove_breakpoint(state, addr);
    if (result == 0) {
        errno = EINVAL;
        return -1;
    }

    if (result == -1) {
        return -1;
    }

    return 0;
}

int dmbg_functions_get(DumbuggerState *state, const char ***functions,
                       int *functions_count) {
    STOPPED_PROCESS_GUARD(state);
    const char **funcs_names = (const char **) calloc(
        state->debug_info.functions_count, sizeof(char *));
    if (funcs_names == NULL) {
        return -1;
    }

    for (size_t i = 0; i < state->debug_info.functions_count; i++) {
        funcs_names[i] = state->debug_info.functions[i].name;
    }

    *functions_count = state->debug_info.functions_count;
    *functions = funcs_names;
    return 0;
}

int dmbg_function_list_free(const char **functions, int functions_count) {
    (void) functions_count;
    free((void *) functions);
    return 0;
}
