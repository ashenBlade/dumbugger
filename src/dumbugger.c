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
#include <sys/reg.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>

#include "list.h"
#include "debug_syms.h"
#include "dis-asm.h"

#define WIFBREAKPOINT(wstatus) \
    (WIFSTOPPED(wstatus) && WSTOPSIG(wstatus) == SIGTRAP)

/* 
 * Прочитанная инструкция - начало фрейма с 2 инструкциями настройки стека:
 * push %rbp
 * mov  %rsp, %rbp
 */
#define IS_FRAMESETUP(text) (((text) & 0xFFFFFFFF) == 0xe5894855)

#define MAKE_BREAKPOINT_TEXT(text) (((text) & ~0xFF) | 0xCC)

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
LIST_DECLARE(breakpoint_info, bp_list)

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
    DebugInfo *debug_info;
};

static int set_breakpoint_at_addr(DumbuggerState *state, long addr);
static int remove_breakpoint(DumbuggerState *state, long addr);
static int make_single_instruction_step(DumbuggerState *state);
static int skip_frame_setup(DumbuggerState *state, long rip);

static void run_child(const char **args) {
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
        exit(errno);
    }

    execvp(args[0], (char *const *) args);
    exit(errno);
}

static int get_rip(DumbuggerState *state, long *rip) {
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, state->pid, NULL, &regs) == -1) {
        return -1;
    }

    *rip = (long) regs.rip;
    return 0;
}

static int get_rbp(DumbuggerState *state, long *rbp) {
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, state->pid, NULL, &regs) == -1) {
        return -1;
    }

    *rbp = (long) regs.rbp;
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
    /*
     * Для нахождения адреса загрузки парсим /proc/id/maps файл.
     * Находим первое упоминание exe_name в этом файле и возвращаем первый его
     * адрес. Обычно, нужный адрес самый первый, но лучше пройдем по всем
     * строкам и найдем нужный.
     */

    char maps_path[32];
    if (snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", (int) pid) ==
        -1) {
        return -1;
    }

    FILE *maps_file = fopen(maps_path, "r");
    if (maps_file == NULL) {
        return -1;
    }

    /*
     * Формат файла:
     * start-end    flags   offset  major_id:minor_id   inode_id    file_path
     *
     * Нам нужно получить первый 'start', у которого file_path равен exe_name,
     * т.е. бинарю запускаемого процесса
     */
    long start;
    char filepath[PATH_MAX + 1];
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
    char link_path[32];
    memset(link_path, 0, sizeof(link_path));
    if (snprintf(link_path, sizeof(link_path), "/proc/%d/exe", (int) pid) ==
        -1) {
        return -1;
    }

    int len = readlink(link_path, exe_path, exe_path_len);
    if (len == -1) {
        return -1;
    }
    exe_path[len + 1] = '\0';

    return 0;
}

static int fill_debug_info(DumbuggerState *state, pid_t child_pid) {
    /*
     * Получаем полный путь до исполняемого файла
     */
    char exe_path[PATH_MAX];
    if (get_exe_path(child_pid, exe_path, sizeof(exe_path)) == -1) {
        return -1;
    }

    /*
     * Находим загрузочный адрес
     */
    long load_addr;
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
    if (debug_syms_init(exe_path, &state->debug_info) == -1) {
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

    if (WIFEXITED(state->wstatus) || WIFSIGNALED(state->wstatus)) {
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

    debug_syms_free(state->debug_info);
    free(state->exe_path);
    bp_list_free(&state->breakpoints);
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

    /* Откатываемся */
    rip -= 1;
    if (set_rip(state, rip) == -1) {
        return -1;
    }

    if (remove_breakpoint(state, rip) == -1) {
        return -1;
    }

    /* Если точка останова на начале функции, то перейдем к концу пролога */
    if (skip_frame_setup(state, rip) == -1) {
        return -1;
    }

    return 0;
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
        if (restore_after_breakpoint(state) == -1) {
            return -1;
        }
        return 1;
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

static int skip_frame_setup(DumbuggerState *state, long rip) {
    /*
     * Если дальше пролог функции, то выполним его.
     * Под прологом имеется ввиду 2 инструкции: push %rbp; mov %rsp, %rbp
     * В прологе могут быть и другие функции, например, для
     * выделения места под стек, но для их обнаружения
     * потребуется больше ресурсов.
     * Этот код вынужденная мера, так как gcc пока не генерирует DW_LNS_set_prologue_end
     * инструкцию в DWARF
     */
    FunctionInfo *cur_func;
    if (debug_syms_get_function_at_addr(state->debug_info, rip - state->load_addr, &cur_func) == -1) {
        if (errno == ENOENT) {
            return 0;
        }
        return -1;
    }

    if (cur_func->low_pc != rip - state->load_addr) {
        return 0;
    }

    long text;
    if (peek_text(state, rip, &text) == -1) {
        return -1;
    }

    if (IS_FRAMESETUP(text)) {
        /* Читаем 2 инструкции: push rbp и mov rsp rbp */
        if (make_single_instruction_step(state) == -1) {
            return -1;
        }

        if (make_single_instruction_step(state) == -1) {
            return -1;
        }
    }

    return 0;
}

static int make_single_instruction_step(DumbuggerState *state) {
    if (ptrace(PTRACE_SINGLESTEP, state->pid, NULL, NULL) == -1) {
        return -1;
    }

    if (waitpid(state->pid, &state->wstatus, 0) != state->pid) {
        return -1;
    }

    if (WIFEXITED(state->wstatus) || WIFSIGNALED(state->wstatus)) {
        state->state = PROCESS_STATE_FINISHED;
        return 1;
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

int dmbg_step_instruction(DumbuggerState *state) {
    STOPPED_PROCESS_GUARD(state);
    switch (make_single_instruction_step(state)) {
        case 1:
        case 0:
            return 0;
        default /* case -1 */:
            return -1;
    }
}

int dmbg_step_in(DumbuggerState *state) {
    STOPPED_PROCESS_GUARD(state);

    long rip;
    if (get_rip(state, &rip) == -1) {
        return -1;
    }
    rip -= state->load_addr;
    /* Находим текущую строку кода и ее функцию */
    long start;
    long end;
    if (debug_syms_get_line_bounds(state->debug_info, rip, &start, &end) == -1) {
        return -1;
    }

    /* Выполняем по 1 инструкции до тех пор, пока информация о контексте не
     * поменяется */
    do {
        switch (make_single_instruction_step(state)) {
            case -1:
                return -1;
            case 1:
                /* Закончили выполнение */
                return 0;
        }

        if (get_rip(state, &rip) == -1) {
            return -1;
        }
        rip -= state->load_addr;

    } while (start <= rip && rip <= end);

    if (skip_frame_setup(state, rip) == -1) {
        return -1;
    }

    return 0;
}

static int exec_after_return(DumbuggerState *state) {
    /* 
     * После возвращения (return) необходимо выполнить всю строку до конца.
     * Единственная загвоздка - адрес возврата на другой строке.
     * Если это так, то мы ничего не должны делать.
     */
    long rip;
    if (get_rip(state, &rip) == -1) {
        return -1;
    }
    rip -= state->load_addr;
    
    FunctionInfo *cur_func;
    SourceLineInfo *cur_line;
    if (debug_syms_get_context(state->debug_info, rip, &cur_func, &cur_line) == -1) {
        if (errno == ENOENT) {
            return 0;
        }
        return -1;
    }

    FunctionInfo *prev_func;
    SourceLineInfo *prev_line;
    if (debug_syms_get_context(state->debug_info, rip - 1, &prev_func, &prev_line) == -1) {
        if (errno == ENOENT) {
            return 0;
        }
        return -1;
    }

    if (!(SOURCE_LINE_INFO_EQUAL(cur_line, prev_line) && FUNCTION_INFO_EQUAL(cur_func, prev_func))) {
        /* На разных строках */
        return 0;
    }


    FunctionInfo *cur_function;
    if (debug_syms_get_function_at_addr(state->debug_info, rip, &cur_function) == 0) {
        return 0;
    }
    
    /* Находим следующую строку - нам нужен адрес ее начала */
    SourceLineInfo *next_line = NULL;
    SourceLineInfo *sl_info;
    foreach (sl_info, cur_function->line_table) {
        if (cur_line == NULL) {
            if (sl_info->addr <= rip) {
                cur_line = sl_info;
            }
        } else {
            next_line = sl_info;
            break;
        }
    }

    /* 
     * Возможно, следующей строки нет, т.к. текущая была последней.
     * В этом случае, используем последний адрес функции (high_pc) как конец
     * последней инструкции
     */
    long line_end_addr;
    if (next_line == NULL) {
        line_end_addr = cur_function->high_pc;
    } else {
        line_end_addr = next_line->addr;
    }

    do {
        switch (make_single_instruction_step(state)) {
            case -1:
                return -1;
            case 1:
                return 0;
            default:
                break;
        }

        if (get_rip(state, &rip) == -1) {
            return -1;
        }
        rip -= state->load_addr;
    } while (cur_line->addr <= rip && rip <= line_end_addr);
    return 0;
}

int dmbg_step_out(DumbuggerState *state) {
    /*
     * step out реализуется следующим образом:
     *
     * 1. Читаем значение RBP
     * 2. Получаем с его помощью адрес возврата
     * 3. Ставим туда точку останова
     * 4. Удаляем точку останова, если останов произошел не в ней
     *
     * Последний шаг нужен тогда, когда на пути выполнения была
     * другая точка останова - тогда поставленная на 3 шаге уже не нужна.
     */

    STOPPED_PROCESS_GUARD(state);

    /*
     * |-------------| <----- RBP + 16
     * | return addr |
     * |-------------| <----- RBP + 8
     * |  prev rbp   |
     * |-------------| <----- RBP
     * |    .....    |
     */
    long rbp;
    if (get_rbp(state, &rbp) == -1) {
        return -1;
    }

    long return_addr;
    if (peek_text(state, rbp + 0x8, &return_addr) == -1) {
        return -1;
    }

    if (set_breakpoint_at_addr(state, return_addr) == -1) {
        return -1;
    }

    if (dmbg_continue(state) == -1) {
        return -1;
    }

    if (dmbg_wait(state) == -1) {
        return -1;
    }

    if (state->state == PROCESS_STATE_FINISHED) {
        return 0;
    }

    /*
     * Не факт, что точка останова та, что поставили - это может быть
     * точкой, что просто лежала по пути. Поэтому вручную удалим ту,
     * что поставили
     */
    if (remove_breakpoint(state, return_addr) == -1) {
        return -1;
    }

    /* 
     * В конце необходимо выполнить строку, на которую вернулись,
     * так как там может быть код восстанавливающий контекст (регистры и т.д.)
     */
    if (exec_after_return(state) == -1) {
        return -1;
    }

    return 0;
}

int dmbg_step_over(DumbuggerState *state) {
    long rip;
    if (get_rip(state, &rip) == -1) {
        return -1;
    }

    FunctionInfo *cur_func;
    if (debug_syms_get_function_at_addr(state->debug_info, rip - state->load_addr, &cur_func) == 0) {
        errno = ENOENT;
        return -1;
    }

    assert(cur_func != NULL);

    /* 
     * Сначала прочитаем адрес возврата.
     * На него тоже необходимо поставить точку останова, так как
     * выполняться может последняя строка.
     */
    long rbp;
    if (get_rbp(state, &rbp) == -1) {
        return -1;
    }

    long return_addr;
    if (peek_text(state, rbp + 0x8, &return_addr) == -1) {
        return -1;
    }

    /*
     * Мы не знаем куда точно попадем, так как есть условия, goto и др.,
     * поэтому поставим точки останова на все строки до конца функции
     */
    bp_list *set_breakpoints;
    if (bp_list_init(&set_breakpoints) == -1) {
        return -1;
    }

    breakpoint_info return_addr_bp = {
        .address = return_addr,
        .saved_text = 0,
    };
    if (bp_list_add(set_breakpoints, &return_addr_bp) == -1) {
        bp_list_free(set_breakpoints);
        return -1;
    }

    /* Уберем смещение адреса загрузки для удобной работы с символами отладки */
    rip -= state->load_addr;

    SourceLineInfo *line;
    foreach (line, cur_func->line_table) {
        /* 
         * Пропускаем только текущую строку, так как мы можем уйти выше.
         * Например, goto, longjmp, циклы и т.д.
         */
        if (line->addr == rip) {
            continue;
        }

        breakpoint_info cur_bp = {
            .address = line->addr + state->load_addr,
            .saved_text = 0,
        };

        if (bp_list_add(set_breakpoints, &cur_bp) == -1) {
            return -1;
        }
    }

    breakpoint_info *bp;
    foreach (bp, set_breakpoints) {
        if (set_breakpoint_at_addr(state, bp->address) == -1) {
            return -1;
        }
    }

    if (dmbg_continue(state) == -1) {
        return -1;
    }

    if (dmbg_wait(state) == -1) {
        return -1;
    }

    foreach (bp, set_breakpoints) {
        if (remove_breakpoint(state, bp->address) == -1) {
            return -1;
        }
    }
    
    if (bp_list_free(set_breakpoints) == -1) {
        return -1;
    }

    /* 
     * Если после этого шага мы вернулись в вызывающую функцию (return),
     * то выполним инструкции до конца строки на которую вернулись
     */
    if (get_rip(state, &rip) == -1) {
        return -1;
    }

    if (rip != return_addr) {
        return 0;
    }

    if (exec_after_return(state) == -1) {
        return -1;
    }

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
    dumbugger_assembly_dump_buffer *buf =
        (dumbugger_assembly_dump_buffer *) stream;

    if (buf->dump->length <= buf->insn_index) {
        return -1;
    }

    if (buf->asm_str_index < sizeof(buf->dump->insns[buf->insn_index].str)) {
        va_list argp;
        va_start(argp, fmt);
        int written = snprintf(
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
     * libopcodes добавляет в результирующую строку 3 символа
     * \002X\002, где X - любой символ, \002 - восьмеричные.
     * Это добавляет в вывод лишние символы и мешают. Поэтому удаляем эти
     * последовательности. Как по другому их убрать - не знаю.
     */

    int written = snprintf(buf, buf_len, fmt, argp);

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
    dumbugger_assembly_dump_buffer *buf =
        (dumbugger_assembly_dump_buffer *) stream;

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

    char temp_buf[64];
    memset(temp_buf, 0, sizeof(temp_buf));
    va_list argp;
    va_start(argp, fmt);
    int written = write_cleanup_escape(temp_buf, sizeof(temp_buf), fmt, argp);
    va_end(argp);

    if (written == -1) {
        return -1;
    }

    /* Если вернул 0, то оставшееся значение надо выбросить */
    if (written == 0) {
        return 0;
    }

    int current_length = buf->asm_str_index;
    int left_space =
        sizeof(buf->dump->insns[buf->insn_index].str) - current_length;
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
static int read_child_memory_opcodes_callback(bfd_vma memaddr, bfd_byte *myaddr,
                                              unsigned int length,
                                              struct disassemble_info *dinfo) {
    if (length == 0) {
        return 0;
    }

    unsigned int left = length;

    /* 
     * В каждом цикле читаем по 8 байт (размер слова)
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

    di.read_memory_func = read_child_memory_opcodes_callback;
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

static int has_breakpoint_at_address_predicate(void *ctx,
                                               breakpoint_info *info) {
    return info->address == (long) ctx ? 1 : 0;
}

static int dumbugger_state_add_breakpoint(DumbuggerState *state,
                                          breakpoint_info *info) {
    breakpoint_info *dummy;
    if (bp_list_contains(&state->breakpoints,
                         has_breakpoint_at_address_predicate,
                         (void *) info->address, &dummy)) {
        return 0;
    }

    return bp_list_add(&state->breakpoints, info);
}

static int set_breakpoint_at_addr(DumbuggerState *state, long addr) {
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
        errno = ENOENT;
        return -1;
    }

    FunctionInfo *func;
    int res = debug_syms_get_function_by_name(state->debug_info, function, &func);
    if (res == -1) {
        return -1;
    }

    if (res == 0) {
        errno = ENOENT;
        return -1;
    }

    return set_breakpoint_at_addr(state, func->low_pc - state->load_addr);
}

int dmbg_set_breakpoint_src_file(DumbuggerState *state, const char *filename,
                                 int src_line_no) {
    STOPPED_PROCESS_GUARD(state);
    if (filename == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (src_line_no < 0) {
        errno = EINVAL;
        return -1;
    }

    long addr;
    if (debug_syms_get_address_at_line(state->debug_info, filename,
                                       src_line_no, &addr) == 0) {
        errno = ENOENT;
        return -1;
    }

    return set_breakpoint_at_addr(state, state->load_addr + addr);
}

static int remove_breakpoint(DumbuggerState *state, long addr) {
    if (list_size(&state->breakpoints) == 0) {
        return 0;
    }

    breakpoint_info *info = NULL;
    int index = 0;
    foreach (info, &state->breakpoints) {
        if (info->address == addr) {
            break;
        }
        ++index;
    }

    if (list_size(&state->breakpoints) <= index) {
        /* Нет такой точки останова */
        return 0;
    }

    if (info == NULL) {
        /* Точка останова не найдена */
        return 0;
    }

    /*
     * Перед тем как удалить точку останова из списка, восстановим данные
     */
    long current_text;
    if (peek_text(state, addr, &current_text) == -1) {
        return -1;
    }

    current_text = (current_text & ~0xFF) | (info->saved_text & 0xFF);
    if (poke_text(state, addr, current_text) == -1) {
        return -1;
    }

    if (bp_list_remove(&state->breakpoints, index) == -1) {
        return -1;
    }

    return 0;
}

int dmbg_remove_breakpoint(DumbuggerState *state, long addr) {
    int result = remove_breakpoint(state, addr);
    if (result == 0) {
        errno = EINVAL;
        return -1;
    }

    if (result == -1) {
        return -1;
    }

    return 0;
}

int dmbg_functions_get(DumbuggerState *state, char ***functions,
                       int *functions_count) {
    int count = list_size(state->debug_info->functions);
    if (count == 0) {
        return 0;
    }

    char **funcs = malloc(count * sizeof(char *));
    if (funcs == NULL) {
        return -1;
    }

    int i = 0;
    FunctionInfo *finfo;
    foreach (finfo, state->debug_info->functions) {
        funcs[i] = strdup(finfo->name);
        if (funcs[i] == NULL) {
            for (int j = 0; j < i; ++j) {
                free(funcs[j]);
            }
            free(funcs);
            return -1;
        }
        ++i;
    }
    *functions = funcs;
    *functions_count = count;
    return 0;
}

int dmbg_function_list_free(char **functions, int functions_count) {
    (void) functions_count;
    for (int i = 0; i < functions_count; ++i) {
        free(functions[i]);
    }
    free((void *) functions);
    return 0;
}

int dmbg_get_src_position(DumbuggerState *state, char **filename,
                          int *line_no) {
    STOPPED_PROCESS_GUARD(state);

    long rip;
    if (get_rip(state, &rip) == -1) {
        return -1;
    }

    FunctionInfo *fi;
    SourceLineInfo *sli;
    if (debug_syms_get_context(state->debug_info, rip - state->load_addr, &fi, &sli) == -1) {
        return -1;
    }

    *filename = strdup(fi->decl_filename);
    *line_no = sli->logical_line_no;
    return 0;
}

int dmbg_get_variables(DumbuggerState *state, char ***out_variables,
                       int *out_count) {
    STOPPED_PROCESS_GUARD(state);

    FunctionInfo *cur_function;
    long rip;
    if (get_rip(state, &rip) == -1) {
        return -1;
    }

    if (debug_syms_get_function_at_addr(state->debug_info, rip - state->load_addr, &cur_function) == 0) {
        errno = ENOENT;
        return -1;
    }

    int length = list_size(cur_function->variables);
    if (length == 0) {
        *out_count = 0;
        *out_variables = NULL;
        return 0;
    }

    char **vars = calloc(length, sizeof(char *));
    int i = 0;
    Variable *var;
    foreach (var, cur_function->variables) {
        vars[i] = strdup(var->name);
        if (vars[i] == NULL) {
            for (int j = 0; j < i; ++j) {
                free(vars[j]);
            }
            free(vars);
            return -1;
        }

        ++i;
    }

    *out_count = length;
    *out_variables = vars;

    return 0;
}

int dmbg_free_variables(DumbuggerState *state, char **variables, int count) { 
    for (int i = 0; i < count; ++i) {
        free(variables[i]);
    }
    free(variables);
    return 0; 
}

static int read_simple_value(DumbuggerState *state, BaseType *type, 
                             long addr, char **value) {
    if (type->kind == TypeKindStruct) {
        *value = strdup("");
        if (*value == NULL) {
            return -1;
        }
        return 0;
    }

    long text;
    if (peek_text(state, addr, &text) == -1) {
        return -1;
    }

    char buf[32];
    memset(buf, 0, sizeof(buf));
    const char *formatter;
    if (type->kind == TypeKindPrimitive) {
        PrimitiveType *prim = (PrimitiveType *)type;
        switch (prim->byte_size) {
            case 1:
                if (prim->is_signed) {
                    formatter = "%d";
                } else {
                 
                    formatter = "%u";
                }
                break;
            case 2:
                if (prim->is_signed) {
                    formatter = "%hd";
                } else {
                    formatter = "%hu";
                }
                break;
            case 4:
                if (prim->is_signed) {
                    formatter = "%d";
                } else {
                    formatter = "%u";
                }
                break;
            case 8:
            default:
                if (prim->is_signed) {
                    formatter = "%ld";
                } else {
                    formatter = "%lu";
                }
                break;
        }
    } else {
        assert(type->kind == TypeKindPointer);
        formatter = "%p";
    }

    int written = snprintf(buf, sizeof(buf), formatter, text);
    if (written < 0) {
        return -1;
    }

    *value = strndup(buf, written);
    if (*value == NULL) {
        return -1;
    }

    return 0;
}

static int get_struct_values(DumbuggerState *state, long base_addr,
                             StructType *structure, char **values) {
    StructMember *member;
    bool error = false;
    int i = 1;
    foreach (member, structure->members) {
        if (read_simple_value(state, member->type, base_addr + member->byte_offset, &values[i + 1]) == -1) {
            error = true;
            break;
        }
        values[i] = strdup(member->name);
        if (values[i] == NULL) {
            error = true;
            break;
        }
        i += 2;
    }
    
    if (error) {
        for (i = 1; i < list_size(structure->members); ++i) {
            free(values[i]);
            values[i] = NULL;
        }
        return -1;
    }

    return 0;
}

static int read_pointer_values(DumbuggerState *state, long addr, 
                               PointerType *ptr, char ***out_values, int *out_count) {
    /* 
     * int *value   - разыменовываем
     * int **value  - значение самого указателя
     */
    assert(ptr->type->kind != TypeKindStruct);
    
    /* 
     * Если тип переменной указатель, то в этом случае
     * есть только 2 значения: значение указателя и на что он указывает.
     * Эта функция ответственна за примитивные типы и указатель на указатель.
     */
    int count = 2;
    char **values = calloc(2, sizeof(char *));
    if (values == NULL) {
        return -1;
    }

    /* Прочитаем, что находится на месте указателя */
    long ptr_value;
    if (peek_text(state, state->load_addr + addr, &ptr_value) == -1) {
        free(values);
        return -1;
    }

    /* И сохраним его сразу, без вызова read_simple_value */
    char buf[16];
    memset(buf, 0, sizeof(buf));
    if (snprintf(buf, sizeof(buf), "0x%p", (void*)ptr_value) < 0) {
        free(values);
        return -1;
    }
    buf[sizeof(buf) - 1] = '\0';

    values[0] = strdup(buf);
    if (values[0] == NULL) {
        free(values);
        return -1;
    }

    /* 
     * После, попытаемся прочитать, что находится уже по указателю
     */
    char *ptr_deref_value = NULL;
    if (ptr_value != 0 && 
        read_simple_value(state, ptr->type, ptr_value, &ptr_deref_value) == -1 &&
        errno != EIO) {
        /* 
         * Если указатель невалидный, то при попытке 
            * прочтения мы получим errno == EIO
            */
        free(values[0]);
        free(values);
        return -1;
    }

    if (ptr_deref_value == NULL) {
        ptr_deref_value = strdup("<invalid>");
        if (ptr_deref_value == NULL) {
            free(values[0]);
            free(values);
            return -1;
        }
    }

    values[1] = ptr_deref_value;

    *out_values = values;
    *out_count = count;
    return 0;
}

static int get_current_variable(DumbuggerState *state, const char *variable, 
                                Variable **out_var) {
    long rip;
    if (get_rip(state, &rip) == -1) {
        return -1;
    }

    FunctionInfo *func;
    if (debug_syms_get_function_at_addr(state->debug_info, rip - state->load_addr, &func) == 0) {
        errno = ENOENT;
        return -1;
    }

    Variable *var;
    foreach (var, func->variables) {
        if (strcmp(variable, var->name) == 0) {
            *out_var = var;
            return 0;
        }
    }

    errno = ENOENT;
    return -1;
}

int dmbg_get_variable_value(DumbuggerState *state, const char *variable,
                            char ***out_values, int *out_count) {
    STOPPED_PROCESS_GUARD(state);

    Variable *var;
    if (get_current_variable(state, variable, &var) == -1) {
        return -1;
    }

    if (var->type == NULL) {
        /* 
         * Возможно для некоторых переменных типы каким-то образом
         * не будут известны. Просто скажем, что такой переменной нет -
         * пока оставлю так
         */
        errno = ENOENT;
        return -1;
    }

    long rbp;
    if (get_rbp(state, &rbp) == -1) {
        return -1;
    }

    StructType *structure;
    PointerType *ptr;

    /* 
     * В dwarf смещение переменных начинается с самого начала фрейма, 
     * учитывая адрес возврата и сохраненный RBP
     */
    long addr = rbp + var->frame_offset + 16;
    char **values;
    int count;
    switch (var->type->kind) {
        case TypeKindPrimitive:
            /* int value */
            count = 1;
            values = calloc(1, sizeof(char *));
            if (values == NULL) {
                return -1;
            }
            if (read_simple_value(state, var->type, addr, values) == -1) {
                free(values);
                return -1;
            }
            break;
        case TypeKindPointer:
            ptr = (PointerType *)var->type;
            long ptr_value;
            switch (ptr->type->kind) {
                case TypeKindPrimitive:
                case TypeKindPointer:
                    /*
                     * int  *value
                     * int **value
                     */
                    if (read_pointer_values(state, addr, ptr, &values, &count) == -1) {
                        return -1;
                    }
                    break;
                case TypeKindStruct:
                    /* Struct *value */

                    /* Читаем, что находится по этому указателю */
                    if (peek_text(state, addr, &ptr_value) == -1) {
                        return -1;
                    }

                    char buf[16];
                    memset(buf, 0, sizeof(buf));
                    if (snprintf(buf, sizeof(buf), "%p", (void*)ptr_value) < 0) {
                        return -1;
                    }
                    char *ptr_value_str = strdup(buf);
                    if (ptr_value_str == NULL) {
                        return -1;
                    }

                    structure = (StructType *)ptr->type;
                    count = 1 + 2 * list_size(structure->members);
                    values = calloc(count, sizeof(char *));
                    if (values == NULL) {
                        free(ptr_value_str);
                        return -1;
                    }
                    
                    if (list_size(structure->members) == 0) {
                        values[0] = ptr_value_str;
                        break;
                    }

                    /* 
                     * Разыменовываем указатель и читаем поля структуры.
                     * Если указатель невалидный, то просто отдадим
                     * единственное значение - значение указателя.
                     */
                    if (get_struct_values(state, ptr_value, structure, values) == -1) {
                        if (errno == EIO) {
                            free(values);
                            values = calloc(1, sizeof(char *));
                            if (values == NULL) {
                                return -1;
                            }

                            values[0] = ptr_value_str;
                            count = 1;
                            break;
                        }

                        free(ptr_value_str);
                        free(values);
                        return -1;
                    }
                    break;
                default:
                    assert(false);
                    return -1;
            }
            break;
        case TypeKindStruct:
            /* Struct value */
            structure = (StructType *)var->type;
            count = 1 + 2 * list_size(structure->members);
            values = calloc(count, sizeof(char *));
            if (values == NULL) {
                return -1;
            }

            values[0] = strdup("");
            if (values[0] == NULL) {
                free(values);
                return -1;
            }

            if (count > 1) {
                if (get_struct_values(state, addr, structure, values) == -1) {
                    free(values[0]);
                    free(values);
                    return -1;
                }
            }
            break;
        default:
            errno = EINVAL;
            return -1;
    }

    *out_count = count;
    *out_values = values;

    return 0;
}

int dmbg_free_variable_value(DumbuggerState *state, char **values, int count) {
    for (int i = 0; i < count; ++i) {
        free(values[i]);
    }
    free(values);
    return 0;
}

int dmbg_backtrace_free(DumbuggerState *state, char **bt, int count) {
    for (int i = 0; i < count; ++i) {
        free(bt[i]);
    }
    free(bt);
    return 0;
}

DmbgStatus dmbg_status(DumbuggerState *state) {
    switch (state->state) {
        case PROCESS_STATE_RUNNING:
            return DMBG_STATUS_RUNNING;
        case PROCESS_STATE_STOPPED:
            return DMBG_STATUS_STOPPED;
        case PROCESS_STATE_FINISHED:
            return DMBG_STATUS_FINISHED;
    }
    return -1;
}

static int get_bt_function_at_addr(DumbuggerState *state, long addr, 
                                   char **out_value) {                  
    FunctionInfo *func;
    SourceLineInfo *sli;

    if (debug_syms_get_context(state->debug_info, addr, &func, &sli) == -1) {
        if (errno == ENOENT) {
            *out_value = strdup("<unknown>");
            if (*out_value == NULL) {
                return -1;
            }
            return 0;
        }
    }
    
    char buf[128];
    memset(buf, 0, sizeof(buf));
    int written = snprintf(buf, sizeof(buf), "%s:%ld", func->name, sli->logical_line_no);
    if (written < 0) {
        return -1;
    }

    buf[written] = '\0';
    *out_value = strdup(buf);
    if (*out_value == NULL) {
        return -1;
    }

    return 0;
}

int dmbg_get_backtrace(DumbuggerState *state, int max, char ***out_bt,
                       int *out_count) {
    STOPPED_PROCESS_GUARD(state);
    
    if (max < 0) {
        errno = EINVAL;
        return -1;
    }

    if (max == 0) {
        *out_count = 0;
        *out_bt = NULL;
        return 0;
    }

    /* Сохраняем текущий контекст (функция + строка файла) */
    long rip;
    if (get_rip(state, &rip) == -1) {
        return -1;
    }

    char **backtrace;
    int count;
    backtrace = calloc(max, sizeof(char *));
    if (backtrace == NULL) {
        return -1;
    }

    if (get_bt_function_at_addr(state, rip - state->load_addr, backtrace) == -1) {
        free(backtrace);
        return -1;
    }

    /* Если запросили только 1 функцию, то возвращаемся сразу */
    if (max == 1) {
        *out_count = 1;
        *out_bt = backtrace;
        return 0;
    }

    /* Начинаем итерироваться по предыдущим фреймам */
    long rbp;
    if (get_rbp(state, &rbp) == -1) {
        free(backtrace[0]);
        free(backtrace);
        return -1;
    }

    count = 1;
    bool error = false;
    while (count < max) {
        /* Получаем контекст предыдущей функции по адресу возврата */
        long ret_addr;
        if (peek_text(state, rbp + 0x8, &ret_addr) == -1) {
            error = true;
            break;
        }

        if (get_bt_function_at_addr(state, ret_addr - state->load_addr, &backtrace[count]) == -1) {
            error = true;
            break;
        }

        /* Переходим к следующей - читаем предыдущий RBP на основании текущего */
        ++count;

        if (count == max) {
            break;
        }

        if (peek_text(state, rbp, &rbp) == -1) {
            error = true;
            break;
        }

        /* 
         * Если полученный RBP - 0, то значит мы дошли 
         * до первородной функции и дальше ничего нет 
         */
        if (rbp == 0) {
            break;
        }
    }

    if (error) {
        for (int i = 0; i < count; ++i) {
            free(backtrace[i]);
        }
        free(backtrace);
        return -1;
    }

    *out_bt = backtrace;
    *out_count = count;
    return 0;
}