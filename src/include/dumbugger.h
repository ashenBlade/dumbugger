#ifndef DUMBUGGER_H
#define DUMBUGGER_H

/*
 * Структура содержащая информацию для отладки конкретного процесса.
 * Создается для каждого запущенного под отладкой процесса.
 */
typedef struct DumbuggerState DumbuggerState;

/* Причина остановки отлаживаемого процесса */
typedef enum {
    /* Процесс завершил работу */
    DMBG_STOP_EXITED,

    /* Точка останова */
    DMBG_STOP_BP,
} DmbgStopReason;

/*
 * Запустить указанную программу для отладки.
 *
 * @param prog_name название программы
 * @param args аргументы командной строки, которые следует передать, включая
 * название программы
 *
 * @returns объект состояния для управления процессом отладки, либо NULL в
 * случае ошибки
 */
DumbuggerState *dmbg_run(const char *prog_name, const char **args);

/*
 * Остановить запущенный процесс и завершить процесс отладки.
 *
 * @returns 0 - успешно, -1 - ошибка
 */
int dmbg_stop(DumbuggerState *state);

/*
 * Освободить ресурсы выделенные для процесса отладки.
 *
 * После выполнения, указатель невалиден
 */
int dmbg_free(DumbuggerState *state);

/*
 * Получить причину остановки процесса.
 * Вызывается после возврата из dmbg_stop для получения причины остановки
 * процесса.
 */
int dmbg_stop_reason(DumbuggerState *state, DmbgStopReason *reason);

/*
 * Ожидать остановку процесса. Остановка может произойти по различным причинам,
 * поэтому при возвращении необходимо получить причину остановки.
 *
 * В случае, если процесс уже был остановлен, то возврат происходит сразу.
 */
int dmbg_wait(DumbuggerState *state);

/*
 * Продолжить выполнение остановленного процесса.
 * Запускается после того, как процесс был остановлен с помощью dmbg_wait().
 */
int dmbg_continue(DumbuggerState *state);

/*
 * Выполнить одну инструкцию и остановиться.
 */
int dmbg_single_step_i(DumbuggerState *state);

/* 
 * Выполнить одну строку исходного кода (step in)
 */
int dmbg_single_step_src(DumbuggerState *state);

/* Структура, представляющая регистры процессора */
typedef struct Registers {
    unsigned long long int r8;
    unsigned long long int r9;
    unsigned long long int r10;
    unsigned long long int r11;
    unsigned long long int r12;
    unsigned long long int r13;
    unsigned long long int r14;
    unsigned long long int r15;
    unsigned long long int rbp;
    unsigned long long int rbx;
    unsigned long long int rax;
    unsigned long long int rcx;
    unsigned long long int rdx;
    unsigned long long int rsi;
    unsigned long long int rdi;
    unsigned long long int rip;
    unsigned long long int rsp;
} Registers;

/*
 * Получить регистры процессора.
 * При успешной операции, результат сохраняется в переменной *regs
 */
int dmbg_get_regs(DumbuggerState *state, Registers *regs);

/*
 * Выставить значения регистров в переданные значения.
 * Скорее всего, для получения изначальных данных нужен dmbg_get_regs
 */
int dmbg_set_regs(DumbuggerState *state, Registers *regs);

/*
 * Структура для представления результата дизассемблирования
 */
typedef struct DumbuggerAssemblyDump {
    /*
     * Длина массива инструкций (insns)
     */
    int length;
#define DMBG_MAX_ASSEMBLY_STR_LEN 64

    /*
     * Массив пар адрес и строка ассемблера.
     * Каждая строка оканчивается '\0'.
     */
    struct {
        long addr;
        char str[DMBG_MAX_ASSEMBLY_STR_LEN];
    } *insns;
} DumbuggerAssemblyDump;

/*
 * Дизассемблировать length следующих машинных инструкций
 */
int dmbg_disassemble(DumbuggerState *state, int length,
                     DumbuggerAssemblyDump *result);

/*
 * Освободить место, выделенное для процесса дизассемблирования
 */
int dumb_assembly_dump_free(DumbuggerAssemblyDump *dump);

/*
 * Поставить точку останова на указанный адрес.
 * Точка останова будет срабатывать каждый раз при ее достижении, т.е.
 */
int dmbg_set_breakpoint_addr(DumbuggerState *state, long addr);

/*
 * Поставить точку останова на указанную функцию.
 *
 * Если эта функция не найдена, то возвращается -1 и errno равен ENOENT
 */
int dmbg_set_breakpoint_function(DumbuggerState *state, const char *function);

/* 
 * Поставить точку останова в файле на строке.
 * Нумерация строк с 1.
 * 
 * Если по указанной строке нельзя поставить точку останова (функции нет),
 * то возвращается -1 и errno равен ENOENT
 */
int dmbg_set_breakpoint_src_file(DumbuggerState *state, const char *filename,
                                 int src_line_no);

/*
 * Удалить точку останова по указанному адресу
 */
int dmbg_remove_breakpoint(DumbuggerState *state, long addr);

/*
 * Получить список всех функций, доступных в процессе.
 * При завершении необходимо вызвать dmbg_functions_free для освобождения
 * ресурсов
 */
int dmbg_functions_get(DumbuggerState *state, char ***functions,
                       int *functions_count);

/*
 * Освободить ресурсы выделенные для создания списка функций
 */
int dmbg_function_list_free(char **functions, int functions_count);


/* 
 * Получить информацию об исходном коде, исполняющего процесса
 */
int dmbg_get_run_context(DumbuggerState *state, char **filename, int *line_no);


#endif