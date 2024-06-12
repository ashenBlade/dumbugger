#ifndef DUMBUGGER_H
#define DUMBUGGER_H

/*
 * Структура содержащая информацию для отладки конкретного процесса.
 * Создается для каждого запущенного под отладкой процесса.
 */
typedef struct DumbuggerState DumbuggerState;

/* Причина остановки отлаживаемого процесса */
typedef enum
{
    /* Процесс завершил работу */
    DMBG_STOP_EXITED,

    /* Точка останова */
    DMBG_STOP_BP,
} DmbgStopReason;

/*
 * Запустить указанную программу для отладки.
 *
 * @param prog_name название программы
 * @param args аргументы командной строки, которые следует передать, включая название программы
 *
 * @returns объект состояния для управления процессом отладки, либо NULL в случае ошибки
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
 * Вызывается после возврата из dmbg_stop для получения причины остановки процесса.
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
int dmbg_continue(DumbuggerState  *state);

/* Структура, представляющая регистры процессора */
typedef struct Registers
{
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
     * Длина массива as
     */
    int length;
#define DMBG_MAX_ASSEMBLY_STR_LEN 32

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
int dmbg_disassemble(DumbuggerState *state, int length, DumbuggerAssemblyDump *result);

/* 
 * Освободить место, выделенное для процесса дизассемблирования
 */
int dumb_assembly_dump_free(DumbuggerAssemblyDump *dump);

/* 
 * Поставить точку останова на указанный адрес.
 * Точка останова будет срабатывать каждый раз при ее достижении, т.е. 
 */
int dmbg_set_breakpoint(DumbuggerState *state, long addr);

/* 
 * Удалить точку останова по указанному адресу
 */
int dmbg_remove_breakpoint(DumbuggerState  *state, long addr);

#endif