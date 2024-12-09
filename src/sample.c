#include <stdio.h>

typedef struct Data {
    int value1;
    long value2;
} Data;

int do_magic(Data *data) {
    int temp = data->value1 * 2;
    if (0 < temp) {
        data->value2 *= 3;
    } else {
        data->value1 -= 1;
    }
    
    return (temp + 2) / 6;
}

int main(int argc, const char **argv) {
    Data data = {
        .value1 = 3,
        .value2 = 1
    };
    if (do_magic(&data)) {
        printf("value1 is: %ld", data.value2);
    }
    return 0;
}