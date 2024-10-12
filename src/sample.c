#include <stdio.h>
#include <stdlib.h>

typedef struct Sample {
    int value;
} Sample;

int sample_function(int a) {
    int lon = a * 2;
    Sample s = {
        .value = 123,
    };
    Sample *sss = calloc(1, sizeof(Sample));
    sss->value = 12323;
    return lon + 1;
}

int main(int argc, const char **argv) {
    int i = argc;
    ++i;
    i = sample_function(i);
    printf("%d", i);
    return 0;
}