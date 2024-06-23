#include <stdio.h>

int sample_function(int a) {
    int lon = a * 2;
    return lon + 1;
}

int main(int argc, const char **argv) {
    int i = argc;
    ++i;
    i = sample_function(i);
    printf("%d", i);
    return 0;
}