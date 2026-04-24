
#include <stdio.h>
#include <stdlib.h>

int main() {
    int x = 42;
    int *p = NULL;
    printf("About to crash with x = %d\n", x);
    *p = x;  // This will cause a segfault
    return 0;
}
