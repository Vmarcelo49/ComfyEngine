#include <stdio.h>
#include <unistd.h>

volatile int secret = 1337;
int* anchor = 0;

int main() {
    anchor = &secret;
    printf("X=%llx\n", (unsigned long long)(unsigned long)(void*)&secret);
    fflush(stdout);
    printf("P=%llx\n", (unsigned long long)(unsigned long)(void*)&anchor);
    fflush(stdout);
    while (1) {
        sleep(1);
    }
    return 0;
}
