#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>

volatile int secret = 1337;
int* anchor = 0;

int main(int argc, char** argv) {
    prctl(PR_SET_PTRACER, -1UL);
    anchor = &secret;
    printf("X=%llx\n", (unsigned long long)(unsigned long)(void*)&secret);
    fflush(stdout);
    printf("P=%llx\n", (unsigned long long)(unsigned long)(void*)&anchor);
    fflush(stdout);
    if (argc > 1 && strcmp(argv[1], "mutate") == 0) {
        while (1) {
            usleep(150000);
            secret++;
        }
    }
    while (1) {
        sleep(1);
    }
    return 0;
}
