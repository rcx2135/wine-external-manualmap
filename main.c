
#include <stdio.h>
#include <unistd.h>
#include <dirent.h>
#include <libgen.h>
#include <string.h>
#include <stdlib.h>

#include "lib/ptrace_do/libptrace_do.h"



int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <pid>\n", argv[0]);
        return 1;
    }

    pid_t pid = atoi(argv[1]);
    printf("pid=%d\n", pid);
    if (kill(pid, 0) == -1) {
        printf("Invalid pid\n");
        return 1;
    }


    struct ptrace_do *target;
    target = ptrace_do_init(pid);

    char* buffer = (char *) ptrace_do_malloc(target, 0x500);
    ptrace_do_cleanup(target);


    printf("did nothing award %p\n", buffer);



}
