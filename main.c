#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <signal.h>
#include <errno.h>

#define EXEC_PATH "/home/mirenk/sh365/ptrace_emu/bin/test_asm"

int main() {
    int status;
    struct user_regs_struct regs;
    pid_t target;
    int is_enter_stop = 0;
    long prev_orig_rax = -1;

    target = fork();

    if(target == 0) {
        ptrace(PTRACE_TRACEME, NULL, NULL, NULL);
        status = execlp(EXEC_PATH, EXEC_PATH, NULL);
        printf("failed. %d\n", errno);
    } else if(target == -1) {
        printf("fork failed\n");
        exit(-1);
    }

    ptrace(PTRACE_SETOPTIONS, target, NULL, PTRACE_O_TRACESYSGOOD);

    ptrace(PTRACE_SINGLESTEP, target, NULL, NULL);
    waitpid(target, &status, 0);

    ptrace(PTRACE_GETREGS, target, NULL, &regs);
    printf("rsp: 0x%016llx\n", regs.rsp);
    regs.rdi = regs.rsp;
    ptrace(PTRACE_SETREGS, target, NULL, &regs);

    while(1) {
        ptrace(PTRACE_SYSCALL, target, NULL, NULL);
        waitpid(target, &status, 0);
        if (WIFEXITED(status)) {
            printf("child process exited\n");
            ptrace(PTRACE_DETACH, target, NULL, NULL);
            break;
        } else if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
            printf("SIGTRAP.\n");
            ptrace(PTRACE_GETREGS, target, NULL, &regs);
            printf("orig_rax: 0x%llx\n", regs.orig_rax);
            is_enter_stop = prev_orig_rax == regs.orig_rax ? !is_enter_stop : 1;
            prev_orig_rax = regs.orig_rax;
            if (is_enter_stop && regs.orig_rax == 4) {
                printf("freebsd orig_rax(write): 0x%llx\n", regs.orig_rax);
                regs.orig_rax = SYS_write;
                prev_orig_rax = SYS_write;
                ptrace(PTRACE_SETREGS, target, NULL, &regs);
                ptrace(PTRACE_GETREGS, target, NULL, &regs);
                printf("modify orig_rax(write): 0x%llx\n", regs.orig_rax);
            } else if (is_enter_stop && regs.orig_rax == 1) {
                printf("freebsd orig_rax(exit): 0x%llx\n", regs.orig_rax);
                regs.orig_rax = SYS_exit;
                prev_orig_rax = SYS_exit;
                ptrace(PTRACE_SETREGS, target, NULL, &regs);
                ptrace(PTRACE_GETREGS, target, NULL, &regs);
                printf("modify orig_rax(exit): 0x%llx\n", regs.orig_rax);
            }
        }
    }
}
