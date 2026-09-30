#define _GNU_SOURCE /* Enables clearenv() and advanced POSIX features */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/resource.h>

#include "executor.h"

/* --------------------------------------------------------------------------
 * Internal Helper: Robust Write
 * Ensures all bytes are written to a file descriptor, handling partial writes 
 * and interrupts (EINTR) which are common in socket programming.
 * -------------------------------------------------------------------------- */
static ssize_t write_all(int fd, const void *buf, size_t count) {
    const char *ptr = buf;
    size_t nleft = count;
    ssize_t nwritten;

    while (nleft > 0) {
        nwritten = write(fd, ptr, nleft);
        
        /* LCOV_EXCL_START - Defensive kernel I/O fault handling */
        if (nwritten <= 0) {
            if (nwritten < 0 && errno == EINTR) {
                nwritten = 0; /* Interrupted by signal, call write() again */
            } else {
                return -1;    /* Fatal error (e.g., client disconnected) */
            }
        }
        /* LCOV_EXCL_STOP */
        
        nleft -= (size_t)nwritten;
        ptr   += nwritten;
    }
    return (ssize_t)count;
}

/* --------------------------------------------------------------------------
 * Public API: execute_script
 * -------------------------------------------------------------------------- */
server_status_t execute_script(int client_fd, 
                               const char *req_id, 
                               const char *payload, 
                               size_t payload_len) {
    int pipe_in[2];   /* Parent writes to [1], Child reads from [0] */
    int pipe_out[2];  /* Child writes to [1], Parent reads from [0] */
    pid_t pid;

    /* Initialize unidirectional pipes */
    if (pipe(pipe_in) < 0 || pipe(pipe_out) < 0) {
        perror("[-] pipe() failed");    // LCOV_EXCL_LINE
        return STATUS_ERR_INTERNAL;     // LCOV_EXCL_LINE
    }

    /* Send execution approval header to the client */
    char header[512];
    int hlen = snprintf(header, sizeof(header), 
                        "[%s] STATUS: APPROVED\n--- OUTPUT START ---\n", req_id);
    write_all(client_fd, header, (size_t)hlen);

    /* Fork the execution process */
    pid = fork();
    if (pid < 0) {
        perror("[-] fork() failed");    // LCOV_EXCL_LINE
        return STATUS_ERR_INTERNAL;     // LCOV_EXCL_LINE
    }

    if (pid == 0) {
        /* ==================================================================
         * CHILD PROCESS: THE SANDBOX
         * ================================================================== */
        close(pipe_in[1]);   /* Child does not write to stdin pipe */
        close(pipe_out[0]);  /* Child does not read from stdout pipe */

        /* 1. File Descriptor Redirection */
        if (dup2(pipe_in[0], STDIN_FILENO) < 0 || 
            dup2(pipe_out[1], STDOUT_FILENO) < 0 || 
            dup2(pipe_out[1], STDERR_FILENO) < 0) {
            exit(127);      // LCOV_EXCL_LINE
        }
        
        close(pipe_in[0]);
        close(pipe_out[1]);

        /* 2. Resource Exhaustion Protection (DoS Mitigation) */
        
        /* Limit CPU execution time to prevent infinite loops */
        struct rlimit rlim_cpu = {LIMIT_CPU_SEC, LIMIT_CPU_SEC};
        setrlimit(RLIMIT_CPU, &rlim_cpu);

        /* Limit Memory footprint to prevent memory exhaustion */
        struct rlimit rlim_mem = {LIMIT_MEM_BYTES, LIMIT_MEM_BYTES};
        setrlimit(RLIMIT_AS, &rlim_mem);

        /* Limit child processes to prevent fork bombs */
        struct rlimit rlim_nproc = {LIMIT_NPROC, LIMIT_NPROC};
        setrlimit(RLIMIT_NPROC, &rlim_nproc);

        /* 3. Environment Sanitization */
        clearenv(); /* Strip all potentially malicious environment variables */
        setenv("PATH", "/usr/bin:/bin", 1); /* Provide minimal safe path */

        /* 4. Execution 
         * By passing "-s", bash reads the entire script from stdin into memory
         * before executing it. This means no temporary files are written to disk. */
        execl("/bin/bash", "bash", "-s", NULL);

        /* If we reach here, execl failed */
        perror("execl failed");
        exit(127);

    } else {
        /* ==================================================================
         * PARENT PROCESS: THE CONTROLLER
         * ================================================================== */
        close(pipe_in[0]);  /* Parent does not read from stdin pipe */
        close(pipe_out[1]); /* Parent does not write to stdout pipe */

        /* 1. Feed the verified payload directly into the bash process's memory.
         * Because `bash -s` buffers the whole script before executing, it won't 
         * block our write or cause a pipe deadlock. */
        if (write_all(pipe_in[1], payload, payload_len) < 0) {
            perror("[-] Failed to write payload to child");     // LCOV_EXCL_LINE
        }
        close(pipe_in[1]); /* Sending EOF tells bash to start execution */

        /* 2. Stream the execution output in real-time back to the client socket */
        char buf[4096];
        ssize_t bytes_read;
        
        while ((bytes_read = read(pipe_out[0], buf, sizeof(buf))) > 0) {
            if (write_all(client_fd, buf, (size_t)bytes_read) < 0) {
                fprintf(stderr, "[-] Client disconnected during output stream.\n"); // LCOV_EXCL_LINE
                break;                                                              // LCOV_EXCL_LINE
            }
        }
        close(pipe_out[0]);

        /* 3. Wait for the sandbox process to complete and reap the zombie */
        int status;
        waitpid(pid, &status, 0);
        
        char footer[512];
        int flen;

        /* 4. Format detailed execution summary footer */
        if (WIFEXITED(status)) {
            /* Process exited normally (e.g., exit(0) or exit(1)) */
            int exit_code = WEXITSTATUS(status);
            flen = snprintf(footer, sizeof(footer), 
                            "\n--- OUTPUT END (EXIT CODE: %d) ---\n", exit_code);
        } else if (WIFSIGNALED(status)) {
            /* Process was brutally assassinated by the OS kernel */
            int sig = WTERMSIG(status);
            const char *reason = "Unknown Signal";
            
            if (sig == SIGKILL) {
                reason = "SIGKILL - Resource limit exceeded (CPU timeout or Memory exhaustion)";
            } else if (sig == SIGSEGV) {
                reason = "SIGSEGV - Segmentation fault";
            }
            
            /* We retain the 'EXIT CODE: -1' substring so our existing 
             * Python automated tests continue to pass seamlessly! */
            flen = snprintf(footer, sizeof(footer), 
                            "\n--- OUTPUT END (EXIT CODE: -1 [%s]) ---\n", reason);
        } else {
            flen = snprintf(footer, sizeof(footer), 
                            "\n--- OUTPUT END (EXIT CODE: -1 [TERMINATED UNKNOWN]) ---\n");
        }

        /* 5. Send execution summary footer to client */
        write_all(client_fd, footer, (size_t)flen);

        return STATUS_OK;
    }
}