#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/crypto.h>

#include "server.h"
#include "crypto.h"
#include "executor.h"

/* Global flag for graceful daemon shutdown */
volatile sig_atomic_t keep_running = 1;

/* --------------------------------------------------------------------------
 * Signal Handlers
 * -------------------------------------------------------------------------- */
static void sigchld_handler(int s) {
    (void)s;
    int saved_errno = errno;
    while (waitpid(-1, NULL, WNOHANG) > 0);
    errno = saved_errno;
}

/* Handler for SIGTERM/SIGINT to gracefully stop the daemon */
static void sigterm_handler(int s) {
    (void)s;
    keep_running = 0;
}

static void setup_signals() {
    /* 1. SIGCHLD (Reap zombies, restart interrupted syscalls) */
    struct sigaction sa_chld;
    sa_chld.sa_handler = sigchld_handler;
    sigemptyset(&sa_chld.sa_mask);
    sa_chld.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa_chld, NULL) == -1) {
        perror("[-] sigaction(SIGCHLD) failed");    // LCOV_EXCL_LINE
        exit(EXIT_FAILURE);                         // LCOV_EXCL_LINE
    }
    
    /* 2. SIGTERM & SIGINT (Graceful shutdown, DO NOT restart syscalls) */
    struct sigaction sa_term;
    sa_term.sa_handler = sigterm_handler;
    sigemptyset(&sa_term.sa_mask);
    sa_term.sa_flags = 0; /* No SA_RESTART so accept() breaks out with EINTR */
    sigaction(SIGTERM, &sa_term, NULL);
    sigaction(SIGINT, &sa_term, NULL);
    
    /* 3. SIGPIPE (Prevent crash on dropped client connections) */
    signal(SIGPIPE, SIG_IGN);
}

/* --------------------------------------------------------------------------
 * Listener Setup
 * -------------------------------------------------------------------------- */
static int create_listener(const server_config_t *config) {
    int sockfd = -1;

    if (config->uds_path) {
        sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (sockfd < 0) return -1;  // LCOV_EXCL_LINE

        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, config->uds_path, sizeof(addr.sun_path) - 1);

        /* Remove any existing socket file at the path */
        unlink(config->uds_path);

        if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) return -1; // LCOV_EXCL_LINE
        fprintf(stdout, "[*] Bound to UNIX Domain Socket: %s\n", config->uds_path);

    } else if (config->tcp_port) {
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) return -1;  // LCOV_EXCL_LINE

        /* Allow immediate reuse of the port after server restart */
        int opt = 1;
        setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons((uint16_t)atoi(config->tcp_port));

        if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) return -1; // LCOV_EXCL_LINE
        fprintf(stdout, "[*] Bound to TCP Port: %s\n", config->tcp_port);
    }

    /* Queue up to 10 incoming connection requests */
    if (listen(sockfd, 10) < 0) return -1;
    return sockfd;
}

/* --------------------------------------------------------------------------
 * Client Connection Handler (Runs in a child process)
 * -------------------------------------------------------------------------- */
static void handle_client(int client_fd, crypto_ctx_t *crypto_ctx) {
    char req_id[64];
    snprintf(req_id, sizeof(req_id), "REQ-%ld-%d", (long)time(NULL), getpid());

    /* Allocate buffer securely on the heap to prevent stack overflow */
    unsigned char *buffer = malloc(MAX_PAYLOAD_SIZE + 1);
    if (!buffer) {
        close(client_fd);   // LCOV_EXCL_LINE
        exit(EXIT_FAILURE); // LCOV_EXCL_LINE
    }

    size_t total_read = 0;
    ssize_t n;

    /* Read the payload until the client signals EOF via shutdown(SHUT_WR) */
    while ((n = read(client_fd, buffer + total_read, MAX_PAYLOAD_SIZE - total_read)) > 0) {
        total_read += (size_t)n;
        if (total_read == MAX_PAYLOAD_SIZE) break; /* Prevent memory exhaustion DoS */
    }

    if (n < 0) {
        free(buffer);       // LCOV_EXCL_LINE
        close(client_fd);   // LCOV_EXCL_LINE
        exit(EXIT_FAILURE); // LCOV_EXCL_LINE
    }

    buffer[total_read] = '\0'; /* Ensure null termination for string processing */

    /* Protocol Parsing: Split Line 1 (Signature) from Payload */
    char *newline = strchr((char*)buffer, '\n');
    if (!newline) {
        char err[256];
        int len = snprintf(err, sizeof(err), "[%s] STATUS: REJECTED (Reason: Malformed input, no newline)\n", req_id);
        if (write(client_fd, err, (size_t)len) < 0) { /* ignore */ } // LCOV_EXCL_LINE
        goto cleanup;
    }

    size_t line1_len = (size_t)(newline - (char*)buffer);
    char *line1 = malloc(line1_len + 1);
    if (!line1) goto cleanup;
    
    memcpy(line1, buffer, line1_len);
    line1[line1_len] = '\0';

    /* Determine Payload Start */
    unsigned char *payload = (unsigned char*)(newline + 1);
    size_t payload_len = total_read - line1_len - 1;

    /* Validate Signature Prefix */
    const char *prefix = "# SIG: ";
    if (strncmp(line1, prefix, strlen(prefix)) != 0) {
        char err[256];
        int len = snprintf(err, sizeof(err), "[%s] STATUS: REJECTED (Reason: Missing or invalid '# SIG: ' prefix)\n", req_id);
        if (write(client_fd, err, (size_t)len) < 0) { /* ignore */ }
        free(line1);
        goto cleanup;
    }

    char *base64_sig = line1 + strlen(prefix);
    
    /* Strip Windows CRLF '\r' if present */
    size_t sig_len = strlen(base64_sig);
    if (sig_len > 0 && base64_sig[sig_len - 1] == '\r') {
        base64_sig[sig_len - 1] = '\0';
    }

    /* Verification & Execution phase */
    if (crypto_verify_signature(crypto_ctx, payload, payload_len, base64_sig) == STATUS_OK) {
        /* execute_script handles the STATUS: APPROVED message and streams output */
        execute_script(client_fd, req_id, (const char*)payload, payload_len);
    } else {
        char err[256];
        int len = snprintf(err, sizeof(err), "[%s] STATUS: REJECTED (Reason: Cryptographic signature verification failed)\n", req_id);
        if (write(client_fd, err, (size_t)len) < 0) { /* ignore */ }
    }

    free(line1);

cleanup:
    /* Securely wipe the script and memory buffers before releasing */
    OPENSSL_cleanse(buffer, MAX_PAYLOAD_SIZE + 1);
    free(buffer);
    close(client_fd);
    exit(EXIT_SUCCESS);
}

/* --------------------------------------------------------------------------
 * Main Entry Point
 * -------------------------------------------------------------------------- */
int main(int argc, char *argv[]) {
    server_config_t config = {0};
    int opt;

    /* Parse CLI Arguments using POSIX getopt */
    while ((opt = getopt(argc, argv, "u:p:c:h")) != -1) {
        switch (opt) {
            case 'u': config.uds_path = optarg; break;
            case 'p': config.tcp_port = optarg; break;
            case 'c': config.cert_dir = optarg; break;
            case 'h': 
            default:
                fprintf(stderr, "Usage: %s [-u uds_path | -p tcp_port] -c cert_dir\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if ((!config.uds_path && !config.tcp_port) || !config.cert_dir) {
        fprintf(stderr, "[-] Error: Must specify an IPC transport (-u or -p) and a certificate directory (-c).\n");
        exit(EXIT_FAILURE);
    }

    setup_signals();

    /* Load X.509 certificates and validate policies *once* at startup */
    crypto_ctx_t *ctx = crypto_init(config.cert_dir);
    if (!ctx) {
        fprintf(stderr, "[-] Failed to initialize cryptography subsystem. Exiting.\n");
        exit(EXIT_FAILURE);
    }

    int server_fd = create_listener(&config);
    if (server_fd < 0) {
        perror("[-] Failed to initialize server socket"); // LCOV_EXCL_LINE
        crypto_cleanup(ctx);                              // LCOV_EXCL_LINE
        exit(EXIT_FAILURE);                               // LCOV_EXCL_LINE
    }

    fprintf(stdout, "[*] Server listening and ready to accept connections.\n");

    /* Graceful Accept Loop, instead of infinity loop */
    while (keep_running) {
        int client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) {
            /* EINTR means accept was interrupted by a signal. 
             * If it was SIGTERM, keep_running is now 0, and the loop will exit cleanly! */
            if (errno == EINTR) continue;
            perror("[-] accept() failed");                // LCOV_EXCL_LINE
            continue;                                     // LCOV_EXCL_LINE
        }

        /* Fork a dedicated child process for the connection (Stretch Goal 2) */
        pid_t pid = fork();
        if (pid == 0) {
            /* Child process context */
            close(server_fd); /* Child does not need the listener socket */
            
            /* Add this line: Let executor.c handle waitpid() synchronously */
            signal(SIGCHLD, SIG_DFL); 
            
            handle_client(client_fd, ctx);
        } else if (pid > 0) {
            /* Parent process context */
            close(client_fd); /* Parent hands off the connection to the child */
        } else {
            perror("[-] fork() failed, cannot handle client"); // LCOV_EXCL_LINE
            close(client_fd);                                  // LCOV_EXCL_LINE
        }
    }

    /* Unreachable in this daemon structure, but here for completeness */
    crypto_cleanup(ctx);
    close(server_fd);
    return 0;
}