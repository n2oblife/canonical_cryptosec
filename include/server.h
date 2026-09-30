#ifndef SERVER_H
#define SERVER_H

#include <stddef.h>
#include <stdint.h>

/* System Limits for DoS Protection */
#define MAX_PAYLOAD_SIZE      (1024 * 1024) /* 1MB max script size */
#define MAX_LINE_LENGTH       4096          /* Max signature line length */
#define EXECUTION_TIMEOUT_SEC 10            /* Max run time for bash scripts */

/* Unified Status Codes */
typedef enum {
    STATUS_OK = 0,
    STATUS_ERR_NETWORK,
    STATUS_ERR_BAD_PAYLOAD,
    STATUS_ERR_CRYPTO_FAIL,
    STATUS_ERR_EXEC_FAIL,
    STATUS_ERR_INTERNAL
} server_status_t;

/* Server Configuration */
typedef struct {
    const char *uds_path;   /* UNIX Domain Socket path (e.g., /tmp/sec_server.sock) */
    const char *tcp_port;   /* TCP Port (e.g., "8080") */
    const char *cert_dir;   /* Path to code-signing certificates */
} server_config_t;

/* Starts the main server loop. Blocks indefinitely. */
int start_server(const server_config_t *config);

#endif /* SERVER_H */