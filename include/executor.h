#ifndef EXECUTOR_H
#define EXECUTOR_H

#include <stddef.h>
#include "server.h"

/* ==========================================================================
 * Sandbox Constraints (Dev vs. Prod Profiles)
 * ========================================================================== */
#ifdef ENV_PRODUCTION
    /* Strict FIPS/Prod Limits: Minimal resources for isolated daemon user */
    #define LIMIT_NPROC      64
    #define LIMIT_MEM_BYTES  (128 * 1024 * 1024) /* 128 MB */
    #define LIMIT_CPU_SEC    5                   /* 5 seconds max */
#else
    /* Developer Limits: Generous resources for laptop testing */
    #define LIMIT_NPROC      2048
    #define LIMIT_MEM_BYTES  (256 * 1024 * 1024) /* 256 MB */
    #define LIMIT_CPU_SEC    10                  /* 10 seconds max */
#endif

/**
 * Securely executes the verified bash script entirely in memory.
 * Redirects the stdout/stderr of the bash process directly into the client socket.
 *
 * @param client_fd The active network socket connection to the client.
 * @param req_id A unique request identifier for concurrency tracing.
 * @param payload The verified bash script content.
 * @param payload_len Length of the script.
 * @return STATUS_OK on successful execution, or an error code on failure.
 */
server_status_t execute_script(int client_fd, 
                               const char *req_id, 
                               const char *payload, 
                               size_t payload_len);

#endif /* EXECUTOR_H */