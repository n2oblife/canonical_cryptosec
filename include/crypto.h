#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>
#include "server.h"

/* Opaque context holding the OpenSSL X509 Store */
typedef struct crypto_ctx_t crypto_ctx_t;

/**
 * Initializes the cryptography subsystem.
 * Scans cert_dir, validates X.509 codeSigning EKUs, and loads them into memory.
 * 
 * @param cert_dir Path to the trusted certificates directory.
 * @return A pointer to the crypto context, or NULL on fatal error.
 */
crypto_ctx_t* crypto_init(const char *cert_dir);

/**
 * Verifies a payload against the trusted certificates in the context.
 * 
 * @param ctx The initialized crypto context.
 * @param payload The raw bash script content (from Line 2 to EOF).
 * @param payload_len The length of the payload in bytes.
 * @param base64_sig The Base64 encoded ECDSA signature extracted from Line 1.
 * @return STATUS_OK on success, or STATUS_ERR_CRYPTO_FAIL on rejection.
 */
server_status_t crypto_verify_signature(crypto_ctx_t *ctx, 
                                        const unsigned char *payload, 
                                        size_t payload_len, 
                                        const char *base64_sig);

/**
 * Safely frees the cryptography context and wipes associated memory.
 */
void crypto_cleanup(crypto_ctx_t *ctx);

#endif /* CRYPTO_H */