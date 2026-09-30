#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/types.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/crypto.h>

#include "crypto.h"

/* The opaque context struct defined in crypto.h */
struct crypto_ctx_t {
    STACK_OF(X509) *valid_certs;
};

/* --------------------------------------------------------------------------
 * Internal Helper: Validate X.509 Certificate 
 * Checks validity period and codeSigning Extended Key Usage (EKU).
 * -------------------------------------------------------------------------- */
static int is_cert_valid_for_codesigning(X509 *cert) {
    if (!cert) return 0;

    /* 1. Check validity period (Not Before / Not After) against current time */
    if (X509_cmp_current_time(X509_get0_notBefore(cert)) >= 0) {
        fprintf(stderr, "[!] Cert is not yet valid.\n");    // LCOV_EXCL_LINE
        return 0;                                           // LCOV_EXCL_LINE
    }
    if (X509_cmp_current_time(X509_get0_notAfter(cert)) <= 0) {
        fprintf(stderr, "[!] Cert is expired.\n");          // LCOV_EXCL_LINE
        return 0;                                           // LCOV_EXCL_LINE
    }

    /* 2. Check Extended Key Usage for codeSigning (Stretch Goal 1) */
    EXTENDED_KEY_USAGE *eku = X509_get_ext_d2i(cert, NID_ext_key_usage, NULL, NULL);
    if (!eku) {
        fprintf(stderr, "[!] Cert lacks Extended Key Usage extensions.\n");
        return 0;
    }

    int has_codesign = 0;
    for (int i = 0; i < sk_ASN1_OBJECT_num(eku); i++) {
        ASN1_OBJECT *obj = sk_ASN1_OBJECT_value(eku, i);
        if (OBJ_obj2nid(obj) == NID_code_sign) {
            has_codesign = 1;
            break;
        }
    }
    
    EXTENDED_KEY_USAGE_free(eku);
    return has_codesign;
}

/* --------------------------------------------------------------------------
 * Internal Helper: Base64 Decode
 * Decodes a null-terminated base64 string into raw binary.
 * -------------------------------------------------------------------------- */
static int decode_base64(const char *b64_str, unsigned char **out_buf, size_t *out_len) {
    size_t len = strlen(b64_str);
    
    /* A safe buffer size estimation for base64 */
    *out_buf = malloc(len);
    if (!*out_buf) return 0;    // LCOV_EXCL_LINE

    EVP_ENCODE_CTX *b64_ctx = EVP_ENCODE_CTX_new();
    if (!b64_ctx) {
        free(*out_buf);         // LCOV_EXCL_LINE
        return 0;               // LCOV_EXCL_LINE
    }

    EVP_DecodeInit(b64_ctx);
    
    int outl = 0;
    int tmpl = 0;
    
    /* Cast len to int for OpenSSL API */
    if (EVP_DecodeUpdate(b64_ctx, *out_buf, &outl, (const unsigned char*)b64_str, (int)len) < 0) {
        EVP_ENCODE_CTX_free(b64_ctx);
        free(*out_buf);
        return 0;
    }
    
    EVP_DecodeFinal(b64_ctx, *out_buf + outl, &tmpl);
    
    /* Explicitly cast to size_t to resolve the -Wconversion error safely */
    *out_len = (size_t)outl + (size_t)tmpl;
    
    EVP_ENCODE_CTX_free(b64_ctx);
    return 1;
}

/* --------------------------------------------------------------------------
 * Public API: crypto_init
 * -------------------------------------------------------------------------- */
crypto_ctx_t* crypto_init(const char *cert_dir) {
    DIR *dir = opendir(cert_dir);
    if (!dir) {
        perror("[-] Failed to open certificates directory");
        return NULL;
    }

    crypto_ctx_t *ctx = malloc(sizeof(crypto_ctx_t));
    if (!ctx) {
        closedir(dir);
        return NULL;
    }

    ctx->valid_certs = sk_X509_new_null();

    struct dirent *entry;
    char filepath[1024];

    fprintf(stdout, "[*] Scanning directory '%s' for valid Code Signing certificates...\n", cert_dir);

    /* Iterate over the directory (Stretch Goal 3) */
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type != DT_REG && entry->d_type != DT_LNK) continue;

        snprintf(filepath, sizeof(filepath), "%s/%s", cert_dir, entry->d_name);

        FILE *fp = fopen(filepath, "r");
        if (!fp) continue;

        X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
        fclose(fp);

        if (cert) {
            if (is_cert_valid_for_codesigning(cert)) {
                /* Cert is valid and has codeSigning EKU */
                sk_X509_push(ctx->valid_certs, cert);
                
                char *subj = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
                fprintf(stdout, " [+] Loaded Valid Cert: %s\n", subj);
                OPENSSL_free(subj);
            } else {
                fprintf(stdout, " [!] Ignored invalid/unauthorized cert: %s\n", entry->d_name);
                X509_free(cert); /* Discard immediately to save memory */
            }
        }
    }
    
    closedir(dir);

    if (sk_X509_num(ctx->valid_certs) == 0) {
        fprintf(stderr, "[-] No valid code-signing certificates found in %s\n", cert_dir);
        crypto_cleanup(ctx);
        return NULL;
    }

    return ctx;
}

/* --------------------------------------------------------------------------
 * Public API: crypto_verify_signature
 * -------------------------------------------------------------------------- */
server_status_t crypto_verify_signature(crypto_ctx_t *ctx, 
                                        const unsigned char *payload, 
                                        size_t payload_len, 
                                        const char *base64_sig) {
    if (!ctx || !payload || !base64_sig) return STATUS_ERR_INTERNAL;

    unsigned char *raw_sig = NULL;
    size_t raw_sig_len = 0;

    if (!decode_base64(base64_sig, &raw_sig, &raw_sig_len)) {
        fprintf(stderr, "[-] Failed to decode Base64 signature.\n");
        return STATUS_ERR_CRYPTO_FAIL;
    }

    int verified = 0;
    int num_certs = sk_X509_num(ctx->valid_certs);

    /* Try verifying the payload against every loaded valid code-signing cert */
    for (int i = 0; i < num_certs; i++) {
        X509 *cert = sk_X509_value(ctx->valid_certs, i);
        EVP_PKEY *pubkey = X509_get0_pubkey(cert); /* Get public key without incrementing ref count */
        
        if (!pubkey) continue;

        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        if (!mdctx) continue;

        /* OpenSSL 3.x EVP API: Initialize, Update, Final */
        if (EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pubkey) == 1) {
            if (EVP_DigestVerifyUpdate(mdctx, payload, payload_len) == 1) {
                if (EVP_DigestVerifyFinal(mdctx, raw_sig, raw_sig_len) == 1) {
                    verified = 1;
                }
            }
        }
        
        EVP_MD_CTX_free(mdctx);

        if (verified) {
            char *subj = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
            fprintf(stdout, "[*] Signature verified successfully using cert: %s\n", subj);
            OPENSSL_free(subj);
            break; /* Stop checking further certs */
        }
    }

    /* Securely wipe the signature from memory before freeing */
    OPENSSL_cleanse(raw_sig, raw_sig_len);
    free(raw_sig);

    return verified ? STATUS_OK : STATUS_ERR_CRYPTO_FAIL;
}

/* --------------------------------------------------------------------------
 * Public API: crypto_cleanup
 * -------------------------------------------------------------------------- */
void crypto_cleanup(crypto_ctx_t *ctx) {
    if (ctx) {
        if (ctx->valid_certs) {
            /* Frees the stack AND calls X509_free on every certificate within */
            sk_X509_pop_free(ctx->valid_certs, X509_free);
        }
        
        /* Wipe the context pointer itself */
        OPENSSL_cleanse(ctx, sizeof(crypto_ctx_t));
        free(ctx);
    }
}