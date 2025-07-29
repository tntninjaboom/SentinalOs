#ifndef _CRYPTO_H
#define _CRYPTO_H

#include <stdint.h>
#include <stddef.h>

/* AES-256 Configuration */
#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE   32  /* 256 bits */
#define AES_ROUNDS     14

/* Crypto context */
struct aes_context {
    uint32_t round_keys[4 * (AES_ROUNDS + 1)];
    uint8_t iv[AES_BLOCK_SIZE];
    bool initialized;
};

/* Pentagon-Level Security Features */
struct security_context {
    uint8_t classification_level;  /* 0=Unclassified, 4=Pentagon */
    uint32_t security_flags;
    uint64_t session_id;
    uint8_t user_clearance;
    char source_system[32];
    char dest_system[32];
};

/* Security flags */
#define SEC_FLAG_ENCRYPTED    (1 << 0)
#define SEC_FLAG_AUTHENTICATED (1 << 1)
#define SEC_FLAG_LOGGED       (1 << 2)
#define SEC_FLAG_VERIFIED     (1 << 3)

/* Function prototypes */
int aes_init(struct aes_context *ctx, const uint8_t *key, const uint8_t *iv);
void aes_cleanup(struct aes_context *ctx);

int aes_encrypt_block(struct aes_context *ctx, const uint8_t *plaintext, uint8_t *ciphertext);
int aes_decrypt_block(struct aes_context *ctx, const uint8_t *ciphertext, uint8_t *plaintext);

int aes_encrypt_cbc(struct aes_context *ctx, const uint8_t *plaintext, size_t len, uint8_t *ciphertext);
int aes_decrypt_cbc(struct aes_context *ctx, const uint8_t *ciphertext, size_t len, uint8_t *plaintext);

/* Key derivation */
int derive_key_from_password(const char *password, const uint8_t *salt, uint8_t *key);
int generate_random_iv(uint8_t *iv);
int generate_random_salt(uint8_t *salt, size_t len);

/* Security functions */
int create_security_context(struct security_context *ctx, uint8_t classification, const char *source, const char *dest);
int verify_security_clearance(const struct security_context *ctx, uint8_t user_clearance);
int audit_log_operation(const struct security_context *ctx, const char *operation, const char *details);

/* Secure memory functions */
void secure_memset(void *ptr, int value, size_t len);
int secure_compare(const void *a, const void *b, size_t len);

#endif /* _CRYPTO_H */