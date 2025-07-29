/*
 * AES-256 Cryptographic Implementation for SentinalOS
 * Pentagon-Level Security Encryption
 */

#include "crypto.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

/* AES S-box */
static const uint8_t sbox[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

/* AES inverse S-box */
static const uint8_t inv_sbox[256] = {
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

/* Round constants */
static const uint8_t rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

/* Utility functions */
static uint32_t sub_word(uint32_t word) {
    return (sbox[word >> 24] << 24) |
           (sbox[(word >> 16) & 0xFF] << 16) |
           (sbox[(word >> 8) & 0xFF] << 8) |
           sbox[word & 0xFF];
}

static uint32_t rot_word(uint32_t word) {
    return (word << 8) | (word >> 24);
}

static void add_round_key(uint8_t *state, const uint32_t *round_key) {
    for (int i = 0; i < 4; i++) {
        uint32_t key = round_key[i];
        state[i * 4 + 0] ^= (key >> 24) & 0xFF;
        state[i * 4 + 1] ^= (key >> 16) & 0xFF;
        state[i * 4 + 2] ^= (key >> 8) & 0xFF;
        state[i * 4 + 3] ^= key & 0xFF;
    }
}

static void sub_bytes(uint8_t *state) {
    for (int i = 0; i < 16; i++) {
        state[i] = sbox[state[i]];
    }
}

static void inv_sub_bytes(uint8_t *state) {
    for (int i = 0; i < 16; i++) {
        state[i] = inv_sbox[state[i]];
    }
}

static void shift_rows(uint8_t *state) {
    uint8_t temp;
    
    /* Row 1: shift left by 1 */
    temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;
    
    /* Row 2: shift left by 2 */
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;
    
    /* Row 3: shift left by 3 */
    temp = state[3];
    state[3] = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = temp;
}

static uint8_t xtime(uint8_t x) {
    return (x << 1) ^ (((x >> 7) & 1) * 0x1B);
}

static void mix_columns(uint8_t *state) {
    for (int i = 0; i < 4; i++) {
        uint8_t *col = state + i * 4;
        uint8_t a[4];
        uint8_t b[4];
        
        memcpy(a, col, 4);
        for (int j = 0; j < 4; j++) {
            b[j] = xtime(a[j]);
        }
        
        col[0] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1];
        col[1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2];
        col[2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3];
        col[3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0];
    }
}

/* Key expansion */
static void key_expansion(const uint8_t *key, uint32_t *round_keys) {
    /* Copy original key */
    for (int i = 0; i < 8; i++) {
        round_keys[i] = (key[i * 4] << 24) |
                       (key[i * 4 + 1] << 16) |
                       (key[i * 4 + 2] << 8) |
                       key[i * 4 + 3];
    }
    
    /* Generate remaining round keys */
    for (int i = 8; i < 4 * (AES_ROUNDS + 1); i++) {
        uint32_t temp = round_keys[i - 1];
        
        if (i % 8 == 0) {
            temp = sub_word(rot_word(temp)) ^ (rcon[i / 8] << 24);
        } else if (i % 8 == 4) {
            temp = sub_word(temp);
        }
        
        round_keys[i] = round_keys[i - 8] ^ temp;
    }
}

/* Initialize AES context */
int aes_init(struct aes_context *ctx, const uint8_t *key, const uint8_t *iv) {
    if (!ctx || !key) {
        return -1;
    }
    
    /* Clear context */
    secure_memset(ctx, 0, sizeof(struct aes_context));
    
    /* Expand key */
    key_expansion(key, ctx->round_keys);
    
    /* Copy IV if provided */
    if (iv) {
        memcpy(ctx->iv, iv, AES_BLOCK_SIZE);
    }
    
    ctx->initialized = true;
    return 0;
}

/* Cleanup AES context */
void aes_cleanup(struct aes_context *ctx) {
    if (ctx) {
        secure_memset(ctx, 0, sizeof(struct aes_context));
    }
}

/* Encrypt single block */
int aes_encrypt_block(struct aes_context *ctx, const uint8_t *plaintext, uint8_t *ciphertext) {
    if (!ctx || !ctx->initialized || !plaintext || !ciphertext) {
        return -1;
    }
    
    uint8_t state[16];
    memcpy(state, plaintext, 16);
    
    /* Initial round */
    add_round_key(state, &ctx->round_keys[0]);
    
    /* Main rounds */
    for (int round = 1; round < AES_ROUNDS; round++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, &ctx->round_keys[round * 4]);
    }
    
    /* Final round */
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, &ctx->round_keys[AES_ROUNDS * 4]);
    
    memcpy(ciphertext, state, 16);
    secure_memset(state, 0, 16);
    
    return 0;
}

/* Encrypt using CBC mode */
int aes_encrypt_cbc(struct aes_context *ctx, const uint8_t *plaintext, size_t len, uint8_t *ciphertext) {
    if (!ctx || !plaintext || !ciphertext || len % AES_BLOCK_SIZE != 0) {
        return -1;
    }
    
    uint8_t prev_block[AES_BLOCK_SIZE];
    memcpy(prev_block, ctx->iv, AES_BLOCK_SIZE);
    
    for (size_t i = 0; i < len; i += AES_BLOCK_SIZE) {
        uint8_t block[AES_BLOCK_SIZE];
        
        /* XOR with previous ciphertext (or IV) */
        for (int j = 0; j < AES_BLOCK_SIZE; j++) {
            block[j] = plaintext[i + j] ^ prev_block[j];
        }
        
        /* Encrypt block */
        if (aes_encrypt_block(ctx, block, &ciphertext[i]) != 0) {
            return -1;
        }
        
        /* Update previous block */
        memcpy(prev_block, &ciphertext[i], AES_BLOCK_SIZE);
    }
    
    return 0;
}

/* Generate random IV */
int generate_random_iv(uint8_t *iv) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return -1;
    }
    
    ssize_t bytes_read = read(fd, iv, AES_BLOCK_SIZE);
    close(fd);
    
    return (bytes_read == AES_BLOCK_SIZE) ? 0 : -1;
}

/* Secure memory operations */
void secure_memset(void *ptr, int value, size_t len) {
    volatile uint8_t *p = (volatile uint8_t*)ptr;
    while (len--) {
        *p++ = value;
    }
}

int secure_compare(const void *a, const void *b, size_t len) {
    const uint8_t *pa = (const uint8_t*)a;
    const uint8_t *pb = (const uint8_t*)b;
    uint8_t result = 0;
    
    for (size_t i = 0; i < len; i++) {
        result |= pa[i] ^ pb[i];
    }
    
    return result;
}

/* Security context functions */
int create_security_context(struct security_context *ctx, uint8_t classification, const char *source, const char *dest) {
    if (!ctx || !source || !dest) {
        return -1;
    }
    
    secure_memset(ctx, 0, sizeof(struct security_context));
    
    ctx->classification_level = classification;
    ctx->security_flags = SEC_FLAG_ENCRYPTED | SEC_FLAG_AUTHENTICATED | SEC_FLAG_LOGGED;
    ctx->session_id = rand() ^ (rand() << 16);
    
    strncpy(ctx->source_system, source, sizeof(ctx->source_system) - 1);
    strncpy(ctx->dest_system, dest, sizeof(ctx->dest_system) - 1);
    
    return 0;
}

int verify_security_clearance(const struct security_context *ctx, uint8_t user_clearance) {
    if (!ctx) {
        return -1;
    }
    
    /* Pentagon security model: user must have clearance >= classification */
    return (user_clearance >= ctx->classification_level) ? 0 : -1;
}

/* PBKDF2 Key Derivation */
int derive_key_from_password(const char *password, const uint8_t *salt, uint8_t *key) {
    if (!password || !salt || !key) {
        return -1;
    }
    
    /* Simple key derivation - in production, use proper PBKDF2 */
    size_t pass_len = strlen(password);
    uint8_t hash[32];
    
    /* Initialize with salt */
    memcpy(hash, salt, 16);
    memset(hash + 16, 0, 16);
    
    /* Mix password */
    for (size_t i = 0; i < pass_len; i++) {
        hash[i % 32] ^= password[i];
    }
    
    /* Simple rounds */
    for (int round = 0; round < 1000; round++) {
        for (int i = 0; i < 32; i++) {
            hash[i] = hash[i] ^ hash[(i + 1) % 32] ^ (round & 0xFF);
        }
    }
    
    memcpy(key, hash, 32);
    secure_memset(hash, 0, sizeof(hash));
    
    return 0;
}

int generate_random_salt(uint8_t *salt, size_t len) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return -1;
    }
    
    ssize_t bytes_read = read(fd, salt, len);
    close(fd);
    
    return (bytes_read == (ssize_t)len) ? 0 : -1;
}

int audit_log_operation(const struct security_context *ctx, const char *operation, const char *details) {
    if (!ctx || !operation) {
        return -1;
    }
    
    /* Log to system log */
    printf("[AUDIT] Classification: %d, Operation: %s, Details: %s\n",
           ctx->classification_level, operation, details ? details : "none");
    
    return 0;
}