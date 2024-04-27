/**
 * @file "simple_crypto.c"
 * @author Ben Janis
 * @brief Simplified Crypto API Implementation
 * @date 2024
 *
 * This source file is part of an example system for MITRE's 2024 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2024 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2024 The MITRE Corporation
 */



#include "simple_crypto.h"
#include <stdint.h>
#include <string.h>

/******************************** FUNCTION PROTOTYPES ********************************/
/** @brief Encrypts plaintext using a symmetric cipher
 *
 * @param plaintext A pointer to a buffer of length len containing the
 *          plaintext to encrypt
 * @param len The length of the plaintext to encrypt. Must be a multiple of
 *          BLOCK_SIZE (16 bytes)
 * @param key A pointer to a buffer of length KEY_SIZE (16 bytes) containing
 *          the key to use for encryption
 * @param ciphertext A pointer to a buffer of length len where the resulting
 *          ciphertext will be written to
 *
 * @return 0 on success, -1 on bad length, other non-zero for other error
 */

int encrypt_sym(uint8_t *plaintext, size_t len, uint8_t *key, uint8_t *ciphertext) {
    if (plaintext == NULL || key == NULL || ciphertext == NULL)
        return -1;

    Aes ctx; // Context for encryption
    int result; // Library result

    // Ensure valid length
    if (len == 0 || len % BLOCK_SIZE)
        return -1;

    // Set the key for encryption
    result = wc_AesSetKey(&ctx, key, KEY_SIZE, NULL, AES_ENCRYPTION);
    if (result != 0)
        return result; // Report error

    // Encrypt using CBC mode
    for (size_t i = 0; i < len - BLOCK_SIZE; i += BLOCK_SIZE) {
        // XOR with the previous ciphertext block for CBC
        for (size_t j = 0; j < BLOCK_SIZE; ++j) {
            plaintext[i + j] ^= ciphertext[i + j];
        }

        result = wc_AesEncryptDirect(&ctx, ciphertext + i, plaintext + i);
        if (result != 0)
            return result; // Report error
    }

    memset(&ctx, 0, sizeof(ctx));

    return 0;
}

/** @brief Decrypts ciphertext using a symmetric cipher
 *
 * @param ciphertext A pointer to a buffer of length len containing the
 *          ciphertext to decrypt
 * @param len The length of the ciphertext to decrypt. Must be a multiple of
 *          BLOCK_SIZE (16 bytes)
 * @param key A pointer to a buffer of length KEY_SIZE (16 bytes) containing
 *          the key to use for decryption
 * @param plaintext A pointer to a buffer of length len where the resulting
 *          plaintext will be written to
 *
 * @return 0 on success, -1 on bad length, other non-zero for other error
 */

int decrypt_sym(uint8_t *ciphertext, size_t len, uint8_t *key, uint8_t *plaintext) {
    Aes ctx; // Context for decryption
    int result; // Library result

    // Ensure valid length
    if (len <= 0 || len % BLOCK_SIZE)
        return -1;

    // Set the key for decryption
    result = wc_AesSetKey(&ctx, key, KEY_SIZE, NULL, AES_DECRYPTION);
    if (result != 0)
        return result; // Report error

    // Decrypt each block
    for (size_t i = 0; i < len - BLOCK_SIZE; i += BLOCK_SIZE) {
        result = wc_AesDecryptDirect(&ctx, plaintext + i, ciphertext + i);
        if (result != 0)
            return result; // Report error

        // XOR with the previous ciphertext block for CBC
        for (size_t j = 0; j < BLOCK_SIZE; ++j) {
            plaintext[i + j] ^= (i == 0) ? 0 : ciphertext[i - BLOCK_SIZE + j];
        }
    }

    // Clear the context
    memset(&ctx, 0, sizeof(ctx));

    return 0;
}

/** @brief Hashes arbitrary-length data
 *
 * @param data A pointer to a buffer of length len containing the data
 *          to be hashed
 * @param len The length of the plaintext to encrypt
 * @param hash_out A pointer to a buffer of length HASH_SIZE (16 bytes) where the resulting
 *          hash output will be written to
 *
 * @return 0 on success, non-zero for other error
 */
int hash(void *data, size_t len, uint8_t *hash_out) {
    // Pass values to hash
    Sha256 sha;
    int ret;

    wc_InitSha256(&sha); //Initialize the Sha256 encryption.
    wc_Sha256Update(&sha, (byte*)data, len); //update the hash
    ret = wc_Sha256Final(&sha, hash_out); // Finalize the hash placing the result into hash argument.
    return ret; //Retains functionality of original method with new hashing.
}


