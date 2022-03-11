#include "global.hpp"

//
uint32_t sec_aes_256_cbc_encrypt(const uint8_t *p_plaintext, uint32_t plaintext_len, const uint8_t *p_seed, uint32_t seed_len, uint8_t *p_ciphertext)
{
    uint32_t ciphertext_len = 0;
    uint8_t hash[HASH_SIZE];

    uint8_t *p_key;
    uint8_t *p_iv;

    openssl_sha256(hash, (uint8_t *)p_seed, seed_len);

    p_key = &hash[0];
    p_iv = &hash[OPENSSL_SYM_KEY_LEN];

    //
    ciphertext_len = aes_cbc_encrypt (p_plaintext, plaintext_len, p_key, p_iv, p_ciphertext);
    // ciphertext_len = openssl_aes_cbc_encrypt(p_plaintext, plaintext_len, p_key, p_iv, p_ciphertext);
    DBG_DUMP(DBG_UTIL, DBG_INFO, (void *) "aes cbc enc", (uint8_t *)p_ciphertext, ciphertext_len);

    return (ciphertext_len);
}

//
uint32_t sec_aes_256_cbc_decrypt(const uint8_t *p_ciphertext, uint32_t ciphertext_len, const uint8_t *p_seed, uint32_t seed_len, uint8_t *p_plaintext)
{
    uint32_t plaintext_len = 0;
    uint8_t hash[HASH_SIZE];

    uint8_t *p_key;
    uint8_t *p_iv;

    openssl_sha256(hash, (uint8_t *)p_seed, seed_len);

    p_key = &hash[0];
    p_iv = &hash[OPENSSL_SYM_KEY_LEN];

    //
    plaintext_len = aes_cbc_decrypt(p_ciphertext, ciphertext_len, p_key, p_iv, p_plaintext);
    // plaintext_len = openssl_aes_cbc_decrypt(p_ciphertext, ciphertext_len, p_key, p_iv, p_plaintext);
    DBG_DUMP(DBG_UTIL, DBG_INFO, (void *) "aes dec dec", (uint8_t *)p_plaintext, plaintext_len);

    return (plaintext_len);
}

//
uint32_t sec_aria_encrypt(const uint8_t *p_plaintext, uint32_t plaintext_len, const uint8_t *p_seed, uint32_t seed_len, uint8_t *p_ciphertext)
{
    uint32_t ciphertext_len = 0;
    uint8_t hash[HASH_SIZE];

    uint8_t *p_key;
    uint32_t Nr = 16;

    openssl_sha256(hash, (uint8_t *)p_seed, seed_len);

    p_key = &hash[0];

    //
    aria_enc(p_key, HASH_SIZE, Nr, (uint8_t *)p_plaintext, plaintext_len, p_ciphertext, &ciphertext_len);
    DBG_DUMP(DBG_UTIL, DBG_INFO, (void *) "aria enc", (uint8_t *)p_ciphertext, ciphertext_len);

    return (ciphertext_len);
}

//
uint32_t sec_aria_decrypt(const uint8_t *p_ciphertext, uint32_t ciphertext_len, const uint8_t *p_seed, uint32_t seed_len, uint8_t *p_plaintext)
{
    uint32_t plaintext_len = 0;
    uint8_t hash[HASH_SIZE];

    uint8_t *p_key;
    uint32_t Nr = 16;

    openssl_sha256(hash, (uint8_t *)p_seed, seed_len);

    p_key = &hash[0];

    //
    aria_dec(p_key, HASH_SIZE, Nr, (uint8_t *)p_ciphertext, ciphertext_len, p_plaintext, &plaintext_len);
    DBG_DUMP(DBG_UTIL, DBG_INFO, (void *) "aria dec", (uint8_t *)p_plaintext, plaintext_len);

    return (plaintext_len);
}
