/**
 * Description : 
 *
 * @date 2021/01/21
 * @author FINL Chain Team
 * @version 1.0
 */

#include "global.hpp"

//
uint32_t openssl_aes_cbc_encrypt(const uint8_t *plaintext, int32_t plaintext_len, uint8_t *key, uint8_t *iv, uint8_t *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        //openssl_handleErrors();
        return (0);
    }

    /* Initialise the encryption operation. IMPORTANT - ensure you use a key
    * and IV size appropriate for your cipher
    * In this example we are using 256 bit AES (i.e. a 256 bit key). The
    * IV size for *most* modes is the same as the block size. For AES this
    * is 128 bits */
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    {
        //openssl_handleErrors();
        return (0);
    }

    /* Provide the message to be encrypted, and obtain the encrypted output.
    * EVP_EncryptUpdate can be called multiple times if necessary
    */
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    {
        //openssl_handleErrors();
        return (0);
    }

    ciphertext_len = len;

    /* Finalise the encryption. Further ciphertext bytes may be written at
    * this stage.
    */
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
    {
        //openssl_handleErrors();
        return (0);
    }

    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

uint32_t openssl_aes_cbc_decrypt(const uint8_t *ciphertext, int32_t ciphertext_len, uint8_t *key, uint8_t *iv, uint8_t *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;
    int plaintext_len;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        //openssl_handleErrors();
        return (0);
    }

    /* Initialise the decryption operation. IMPORTANT - ensure you use a key
    * and IV size appropriate for your cipher
    * In this example we are using 256 bit AES (i.e. a 256 bit key). The
    * IV size for *most* modes is the same as the block size. For AES this
    * is 128 bits */
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    {
        //openssl_handleErrors();
        return (0);
    }

    /* Provide the message to be decrypted, and obtain the plaintext output.
    * EVP_DecryptUpdate can be called multiple times if necessary
    */
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    {
        //openssl_handleErrors();
        return (0);
    }

    plaintext_len = len;

    /* Finalise the decryption. Further plaintext bytes may be written at
    * this stage.
    */
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
    {
        //openssl_handleErrors();
        return (0);
    }

    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

//
int32_t openssl_aes_encrypt_pw(char *p_seed_path, uint8_t *p_pw, uint32_t pw_len, char *p_dst_path)
{
    int32_t ret = ERROR_;

    uint8_t *p_seed, *p_enc;
    uint32_t seed_len, enc_len;

    uint8_t hash[HASH_SIZE];
    uint8_t *p_key;
    uint8_t *p_iv;
    
    DBG_PRINT(DBG_UTIL, DBG_TRACE, (void *)"(%s)\n",  __FUNCTION__);

    // Seed
    p_seed = (uint8_t *)util_file_r(p_seed_path, &seed_len);
    if (!p_seed)
    {
        return (ret);
    }

    DBG_PRINT(DBG_UTIL, DBG_INFO, (void *)"seed_len: %d\n", seed_len);
    DBG_PRINT(DBG_UTIL, DBG_INFO, (void *)"seed : %s\n", p_seed);

    // // Password
    DBG_PRINT(DBG_UTIL, DBG_INFO, (void *)"pw_len: %d\n", pw_len);
    DBG_PRINT(DBG_UTIL, DBG_INFO, (void *)"pw : %s\n", p_pw);

    // Key & IV
    openssl_sha256(hash, (uint8_t *)p_seed, seed_len);
    p_key = &hash[0];
    p_iv = &hash[OPENSSL_SYM_KEY_LEN];

    // Encryption
    enc_len = pw_len + AES_BLOCK_SIZE;
    p_enc = (uint8_t *)MALLOC_M(enc_len);
    MEMSET_M(p_enc, 0, enc_len);

    enc_len = openssl_aes_cbc_encrypt((uint8_t *)p_pw, pw_len, p_key, p_iv, p_enc);
    DBG_DUMP(DBG_UTIL, DBG_INFO, (void *) "file enc", (uint8_t *)p_enc, enc_len);

    // Write File
    util_hex_file_wb(p_dst_path, p_enc, enc_len);

	FREE_M(p_seed);
    FREE_M(p_enc);

    ret = SUCCESS_;

    return (ret);
}

//
uint8_t *openssl_aes_decrypt_pw(char *p_seed_path, char *p_src_path, uint32_t *p_pw_len)
{
    uint8_t *p_seed, *p_enc, *p_pw = NULL;
    uint32_t seed_len, enc_len;
    char seed_path_def[] = "../conf/pw/db/me/seed";
    char src_path_def[] = "../conf/pw/db/me/pw_maria.fin";

    uint8_t hash[HASH_SIZE];
    uint8_t *p_key;
    uint8_t *p_iv;

    DBG_PRINT(DBG_UTIL, DBG_TRACE, (void *)"(%s)\n",  __FUNCTION__);

    *p_pw_len = 0;

    if (!p_seed_path)
    {
        p_seed_path = seed_path_def;
    }

    if (!p_src_path)
    {
        p_src_path = src_path_def;
    }
    
    // Seed
    p_seed = (uint8_t *)util_file_r(p_seed_path, &seed_len);
    if (!p_seed)
    {
        return (NULL);
    }

    DBG_PRINT(DBG_UTIL, DBG_INFO, (void *)"seed_len: %d\n", seed_len);
    DBG_PRINT(DBG_UTIL, DBG_INFO, (void *)"seed : %s\n", p_seed);
    DBG_PRINT(DBG_UTIL, DBG_INFO, (void *)"p_src_path : %s\n", p_src_path);
    // Read Encryption
    p_enc = (uint8_t *)util_hex_file_rb(p_src_path, &enc_len);

    DBG_DUMP(DBG_UTIL, DBG_INFO, (void *) "file enc", (uint8_t *)p_enc, enc_len);

    openssl_sha256(hash, (uint8_t *)p_seed, seed_len);
    p_key = &hash[0];
    p_iv = &hash[OPENSSL_SYM_KEY_LEN];

    *p_pw_len = enc_len + 1;
    p_pw = (uint8_t *)MALLOC_M(*p_pw_len);
    MEMSET_M(p_pw, 0x00, *p_pw_len);

    *p_pw_len = openssl_aes_cbc_decrypt(p_enc, enc_len, p_key, p_iv, p_pw);
    p_pw[*p_pw_len] = 0x00;
    DBG_PRINT(DBG_UTIL, DBG_INFO, (void *)"pw_len: %d\n", *p_pw_len);
    DBG_PRINT(DBG_UTIL, DBG_INFO, (void *)"%s\n", p_pw);
    DBG_DUMP(DBG_UTIL, DBG_INFO, (void *) "aes_dec", (uint8_t *)p_pw, *p_pw_len);

    p_pw[*p_pw_len] = '\0';

    FREE_M(p_enc);
    FREE_M(p_seed);

    return (p_pw);
}

int32_t openssl_aes_encrpt_file(char *p_src_path, char *p_dst_path, uint8_t *p_seed, uint32_t seed_len)
{
    int32_t ret = ERROR_;

    uint8_t *p_plane, *p_enc;
    uint32_t plane_len, enc_len;

    uint8_t hash[HASH_SIZE];
    uint8_t *p_key;
    uint8_t *p_iv;
    
    DBG_PRINT(DBG_UTIL, DBG_TRACE, (void *)"(%s)\n",  __FUNCTION__);

    p_plane = (uint8_t *)util_file_r(p_src_path, &plane_len);

    DBG_PRINT(DBG_UTIL, DBG_INFO, (void *)"plane_len: %d\n", plane_len);
    DBG_PRINT(DBG_UTIL, DBG_INFO, (void *)"%s\n", p_plane);
    DBG_DUMP(DBG_UTIL, DBG_INFO, (void *) "file plane", (uint8_t *)p_plane, plane_len);

    openssl_sha256(hash, (uint8_t *)p_seed, seed_len);
    p_key = &hash[0];
    p_iv = &hash[OPENSSL_SYM_KEY_LEN];

    enc_len = plane_len + 1 + AES_BLOCK_SIZE;
    p_enc = (uint8_t *)MALLOC_M(enc_len);
    MEMSET_M(p_enc, 0, enc_len);
    
    enc_len = openssl_aes_cbc_encrypt(p_plane, plane_len, p_key, p_iv, p_enc);
    DBG_DUMP(DBG_UTIL, DBG_INFO, (void *) "file enc", (uint8_t *)p_enc, enc_len);

    util_hex_file_wb(p_dst_path, p_enc, enc_len);

    FREE_M(p_plane);
    FREE_M(p_enc);

    ret = SUCCESS_;

    return (ret);
}

uint8_t *openssl_aes_decrypt_file(char *p_src_path, uint8_t *p_seed, uint32_t seed_len)
{
    uint8_t *p_plane, *p_enc;
    uint32_t plane_len, enc_len;

    uint8_t hash[HASH_SIZE];
    uint8_t *p_key;
    uint8_t *p_iv;

    DBG_PRINT(DBG_UTIL, DBG_TRACE, (void *)"(%s)\n",  __FUNCTION__);

    p_enc = (uint8_t *)util_hex_file_rb(p_src_path, &enc_len);

    DBG_DUMP(DBG_UTIL, DBG_INFO, (void *) "file enc", (uint8_t *)p_enc, enc_len);

    openssl_sha256(hash, (uint8_t *)p_seed, seed_len);
    p_key = &hash[0];
    p_iv = &hash[OPENSSL_SYM_KEY_LEN];

    plane_len = enc_len + 1;
    // plane_len = enc_len + 60;
    p_plane = (uint8_t *)MALLOC_M(plane_len);
    MEMSET_M(p_plane, 0x00, plane_len);

    plane_len = openssl_aes_cbc_decrypt(p_enc, enc_len, p_key, p_iv, p_plane);
    p_plane[plane_len] = 0x00;
    DBG_PRINT(DBG_UTIL, DBG_INFO, (void *)"plane_len : %d\n", plane_len);
    DBG_PRINT(DBG_UTIL, DBG_INFO, (void *)"%s\n", p_plane);
    DBG_DUMP(DBG_UTIL, DBG_INFO, (void *) "aes_dec", (uint8_t *)p_plane, plane_len);

    FREE_M(p_enc);

    if (!plane_len)
    {
        FREE_M(p_plane);

        p_plane = NULL;
    }

    return (p_plane);
}

uint8_t *openssl_aes_decrypt_binary(uint8_t *p_enc, uint32_t enc_len, uint8_t *p_seed, uint32_t seed_len)
{
    uint8_t *p_plane;//, *p_enc;
    uint32_t plane_len;//, enc_len;

    uint8_t hash[HASH_SIZE];
    uint8_t *p_key;
    uint8_t *p_iv;

    DBG_PRINT(DBG_UTIL, DBG_TRACE, (void *)"(%s)\n",  __FUNCTION__);

    // p_enc = (uint8_t *)util_hex_file_rb(p_src_path, &enc_len);

    DBG_DUMP(DBG_UTIL, DBG_INFO, (void *) "file enc", (uint8_t *)p_enc, enc_len);

    openssl_sha256(hash, (uint8_t *)p_seed, seed_len);
    p_key = &hash[0];
    p_iv = &hash[OPENSSL_SYM_KEY_LEN];

    plane_len = enc_len + 1;
    p_plane = (uint8_t *)MALLOC_M(plane_len);
    MEMSET_M(p_plane, 0x00, plane_len);

    plane_len = openssl_aes_cbc_decrypt(p_enc, enc_len, p_key, p_iv, p_plane);
    p_plane[plane_len] = 0x00;
    DBG_PRINT(DBG_UTIL, DBG_INFO, (void *)"plane_len: %d\n", plane_len);
    DBG_PRINT(DBG_UTIL, DBG_INFO, (void *)"%s\n", p_plane);
    DBG_DUMP(DBG_UTIL, DBG_INFO, (void *) "aes_dec", (uint8_t *)p_plane, plane_len);

    // FREE_M(p_enc);

    if (!plane_len)
    {
        FREE_M(p_plane);

        p_plane = NULL;
    }

    return (p_plane);
}
