/**
 * Description : 
 *
 * @date 2021/01/21
 * @author FINL Chain Team
 * @version 1.0
 */

#include <cstdlib>
#include <cstring>
#include <iostream>

#ifndef __OPENSSL_AES_HPP__
#define __OPENSSL_AES_HPP__

#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/evp.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define AES_SEED_PATH getenv("F_PW_SEED_PATH")
#define NODE_JS_NULL "null"

#define HASH_SIZE 32
#define OPENSSL_SYM_KEY_LEN 16

//
extern uint32_t openssl_aes_cbc_encrypt(const uint8_t *plaintext, int32_t plaintext_len, uint8_t *key, uint8_t *iv, uint8_t *ciphertext);
extern uint32_t openssl_aes_cbc_decrypt(const uint8_t *ciphertext, int32_t ciphertext_len, uint8_t *key, uint8_t *iv, uint8_t *plaintext);

//
extern int32_t openssl_aes_encrypt_pw(char *p_seed_path, uint8_t *p_pw, uint32_t pw_len, char *p_dst_path);
extern uint8_t *openssl_aes_decrypt_pw(char *p_seed_path, char *p_src_path, uint32_t *p_pw_len);

//
extern int32_t openssl_aes_encrpt_file(char *p_src_path, char *p_dst_path, uint8_t *p_seed, uint32_t seed_len);
extern uint8_t *openssl_aes_decrypt_file(char *p_src_path, uint8_t *p_seed, uint32_t seed_len);

extern uint8_t *openssl_aes_decrypt_binary(uint8_t *p_enc, uint32_t enc_len, uint8_t *p_seed, uint32_t seed_len);

#ifdef __cplusplus
}
#endif

#endif	// __OPENSSL_AES_HPP__
