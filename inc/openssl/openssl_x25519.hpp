/**
 * Description : 
 *
 * @date 2021/01/21
 * @author FINL Chain Team
 * @version 1.0
 */

#ifndef __OPENSSL_X25519_HPP__
#define __OPENSSL_X25519_HPP__

#ifdef __cplusplus
extern "C"
{
#endif

#define X25519_TEST ENABLED // ENABLED DISABLED

#define X25519_AES_USE ENABLED // ENABLED DISABLED
#define X25519_ARIA_USE DISABLED // ENABLED DISABLED

#define OPENSSL_X25519_MAC_LEN 32
#define OPENSSL_EDIES_P2_LEN 8

#if (OPENSSL_111 == ENABLED)
extern uint8_t *openssl_111_x25519(const EVP_PKEY *p_prikey, const EVP_PKEY *p_peer_pubkey);
#endif // OPENSSL_111

//
extern int32_t openssl_x25519_sharedkey(
#if (OPENSSL_111 == ENABLED)
                                const EVP_PKEY *p_prikey, const EVP_PKEY *p_peer_pubkey, 
#elif (OPENSSL_102 == ENABLED)
                                const uint8_t *p_prikey, const uint8_t *p_peer_pubkey, 
#endif // OPENSSL_111
                                uint8_t *p_sharedkey);

//
extern int32_t openssl_x25519_aes_encrypt(
#if (OPENSSL_111 == ENABLED)
                                const EVP_PKEY *p_prikey, const EVP_PKEY *p_peer_pubkey, 
#elif (OPENSSL_102 == ENABLED)
                                const uint8_t *p_prikey, const uint8_t *p_peer_pubkey, 
#endif // OPENSSL_111
                                const uint8_t *p_p1, uint32_t p1_len, const uint8_t *p_p2, uint32_t p2_len, 
                                const uint8_t *p_plaintext, uint32_t plaintext_len, uint8_t *p_enc_msg, uint32_t *p_enc_msg_len);

extern int32_t openssl_x25519_aes_decrypt(
#if (OPENSSL_111 == ENABLED)
                                const EVP_PKEY *p_prikey, const EVP_PKEY *p_peer_pubkey, 
#elif (OPENSSL_102 == ENABLED)
                                const uint8_t *p_prikey, const uint8_t *p_peer_pubkey, 
#endif // OPENSSL_111
                                const uint8_t *p_p1, uint32_t p1_len, const uint8_t *p_p2, uint32_t p2_len, 
                                const uint8_t *p_ciphertext, uint32_t ciphertext_len, uint8_t *p_cipher_mac, 
                                uint8_t *p_plaintext, uint32_t *p_plaintext_len);

//
extern int32_t openssl_x25519_aria_encrypt(
#if (OPENSSL_111 == ENABLED)
                                const EVP_PKEY *p_prikey, const EVP_PKEY *p_peer_pubkey, 
#elif (OPENSSL_102 == ENABLED)
                                const uint8_t *p_prikey, const uint8_t *p_peer_pubkey, 
#endif // OPENSSL_111
                                uint32_t Nr, const uint8_t *p_plaintext, uint32_t plaintext_len, uint8_t *p_ciphertext, uint32_t *p_ciphertext_len);

extern int32_t openssl_x25519_aria_decrypt(
#if (OPENSSL_111 == ENABLED)
                                const EVP_PKEY *p_prikey, const EVP_PKEY *p_peer_pubkey, 
#elif (OPENSSL_102 == ENABLED)
                                const uint8_t *p_prikey, const uint8_t *p_peer_pubkey, 
#endif // OPENSSL_111
                                uint32_t Nr, const uint8_t *p_ciphertext, uint32_t ciphertext_len, uint8_t *p_plaintext, uint32_t *p_plaintext_len);

//
extern int32_t openssl_x25519_keygen_with_prikey(char *p_path, char *p_prikey);
extern int32_t openssl_x25519_keygen(char *p_path);

#if (X25519_TEST == ENABLED)
extern int32_t openssl_x25519_key_test(void);
extern int32_t openssl_x25519_test(void);
#endif // X25519_TEST

#ifdef __cplusplus
}
#endif

#endif	// __OPENSSL_X25519_HPP__
