/**
 * Description : 
 *
 * @date 2021/01/21
 * @author FINL Chain Team
 * @version 1.0
 */

#ifndef __OPENSSL_ED_HPP__
#define __OPENSSL_ED_HPP__

#ifdef __cplusplus
extern "C"
{
#endif

//
extern int32_t openssl_ed_prikey_pemstr2hex(char *p_pem_str, uint8_t *p_prikey);

//
extern int32_t openssl_ed_prikey_pem2hex(bool b_enc, char *p_prikey_path, uint8_t *p_prikey);
extern int32_t openssl_ed_pubkey_pem2hex(char *p_pubkey_path, uint8_t *p_pubkey);
extern int32_t openssl_ed_pubkey_hex2pem(char *p_pubkey_path, uint8_t *p_pubkey);

#if (OPENSSL_111 == ENABLED)
extern int32_t openssl_get_25519_prikey(EVP_PKEY *p_pkey, uint8_t *p_prikey);
extern int32_t openssl_get_25519_pubkey(EVP_PKEY *p_pkey, uint8_t *p_pubkey);
extern int32_t openssl_111_25519_keygen_with_prikey(char *p_path, char *p_prikey, int32_t type);
extern int32_t openssl_111_25519_keygen(char *p_path, int32_t type);
extern int32_t openssl_111_25519_keygen_pubkey(char *p_path, int32_t type);
extern int32_t openssl_111_25519_keygen_fin_with_prikey(char *p_path, char *p_prikey, int32_t type, uint8_t *p_seed, uint32_t seed_len);
extern int32_t openssl_111_25519_keygen_fin(char *p_path, int32_t type, uint8_t *p_seed, uint32_t seed_len);
#endif // OPENSSL_111

//
extern int32_t openssl_ed25519_keygen_with_prikey(char *p_path, char *p_prikey);
extern int32_t openssl_ed25519_keygen(char *p_path);

//
extern int32_t openssl_ed25519_keygen_pubkey(char *p_path);

//
extern int32_t openssl_ed25519_keygen_fin_with_prikey(char *p_path, char *p_prikey, uint8_t *p_seed, uint32_t seed_len);
extern int32_t openssl_ed25519_keygen_fin(char *p_path, uint8_t *p_seed, uint32_t seed_len);

#ifdef __cplusplus
}
#endif

#endif	// __OPENSSL_ED_HPP__
