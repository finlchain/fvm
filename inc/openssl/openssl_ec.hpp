/**
 * Description : 
 *
 * @date 2021/01/21
 * @author FINL Chain Team
 * @version 1.0
 */

#ifndef __OPENSSL_EC_HPP__
#define __OPENSSL_EC_HPP__

#ifdef __cplusplus
extern "C"
{
#endif

//
extern ECDSA_SIG *ECDSA_SIG_new_raw_SIG(SSL_SIG_U *p_sig_hex);
extern EC_KEY *EC_KEY_new_raw_PUBKEY(uint8_t *p_pubkey, int32_t ec_algo);

//
extern int32_t openssl_ec_prikey_pem2hex(bool b_enc, char *p_prikey_path, uint8_t *p_prikey);
extern int32_t openssl_ec_pubkey_hex2pem(char *p_pubkey_path, uint8_t *p_pubkey, int32_t ec_algo);
extern int32_t openssl_ec_pubkey_pem2hex(char *p_pubkey_path, uint8_t *p_pubkey, int32_t ec_algo);

//
extern int32_t openssl_ec_key_gen_with_prikey(char *p_path, int32_t ec_algo, char *p_prikey_str);
extern int32_t openssl_ec_key_gen(char *p_path, int32_t ec_algo);

//
extern int32_t openssl_ec_pubkey_decompress(char *p_comp_pubkey, char *p_uncomp_pubkey, int32_t ec_algo);
extern int32_t openssl_ec_pubkey_compress(char *p_uncomp_pubkey, char *p_comp_pubkey, int32_t ec_algo);

#ifdef __cplusplus
}
#endif

#endif	// __OPENSSL_EC_HPP__
