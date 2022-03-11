/**
 * Description : 
 *
 * @date 2021/01/21
 * @author FINL Chain Team
 * @version 1.0
 */

#ifndef __OPENSSL_ECDSA_HPP__
#define __OPENSSL_ECDSA_HPP__

#ifdef __cplusplus
extern "C"
{
#endif

//
extern EVP_PKEY *openssl_get_ec_pkey(char *p_prikey_str, int32_t ec_algo) ;

//
extern int32_t openssl_ecdsa_sig(EVP_PKEY *p_pkey, uint8_t *p_data, uint32_t data_len, SSL_SIG_U *p_sig_hex);
extern int32_t openssl_ecdsa_verify(uint8_t *p_data, uint32_t data_len, SSL_SIG_U *p_sig_hex, uint8_t *p_comp_pubkey, int32_t ec_algo);

#ifdef __cplusplus
}
#endif

#endif	// __OPENSSL_ECDSA_HPP__
