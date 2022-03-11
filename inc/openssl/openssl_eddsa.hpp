/**
 * Description : 
 *
 * @date 2021/01/21
 * @author FINL Chain Team
 * @version 1.0
 */

#ifndef __OPENSSL_EDDSA_HPP__
#define __OPENSSL_EDDSA_HPP__

#ifdef __cplusplus
extern "C"
{
#endif

//
extern int32_t openssl_111_ed25519_sig(EVP_PKEY *p_pkey, uint8_t *p_data, uint32_t data_len, SSL_SIG_U *p_sig_hex);
extern int32_t openssl_ed25519_verify(uint8_t *p_data, uint32_t data_len, SSL_SIG_U *p_sig_hex, uint8_t *p_pubkey);

#ifdef __cplusplus
}
#endif

#endif	// __OPENSSL_EDDSA_HPP__
