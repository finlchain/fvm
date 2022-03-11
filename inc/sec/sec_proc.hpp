/**
 * Description : 
 *
 * @date 2021/01/21
 * @author FINL Chain Team
 * @version 1.0
 */

#ifndef __SEC_PROC_HPP__
#define __SEC_PROC_HPP__

#ifndef __cplusplus
#error Do not include the hpp header in a c project!
#endif //__cplusplus

#ifdef __cplusplus
extern "C"
{
#endif


//
uint32_t sec_aes_256_cbc_encrypt(const uint8_t *p_plaintext, uint32_t plaintext_len, const uint8_t *p_seed, uint32_t seed_len, uint8_t *p_ciphertext);
uint32_t sec_aes_256_cbc_decrypt(const uint8_t *p_ciphertext, uint32_t ciphertext_len, const uint8_t *p_seed, uint32_t seed_len, uint8_t *p_plaintext);

//
uint32_t sec_aria_encrypt(const uint8_t *p_plaintext, uint32_t plaintext_len, const uint8_t *p_seed, uint32_t seed_len, uint8_t *p_ciphertext);
uint32_t sec_aria_decrypt(const uint8_t *p_ciphertext, uint32_t ciphertext_len, const uint8_t *p_seed, uint32_t seed_len, uint8_t *p_plaintext);

#ifdef __cplusplus
}
#endif

#endif // __SEC_PROC_HPP__
