/**
 * Description : 
 *
 * @date 2021/01/21
 * @author FINL Chain Team
 * @version 1.0
 */

#ifndef __KEY_HPP__
#define __KEY_HPP__

#ifndef __cplusplus
#error Do not include the hpp header in a c project!
#endif //__cplusplus

#ifdef __cplusplus
extern "C"
{
#endif

//
#define SEED_RAND_NUM_LEN 2

#define SALT_SIZE (HASH_SIZE * 2)
#define SALT_STR_SIZE (SALT_SIZE * 2 + 1)

//
extern void crt_wcstombs_test(void);
extern void crt_mbstowcs_test(void);

//
extern int32_t key_fip39_seed(char *p_pw, int32_t pw_len, char *p_salt, int32_t salt_len, uint32_t *p_rand_num, char *p_seed);
extern int32_t key_fip32_master(char *p_seed, int32_t seed_len);
extern int32_t key_master(char *p_pw_str, char *p_mnemonic1_str, char *p_mnemonic2_str, uint32_t *p_rand_num, uint8_t *p_chain_code);

//
extern int32_t key_fip39_seed_ori(char *p_pw, int32_t pw_len, char *p_salt, int32_t salt_len, char *p_seed);
extern int32_t key_master_ori(char *p_mnemonic1_str, char *p_salt_str, uint8_t *p_chain_code);

#ifdef __cplusplus
}
#endif

#endif //__KEY_HPP__
