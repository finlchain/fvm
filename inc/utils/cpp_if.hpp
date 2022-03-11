/**
 * Description : 
 *
 * @date 2021/01/21
 * @author FINL Chain Team
 * @version 1.0
 */

#include "global.hpp"

#ifndef __CPP_IF_HPP__
#define __CPP_IF_HPP__

#define STR_ERROR_ "error"

#ifdef __cplusplus
extern "C"
{
#endif

//

#ifdef __cplusplus
    }
#endif

//
extern std::string curl_http_get_proc(std::string url, std::string fields);
extern std::string curl_http_post_proc(std::string url, std::string fields);

//
extern int32_t openssl_ec_keygen_with_mnemonic_proc(std::string path, int32_t ec_algo, std::string pw, std::string mnemonic1, std::string mnemonic2, uint32_t rand_num);
extern int32_t openssl_ec_keygen_with_mnemonic_ori_proc(std::string path, int32_t ec_algo, std::string mnemonic1, std::string pw);
extern int32_t openssl_ec_keygen_proc(std::string path, int32_t ec_algo);
//
extern std::string openssl_ecdsa_sig_hex(std::string prikey, std::string data, int32_t ec_algo);
extern std::string openssl_ecdsa_sig_pem(bool b_enc, std::string prikey_path, std::string data);
extern int32_t openssl_ecdsa_verify_hex(std::string data, std::string sig_r, std::string sig_s, std::string comp_pubkey, int32_t ec_algo);

//
extern std::string openssl_ec_prikey_pem2hex_proc(bool b_enc, std::string prikey_path);
extern std::string openssl_ec_pubkey_pem2hex_proc(std::string pubkey_path, int32_t ec_algo);

//
extern std::string openssl_ed_prikey_pemstr2hex_proc(std::string pem_str);

//
extern std::string openssl_ed_prikey_pem2hex_proc(bool b_enc, std::string prikey_path);
extern std::string openssl_ed_pubkey_pem2hex_proc(std::string pubkey_path);

//
extern int32_t openssl_ed25519_keygen_proc(std::string path);
extern int32_t openssl_ed25519_keygen_pubkey_proc(std::string path);
extern int32_t openssl_ed25519_keygen_fin_with_mnemonic_proc(std::string path, std::string pw, std::string mnemonic1, std::string mnemonic2, uint32_t rand_num, std::string seed, uint32_t seed_len);
extern int32_t openssl_ed25519_keygen_fin_with_mnemonic_ori_proc(std::string path, std::string mnemonic1, std::string pw, std::string seed, uint32_t seed_len);
extern int32_t openssl_ed25519_keygen_fin_proc(std::string path, std::string seed, uint32_t seed_len);

//
extern std::string openssl_ed25519_sig_hex(std::string prikey, std::string data);
extern std::string openssl_ed25519_sig_pem(bool b_enc, std::string prikey_path, std::string data);
extern int32_t openssl_ed25519_verify_hex(std::string data, std::string signature, std::string pubkey);
extern int ed_verify();

//
extern std::string openssl_sha256_hex(std::string data);
extern std::string openssl_sha256_str(std::string data);

//
extern int32_t openssl_ed25519_keygen_with_mnemonic_proc(std::string path, std::string pw, std::string mnemonic1, std::string mnemonic2, uint32_t rand_num);
extern int32_t openssl_ed25519_keygen_with_mnemonic_ori_proc(std::string path, std::string mnemonic1, std::string pw);

//
extern int32_t openssl_x25519_keygen_with_mnemonic_proc(std::string path, std::string pw, std::string mnemonic1, std::string mnemonic2, uint32_t rand_num);
extern int32_t openssl_x25519_keygen_with_mnemonic_ori_proc(std::string path, std::string mnemonic1, std::string pw);
extern int32_t openssl_x25519_keygen_proc(std::string path);

//
extern std::string openssl_x25519_hex_skey(std::string prikey_hex, std::string peer_pubkey_hex);
extern std::string openssl_x25519_pem_skey(std::string prikey_pem, std::string peer_pubkey_pem);
extern std::string openssl_x25519_mix_skey(std::string prikey_pem, std::string peer_pubkey_hex);

//
extern std::string openssl_x25519_hex_enc(std::string prikey, std::string peer_pubkey, std::string plaintext_str, uint32_t plaintext_str_len);
extern std::string openssl_x25519_hex_dec(std::string prikey_hex, std::string peer_pubkey_hex, std::string enc_msg_str, uint32_t enc_msg_str_len);
extern std::string openssl_x25519_pem_enc(std::string prikey_pem, std::string peer_pubkey_pem, std::string plaintext_hex, uint32_t plaintext_hex_len);
extern std::string openssl_x25519_pem_dec(std::string prikey_pem, std::string peer_pubkey_pem, std::string enc_msg_str, uint32_t enc_msg_str_len);
extern std::string openssl_x25519_mix_enc(std::string prikey_pem, std::string peer_pubkey_hex, std::string plaintext_str, uint32_t plaintext_hex_len);
extern std::string openssl_x25519_mix_dec(std::string prikey_pem, std::string peer_pubkey_hex, std::string enc_msg_str, uint32_t enc_msg_str_len);

//
extern int32_t openssl_aes_encrypt_pw_proc(std::string p_seed_path, std::string p_pw, uint32_t pw_len, std::string p_dst_path);
extern uint8_t *openssl_aes_decrypt_pw_proc(std::string p_seed_path, std::string p_src_path);
extern int32_t openssl_aes_encrypt_file_proc(std::string src_path, std::string dst_path, std::string seed, uint32_t sed_len);
extern uint8_t *openssl_aes_decrypt_file_proc(std::string src_path, std::string seed, uint32_t seed_len);
extern uint8_t *openssl_aes_decrypt_binary_proc(std::string enc_hex_str, uint32_t enc_len, std::string seed, uint32_t seed_len);

//
extern std::string sec_aes_256_cbc_encrypt_proc(std::string plain_hex_str, uint32_t plain_hex_len, std::string seed, uint32_t seed_len, uint32_t *p_ciphertext_len);
extern std::string sec_aes_256_cbc_decrypt_proc(std::string ciphertext_hex_str, uint32_t ciphertext_hex_len, std::string seed, uint32_t seed_len, uint32_t *p_plaintext_len);

//
extern std::string sec_aria_encrypt_proc(std::string plain_hex_str, uint32_t plain_hex_len, std::string seed, uint32_t seed_len, uint32_t *p_ciphertext_len);
extern std::string sec_aria_decrypt_proc(std::string ciphertext_hex_str, uint32_t ciphertext_hex_len, std::string seed, uint32_t seed_len, uint32_t *p_plaintext_len);


//
extern int32_t x25519_test(void);

//
extern std::string cstombs_str(char *p_new_locale, char *p_str);
extern uint32_t key_create_master_str(std::string pw, std::string mnemonic1, std::string mnemonic2);
extern std::string key_restore_master_str(std::string pw, std::string mnemonic1, std::string mnemonic2, uint32_t rand_num);
extern uint32_t key_create_master_ori_str(std::string mnemonic1, std::string pw);
extern std::string key_restore_master_ori_str(std::string mnemonic1, std::string pw);

#endif	// __CPP_IF_HPP__
