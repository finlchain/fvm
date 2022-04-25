/**
 * Description : 
 *
 * @date 2021/01/21
 * @author FINL Chain Team
 * @version 1.0
 */

#ifndef __OPENSSL_UTIL_HPP__
#define __OPENSSL_UTIL_HPP__

#ifdef __cplusplus
extern "C"
{
#endif

//
#define OPENSSL_102    DISABLED // ENABLED DISABLED
#define OPENSSL_111    ENABLED // ENABLED DISABLED

//
#define PBKDF2_HMAC_SHA_1_MAX_SIZE   20
#define PBKDF2_HMAC_SHA_384_MAX_SIZE 48
#define PBKDF2_HMAC_SHA_512_MAX_SIZE 64

#define PBKDF2_HMAC_SHA_1_MAX_STR_SIZE      (PBKDF2_HMAC_SHA_1_MAX_SIZE*2+1)
#define PBKDF2_HMAC_SHA_384_MAX_STR_SIZE    (PBKDF2_HMAC_SHA_384_MAX_SIZE*2+1)
#define PBKDF2_HMAC_SHA_512_MAX_STR_SIZE    (PBKDF2_HMAC_SHA_512_MAX_SIZE*2+1)

//
#define HMAC_SHA_256_MAX_SIZE 32
#define HMAC_SHA_512_MAX_SIZE 64

//
#define SECP256R1 NID_X9_62_prime256v1
#define SECP256K1 NID_secp256k1
#define ED25519    NID_ED25519
#define X25519     NID_X25519

//
#define SSL_PATH_SIZE 100

//
#define SSL_VERIFY_SUCCESS 1
#define SSL_VERIFY_INCORRECT 0
#define SSL_VERIFY_ERROR -1

//
#define HASH_SIZE           32
#define HASH_STR_SIZE       (HASH_SIZE*2+1)

// EC    
#define SIG_SIZE        64
#define SIG_STR_SIZE    (SIG_SIZE*2+1)
    
#define SIG_R_SIZE      32
#define SIG_S_SIZE      32
    
#define SIG_R_STR_SIZE (SIG_R_SIZE*2+1)
#define SIG_S_STR_SIZE (SIG_S_SIZE*2+1)

#define PRIKEY_SIZE         32
#define COMP_PUBKEY_SIZE    33
#define UNCOMP_PUBKEY_SIZE  65

#define PRIKEY_STR_SIZE (PRIKEY_SIZE*2+1)
    
#define COMP_PUBKEY_STR_SIZE    (COMP_PUBKEY_SIZE*2+1)
#define UNCOMP_PUBKEY_STR_SIZE  (UNCOMP_PUBKEY_SIZE*2+1)

// ED
#define X25519_PRIVATE_KEY_LEN_ 32
#define X25519_PUBLIC_KEY_LEN_ 32
#define X25519_SHARED_KEY_LEN_ 32

#define ED25519_PRIVATE_KEY_LEN_ 64
#define ED25519_PUBLIC_KEY_LEN_ 32
#define ED25519_SIGNATURE_LEN_ 64
////////////////////////////////////////

//
#define PUBKEY_DELIMITER_EC_COMP_EVEN   0x02
#define PUBKEY_DELIMITER_EC_COMP_ODD    0x03
#define PUBKEY_DELIMITER_EC_UNCOMP      0x04
#define PUBKEY_DELIMITER_25519          0x05 // Defined by ourself.

typedef union
{
    struct
    {
        uint8_t r[SIG_R_SIZE];
        uint8_t s[SIG_S_SIZE];
    } ec;
    uint8_t sig[SIG_SIZE];
} __PACK__ SSL_SIG_U;

//
extern int32_t openssl_sha256(uint8_t *hash, uint8_t *data, uint32_t data_len);
extern void pbkdf2_hmac_sha512(const char* pass, int32_t pass_len, const uint8_t *salt, int32_t salt_len, int iterations, unsigned int outputBytes, char* hexResult, uint8_t *binResult);

//
extern char *BN_bn2hex_z(const BIGNUM *a);

//
extern EVP_PKEY *EVP_PKEY_new_read_PRIKEY_pem_str(char *p_pem_str);
extern EVP_PKEY *EVP_PKEY_new_read_PUBKEY_pem_str(char *p_pem_str);
//
extern EVP_PKEY *EVP_PKEY_new_read_PRIKEY_pem(bool b_enc, char *p_prikey_path);
extern EVP_PKEY *EVP_PKEY_new_read_PUBKEY_pem(char *p_pubkey_path);
extern EVP_PKEY *EVP_PKEY_new_read_PRIKEY_pem_no_file(bool b_enc, char *p_prikey_raw);
extern EVP_PKEY *EVP_PKEY_new_read_PUBKEY_pem_no_file(char *p_pubkey_raw);
extern EVP_PKEY *EVP_PKEY_new_read_PRIKEY_hex(char *p_prikey, int32_t ec_algo);
extern EVP_PKEY *EVP_PKEY_new_read_PUBKEY_hex(char *p_pubkey, int32_t ec_algo);

//
extern EVP_PKEY *openssl_get_pkey(bool b_enc, char *p_prikey_path);

//
extern int32_t PEM_new_write_PUBKEY(char *p_pubkey_path, EVP_PKEY *pkey);
extern int32_t PEM_new_write_PRIKEY(char *p_prikey_path, EVP_PKEY *pkey);

//
extern int32_t PEM_write_raw_PUBKEY(char *p_pubkey_path, uint8_t *p_pubkey, int32_t ec_algo);

//
extern int openssl_kdf2(const EVP_MD *md, const uint8_t *p_share, uint32_t share_len, const uint8_t *p_kdp, size_t kdp_len, uint32_t key_len, uint8_t *p_key);

#ifdef __cplusplus
}
#endif

#endif	// __OPENSSL_UTIL_HPP__
