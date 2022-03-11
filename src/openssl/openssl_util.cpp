/**
 * Description : 
 *
 * @date 2021/01/21
 * @author FINL Chain Team
 * @version 1.0
 */

#include "global.hpp"

//
int32_t openssl_sha256(uint8_t *hash, uint8_t *data, uint32_t data_len)
{
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data, data_len);
    SHA256_Final(hash, &sha256);

    return (SUCCESS_);
}

//
void pbkdf2_hmac_sha512(const char* pass, int32_t pass_len, const uint8_t *salt, int32_t salt_len, int iterations, unsigned int outputBytes, char* hexResult, uint8_t *binResult)
{
	unsigned int i;
	unsigned char digest[PBKDF2_HMAC_SHA_512_MAX_SIZE];
	memset(digest, 0, PBKDF2_HMAC_SHA_512_MAX_SIZE);

	PKCS5_PBKDF2_HMAC(pass, pass_len, salt, salt_len, iterations, EVP_sha512(), outputBytes, digest);
	for (i = 0; i < sizeof(digest); i++)
	{
		sprintf(hexResult + (i * 2), "%02X", 255 & digest[i]);
		binResult[i] = digest[i];
	}
}

#if (OPENSSL_111 == ENABLED)
struct bignum_st {
    BN_ULONG *d;                /* Pointer to an array of 'BN_BITS2' bit
                                 * chunks. */
    int top;                    /* Index of last used d +1. */
    /* The next are internal book keeping for bn_expand. */
    int dmax;                   /* Size of the d array. */
    int neg;                    /* one if the number is negative */
    int flags;
};
#endif // OPENSSL_111

//
char *BN_bn2hex_z(const BIGNUM *a)
{
    int i, j, v, z = 1;
    char *buf;
    char *p;
    
    static const char Hex_z[] = "0123456789ABCDEF";

    //DBG_PRINT(DBG_UTIL, DBG_INFO, (void *)"a->top(%d)\n", a->top);

    if (BN_is_zero(a))
        return OPENSSL_strdup("0");
#if (OPENSSL_111 == ENABLED)
    buf = (char *)OPENSSL_malloc((size_t)(a->top * BN_BYTES * 2 + 2));
#elif (OPENSSL_102 == ENABLED)
    buf = (char *)OPENSSL_malloc(a->top * BN_BYTES * 2 + 2);
#endif // OPENSSL_111
    if (buf == NULL) {
        BNerr(BN_F_BN_BN2HEX, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    p = buf;
    if (a->neg)
    {
#if (OPENSSL_111 == ENABLED)
        *p++ = '-';
#elif (OPENSSL_102 == ENABLED)
        *(p++) = '-';
#endif // OPENSSL_111
    }
    if (BN_is_zero(a))
    {
#if (OPENSSL_111 == ENABLED)
        *p++ = '0';
#elif (OPENSSL_102 == ENABLED)
        *(p++) = '0';
#endif // OPENSSL_111
    }
    for (i = a->top - 1; i >= 0; i--) {
        for (j = BN_BITS2 - 8; j >= 0; j -= 8) {
            /* strip leading zeros */
#if (OPENSSL_111 == ENABLED)
            v = (int)((a->d[i] >> j) & 0xff);
            if (z || v != 0) {
                *p++ = Hex_z[v >> 4];
                *p++ = Hex_z[v & 0x0f];
                z = 1;
#elif (OPENSSL_102 == ENABLED)
            v = ((int)(a->d[i] >> (long)j)) & 0xff;
            //DBG_PRINT(DBG_UTIL, DBG_INFO, (void *)"z(%d) v(0x%02X)\n", z, v);
            if (z || (v != 0)) {
                *(p++) = Hex_z[v >> 4];
                *(p++) = Hex_z[v & 0x0f];
                z = 1;
#endif // OPENSSL_111
            }
        }
    }
    *p = '\0';
 err:
    return (buf);
}

//
EVP_PKEY *EVP_PKEY_new_read_PRIKEY_pem_str(char *p_pem_str)
{
    EVP_PKEY *p_pkey = NULL;
    
    if (p_pem_str)
    {
        BIO *pri_b = BIO_new_mem_buf((void*)p_pem_str, STRLEN_M((char *)p_pem_str));

        if (pri_b)
        {
            p_pkey = PEM_read_bio_PrivateKey(pri_b, NULL, NULL, NULL);

            BIO_free(pri_b);
        }
    }
	else
	{
		return (NULL);
	}

    return (p_pkey);
}

//
EVP_PKEY *EVP_PKEY_new_read_PRIKEY_pem(bool b_enc, char *p_prikey_path)
{
    EVP_PKEY *p_pkey = NULL;
    
    if (!b_enc)
    {
        FILE* fp;
        
        fp = fopen (p_prikey_path, "r");
        if (fp)
        {
            
            p_pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);

            fclose(fp);
        }
    }
	else
	{
		return (NULL);
	}

    return (p_pkey);
}

EVP_PKEY *EVP_PKEY_new_read_PUBKEY_pem(char *p_pubkey_path)
{
    EVP_PKEY *p_pkey = NULL;
    FILE *fp;

    fp= fopen(p_pubkey_path, "r");
    if(fp)
    {
        p_pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
        
        fclose(fp);
    }
    
    return (p_pkey);
}

EVP_PKEY *EVP_PKEY_new_read_PRIKEY_hex(char *p_prikey, int32_t ec_algo)
{
    EVP_PKEY *p_pkey = NULL;
    size_t keyLen = X25519_PRIVATE_KEY_LEN_;

    if (ec_algo == ED25519)
    {
        keyLen = X25519_PRIVATE_KEY_LEN_;
    }
    else if (ec_algo == X25519)
    {
        keyLen = X25519_PRIVATE_KEY_LEN_;
    }
    else if ((ec_algo == SECP256R1) || (ec_algo == SECP256K1))
    {
        keyLen = PRIKEY_SIZE;
    }
    else
    {
        return (NULL);
    }
    
    p_pkey = EVP_PKEY_new_raw_private_key(ec_algo, NULL, (uint8_t *)p_prikey, keyLen);

	// EVP_PKEY_free(p_pkey);
	
    return (p_pkey);
}

EVP_PKEY *EVP_PKEY_new_read_PUBKEY_hex(char *p_pubkey, int32_t ec_algo)
{
    EVP_PKEY *p_pkey = NULL;
    size_t keyLen = X25519_PUBLIC_KEY_LEN_;

    if (ec_algo == ED25519)
    {
        keyLen = X25519_PUBLIC_KEY_LEN_;
    }
    else if (ec_algo == X25519)
    {
        keyLen = X25519_PUBLIC_KEY_LEN_;
    }
    else if ((ec_algo == SECP256R1) || (ec_algo == SECP256K1))
    {
        keyLen = UNCOMP_PUBKEY_SIZE;
    }
    else
    {
        return (NULL);
    }
    
    p_pkey = EVP_PKEY_new_raw_public_key(ec_algo, NULL, (uint8_t *)p_pubkey, keyLen);

    return (p_pkey);
}

//
EVP_PKEY *openssl_get_pkey(bool b_enc, char *p_prikey_path)
{
    EVP_PKEY *p_pkey = NULL;

    DBG_PRINT(DBG_UTIL, DBG_TRACE, (void *)"(%s)\n",  __FUNCTION__);

    p_pkey = EVP_PKEY_new_read_PRIKEY_pem(b_enc, p_prikey_path);
    if (!p_pkey)
    {
        DBG_PRINT(DBG_UTIL, DBG_ERROR, (void *)"ERROR : prikey parse\n");
        return (NULL);
    }
    //

    return (p_pkey);
}

////////////////////////////////////////////////
// Pem Write
//
int32_t PEM_new_write_PUBKEY(char *p_pubkey_path, EVP_PKEY *pkey)
{
    int32_t ret = ERROR_;
    FILE* fp;
    
    fp = fopen(p_pubkey_path, "w");
    if(!fp) return (ERROR_);

#if 1
    PEM_write_PUBKEY(fp, pkey);
    ret = SUCCESS_;
#else
    do
    {
        BIO *p_outbio = NULL;
        p_outbio = BIO_new_fp(fp, BIO_NOCLOSE);
        
        if (p_outbio)
        {
            if(!PEM_write_bio_PUBKEY(p_outbio, pkey))
            {
                DBG_PRINT(DBG_UTIL, DBG_ERROR, (void *)"Error writing public key data in PEM format\n");
                break;
            }

            ret = SUCCESS_;
            
            BIO_free(p_outbio);
        }
    } while(0);
#endif

    fclose(fp);

    return (ret);
}

int32_t PEM_new_write_PRIKEY(char *p_prikey_path, EVP_PKEY *pkey)
{
    FILE* fp;
    
    fp = fopen(p_prikey_path, "w");
    if(!fp) return (ERROR_);
    
    PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, 0, NULL);
    fclose(fp);
    
    return (SUCCESS_);
}

//
int32_t PEM_write_raw_PUBKEY(char *p_pubkey_path, uint8_t *p_pubkey, int32_t ec_algo)
{
    int32_t ret = ERROR_;
    
    DBG_PRINT(DBG_UTIL, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);
    DBG_PRINT(DBG_UTIL, DBG_INFO, (void *)"p_pubkey_path (%s)\n", p_pubkey_path);

    if(p_pubkey[0] == PUBKEY_DELIMITER_25519) // 25519
    {
        uint8_t *p_ed_pubkey;

        p_ed_pubkey = &p_pubkey[1];
        ret = openssl_ed_pubkey_hex2pem(p_pubkey_path, (uint8_t *)p_ed_pubkey);
    }
    else if(p_pubkey[0] == PUBKEY_DELIMITER_EC_UNCOMP) // EC Uncompress
    {
        ret = openssl_ec_pubkey_hex2pem(p_pubkey_path, (uint8_t *)p_pubkey, ec_algo);
    }
    else if(p_pubkey[0] == PUBKEY_DELIMITER_EC_UNCOMP || p_pubkey[0] == PUBKEY_DELIMITER_EC_COMP_EVEN || p_pubkey[0] == PUBKEY_DELIMITER_EC_COMP_ODD)
    {
        char comp_pubkey_str[COMP_PUBKEY_STR_SIZE];
        char uncomp_pubkey_str[UNCOMP_PUBKEY_STR_SIZE];
        char uncomp_pubkey[UNCOMP_PUBKEY_SIZE];
        
        util_hex2str_temp(p_pubkey, COMP_PUBKEY_SIZE, comp_pubkey_str, COMP_PUBKEY_STR_SIZE, false);
        openssl_ec_pubkey_decompress(comp_pubkey_str, uncomp_pubkey_str, ec_algo);
        util_str2hex_temp(uncomp_pubkey_str, (unsigned char *)uncomp_pubkey, UNCOMP_PUBKEY_SIZE, false);

        ret = openssl_ec_pubkey_hex2pem(p_pubkey_path, (uint8_t *)uncomp_pubkey, ec_algo);
    }
    else
    {
        ASSERT_M(0);
    }

    return (ret);
}

////////////////////////////////////////////////
//
// x9_63_kdf = kdf2
int openssl_kdf2(const EVP_MD *md, const uint8_t *p_share, uint32_t share_len, const uint8_t *p_kdp, size_t kdp_len, uint32_t key_len, uint8_t *p_key)
{                   
    int ret = 0;
    EVP_MD_CTX *ctx = NULL;
    uint8_t counter[4] = {0, 0, 0, 1};
    uint8_t dgst[EVP_MAX_MD_SIZE];
    uint32_t dgst_len;
    int32_t rlen = (int32_t)key_len;
    unsigned char *pp;

    pp = p_key;

    if (key_len > (uint32_t)(EVP_MD_size(md)*255))
    {
        fprintf(stderr, "%s(%d):", __FILE__, __LINE__);
        goto end;
    }

    while (rlen > 0)
    {
#if (OPENSSL_111 == ENABLED)
        ctx = EVP_MD_CTX_new();
        if (!ctx)
        {
            goto end;
        }
#elif (OPENSSL_102 == ENABLED)
        ctx = (EVP_MD_CTX *)MALLOC_M(sizeof(EVP_MD_CTX));
        if (!ctx)
        {
            goto end;
        }

        EVP_MD_CTX_init(ctx);
#endif // OPENSSL_111

        if (!EVP_DigestInit(ctx, md))
        {
            fprintf(stderr, "%s(%d):", __FILE__, __LINE__);
            goto end;
        }

        if (!EVP_DigestUpdate(ctx, p_share, share_len))
        {
            fprintf(stderr, "%s(%d):", __FILE__, __LINE__);
            goto end;
        }

        if (!EVP_DigestUpdate(ctx, counter, 4))
        {
            fprintf(stderr, "%s(%d):", __FILE__, __LINE__);
            goto end;
        }

        if (kdp_len && p_kdp)
        {
            if (!EVP_DigestUpdate(ctx, p_kdp, kdp_len))
            {
                fprintf(stderr, "%s(%d):", __FILE__, __LINE__);
                goto end;
            }
        }

        if (!EVP_DigestFinal(ctx, dgst, &dgst_len))
        {
            fprintf(stderr, "%s(%d):", __FILE__, __LINE__);
            goto end;
        }

#if (OPENSSL_102 == ENABLED)
        EVP_MD_CTX_cleanup(ctx);
#endif // OPENSSL_102

        MEMCPY_M(pp, dgst, key_len>=dgst_len ? dgst_len:key_len);

        rlen -= dgst_len;
        pp += dgst_len;
        counter[3]++;
    }

    ret = 1;

    end:
    if (ctx)
    {
#if (OPENSSL_111 == ENABLED)
        EVP_MD_CTX_free(ctx);
#elif (OPENSSL_102 == ENABLED)
        FREE_M(ctx);
#endif // OPENSSL_111
    }
    
    return ret;
}
