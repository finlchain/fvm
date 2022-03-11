/**
 * Description : 
 *
 * @date 2021/01/21
 * @author FINL Chain Team
 * @version 1.0
 */

#include "global.hpp"

/////////////////////////////////////////////////////////////////////////////////////////////////////
// Signature
//
int32_t openssl_111_ed25519_sig(EVP_PKEY *p_pkey, uint8_t *p_data, uint32_t data_len, SSL_SIG_U *p_sig_hex)
{
    int32_t ret = ERROR_;

    DBG_PRINT(DBG_UTIL, DBG_TRACE, (void *)"(%s)\n",  __FUNCTION__);

    do
    {
        EVP_MD_CTX *p_mdctx = NULL;
        uint8_t hash[HASH_SIZE];
        
        openssl_sha256(hash, (uint8_t *)p_data, data_len);
        
        DBG_DUMP(DBG_UTIL, DBG_INFO, (void *)"msg hash", hash, HASH_SIZE);
        
        p_mdctx = EVP_MD_CTX_new();
        if (!p_mdctx) 
        {
            DBG_PRINT(DBG_UTIL, DBG_ERROR, (void *)"Failed to create md ctx : OpenSSL %s\n", ERR_error_string(ERR_get_error(), NULL));
            break;
        }
        
        do
        {
            if(EVP_DigestSignInit(p_mdctx, NULL, NULL, NULL, p_pkey) != 1) 
            {
                DBG_PRINT(DBG_UTIL, DBG_ERROR, (void *)"Failed to DigestSignInit : OpenSSL %s\n", ERR_error_string(ERR_get_error(), NULL));
                break;
            }

            do
            {
                size_t sig_len = SIG_SIZE;
                
                if(EVP_DigestSign(p_mdctx, p_sig_hex->sig, &sig_len, hash, HASH_SIZE) != 1)
                {
                    DBG_PRINT(DBG_UTIL, DBG_ERROR, (void *)"Failed to sign a message : OpenSSL %s\n", ERR_error_string(ERR_get_error(), NULL));
                    break;
                }
                
                DBG_DUMP(DBG_UTIL, DBG_INFO, (void *)"ed sig", p_sig_hex->sig, sig_len);

                ret = SUCCESS_;
            } while(0);
        } while(0);
        
        EVP_MD_CTX_free(p_mdctx);
    } while (0);

    return (ret);
}

/////////////////////////////////////////////////////////////////////////////////////////////////////
// Verify
//
int32_t openssl_111_ed25519_verify(uint8_t *p_data, uint32_t data_len, SSL_SIG_U *p_sig_hex, uint8_t *p_pubkey)
{
    int32_t ret = ERROR_;
    EVP_PKEY *p_pkey;
    
    p_pkey = EVP_PKEY_new_raw_public_key(NID_ED25519, NULL, p_pubkey, ED25519_PUBLIC_KEY_LEN_);
    if (!p_pkey)
    {
        DBG_PRINT(DBG_UTIL, DBG_ERROR, (void *)"ERROR : p_pkey\n"); 
        return (ret);
    }

    do
    {
        EVP_MD_CTX *p_mdctx = EVP_MD_CTX_new();

        if(!p_mdctx)
        {
            break;
        }

        do
        {
            if (EVP_DigestVerifyInit(p_mdctx, NULL, NULL, NULL, p_pkey) == 1)
            {
                if (EVP_DigestVerify(p_mdctx, p_sig_hex->sig, SIG_SIZE, p_data, data_len) == 1)
                {
                    ret = SUCCESS_;
                    DBG_PRINT(DBG_UTIL, DBG_INFO, (void *)"Signature verified.\n");
                }
                else
                {
                    DBG_PRINT(DBG_UTIL, DBG_ERROR, (void *)"Signature did not verify.\n"); 
                }
            }
        } while (0);
        
        EVP_MD_CTX_free(p_mdctx);
    } while (0);
    
    EVP_PKEY_free(p_pkey);
    
    return (ret);
}

//
int32_t openssl_ed25519_verify(uint8_t *p_data, uint32_t data_len, SSL_SIG_U *p_sig_hex, uint8_t *p_pubkey)
{
    int32_t ret = ERROR_;
    uint8_t data_hash[HASH_SIZE];
    
    DBG_PRINT(DBG_UTIL, DBG_TRACE, (void *)"(%s)\n",  __FUNCTION__);

    openssl_sha256(data_hash, p_data, data_len);

	DBG_DUMP(DBG_UTIL, DBG_INFO, (void *) "p_data", (uint8_t *)p_data, data_len);
	DBG_DUMP(DBG_UTIL, DBG_INFO, (void *) "data_hash", (uint8_t *)data_hash, HASH_SIZE);
    
#if (OPENSSL_111 == ENABLED)
    ret = openssl_111_ed25519_verify(data_hash, HASH_SIZE, p_sig_hex, p_pubkey);
#elif (OPENSSL_102 == ENABLED)
    ret = ED25519_verify(data_hash, HASH_SIZE, p_sig_hex->sig, p_pubkey);
    if(ret)
    {
        ret = SUCCESS_;
        DBG_PRINT(DBG_UTIL, DBG_INFO, (void *)"ED25519_verify, valid signature\r\n");
    }
#endif // OPENSSL_111

    return (ret);
}
