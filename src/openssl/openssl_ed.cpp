/**
 * Description : 
 *
 * @date 2021/01/21
 * @author FINL Chain Team
 * @version 1.0
 */

#include "global.hpp"

//////////////////////////////////////////////////////////////////
//
int32_t openssl_ed_prikey_pemstr2hex(char *p_pem_str, uint8_t *p_prikey)
{
    int32_t ret = ERROR_;
#if (OPENSSL_111 == ENABLED)
    EVP_PKEY *p_pkey;

    DBG_PRINT(DBG_UTIL, DBG_TRACE, (void *)"(%s)\n",  __FUNCTION__);

    p_pkey = EVP_PKEY_new_read_PRIKEY_pem_str(p_pem_str);
    if (p_pkey)
    {
        int32_t ret_len;

        ret_len = openssl_get_25519_prikey(p_pkey, p_prikey);
        if (ret_len)
        {
            DBG_DUMP(DBG_UTIL, DBG_NONE, (void *)"openssl_ed_prikey_pem2hex", p_prikey, X25519_PRIVATE_KEY_LEN_);
            ret = SUCCESS_;
        }
        
        EVP_PKEY_free(p_pkey);
    }
#elif (OPENSSL_102 == ENABLED)
    //
#endif // OPENSSL_111

    return (ret);
}

//
int32_t openssl_ed_pubkey_pemstr2hex(char *p_pubkey_raw, uint8_t *p_pubkey)
{
    int32_t ret = ERROR_;

#if (OPENSSL_111 == ENABLED)
    EVP_PKEY *p_pkey;

    DBG_PRINT(DBG_UTIL, DBG_TRACE, (void *)"(%s)\n",  __FUNCTION__);

    // p_pkey = EVP_PKEY_new_read_PUBKEY_pem_no_file(p_pubkey_raw);
    p_pkey = EVP_PKEY_new_read_PUBKEY_pem_str(p_pubkey_raw);
    if (p_pkey)
    {
        int32_t pubkey_size = X25519_PUBLIC_KEY_LEN_;
        uint8_t tmp_pubkey[X25519_PUBLIC_KEY_LEN_];
        uint8_t *p_tmp_pubkey = tmp_pubkey;

        EVP_PKEY_get_raw_public_key(p_pkey, p_tmp_pubkey, (size_t *)&pubkey_size);
        DBG_DUMP(DBG_UTIL, DBG_NONE, (void *)"open pubkey pem2hex", p_tmp_pubkey, pubkey_size);

        MEMCPY_M(p_pubkey, &tmp_pubkey, X25519_PUBLIC_KEY_LEN_);

        EVP_PKEY_free(p_pkey);

        ret = SUCCESS_;
    }
#elif (OPENSSL_102 == ENABLED)
    //
#endif // OPENSSL_111

    return (ret);
}

//
int32_t openssl_ed_prikey_pem2hex(bool b_enc, char *p_prikey_path, uint8_t *p_prikey)
{
    int32_t ret = ERROR_;
#if (OPENSSL_111 == ENABLED)
    EVP_PKEY *p_pkey;

    DBG_PRINT(DBG_UTIL, DBG_TRACE, (void *)"(%s)\n",  __FUNCTION__);

    DBG_PRINT(DBG_UTIL, DBG_INFO, (void *)"(%s)\n",  p_prikey_path);

    p_pkey = EVP_PKEY_new_read_PRIKEY_pem(b_enc, p_prikey_path);
    if (p_pkey)
    {
        int32_t ret_len;

        ret_len = openssl_get_25519_prikey(p_pkey, p_prikey);
        if (ret_len)
        {
            DBG_DUMP(DBG_UTIL, DBG_NONE, (void *)"openssl_ed_prikey_pem2hex", p_prikey, X25519_PRIVATE_KEY_LEN_);
            ret = SUCCESS_;
        }
        
        EVP_PKEY_free(p_pkey);
    }
#elif (OPENSSL_102 == ENABLED)
    //
#endif // OPENSSL_111

    return (ret);
}

//
int32_t openssl_ed_pubkey_pem2hex(char *p_pubkey_path, uint8_t *p_pubkey)
{
    int32_t ret = ERROR_;

#if (OPENSSL_111 == ENABLED)
    EVP_PKEY *p_pkey;

    DBG_PRINT(DBG_UTIL, DBG_TRACE, (void *)"(%s)\n",  __FUNCTION__);

    p_pkey = EVP_PKEY_new_read_PUBKEY_pem(p_pubkey_path);
    if (p_pkey)
    {
        int32_t pubkey_size = X25519_PUBLIC_KEY_LEN_;
        uint8_t tmp_pubkey[X25519_PUBLIC_KEY_LEN_];
        uint8_t *p_tmp_pubkey = tmp_pubkey;

        EVP_PKEY_get_raw_public_key(p_pkey, p_tmp_pubkey, (size_t *)&pubkey_size);
        DBG_DUMP(DBG_UTIL, DBG_NONE, (void *)"open pubkey pem2hex", p_tmp_pubkey, pubkey_size);

        MEMCPY_M(p_pubkey, &tmp_pubkey, X25519_PUBLIC_KEY_LEN_);

        EVP_PKEY_free(p_pkey);

        ret = SUCCESS_;
    }
#elif (OPENSSL_102 == ENABLED)
    //
#endif // OPENSSL_111

    return (ret);
}

//
int32_t openssl_ed_pubkey_hex2pem(char *p_pubkey_path, uint8_t *p_pubkey)
{
    int32_t ret = ERROR_;
#if (OPENSSL_111 == ENABLED)
    EVP_PKEY *p_pkey;
    
    DBG_PRINT(DBG_UTIL, DBG_TRACE, (void *)"(%s)\n",  __FUNCTION__);
    DBG_DUMP(DBG_UTIL, DBG_INFO, (void *)"open pubkey hex2pem", p_pubkey, ED25519_PUBLIC_KEY_LEN_);

    p_pkey = EVP_PKEY_new_raw_public_key(NID_ED25519, NULL, p_pubkey, ED25519_PUBLIC_KEY_LEN_);
    if (!p_pkey)
    {
        DBG_PRINT(DBG_UTIL, DBG_ERROR, (void *)"ERROR : p_pkey\n"); 

        return (ret);
    }

    do
    {
        FILE *fp;
        // ED Public Key
        fp = fopen(p_pubkey_path, "w");
        if (fp)
        {
            BIO *p_outbio = NULL;
            p_outbio = BIO_new_fp(fp, BIO_NOCLOSE);
            
            if (p_outbio)
            {
                if(!PEM_write_bio_PUBKEY(p_outbio, p_pkey))
                {
                    DBG_PRINT(DBG_UTIL, DBG_ERROR, (void *)"Error writing public key data in PEM format\n");
                    break;
                }
        
                ret = SUCCESS_;
                
                BIO_free(p_outbio);
            }
            
            fclose(fp);
        }

    } while (0);

    EVP_PKEY_free(p_pkey);

#elif (OPENSSL_102 == ENABLED)
    //
#endif // OPENSSL_111

    return (ret);
}

//
#if (OPENSSL_111 == ENABLED)
int32_t openssl_get_25519_prikey(EVP_PKEY *p_pkey, uint8_t *p_prikey)
{
    int32_t ret;
    int32_t prikey_size = X25519_PRIVATE_KEY_LEN_;
    uint8_t tmp_prikey[X25519_PRIVATE_KEY_LEN_];
    uint8_t *p_tmp_prikey = tmp_prikey;

    ret = EVP_PKEY_get_raw_private_key(p_pkey, p_tmp_prikey, (size_t *)&prikey_size);
    if (ret == 1)
    {
        ASSERT_M(X25519_PRIVATE_KEY_LEN_ == prikey_size);
        MEMCPY_M(p_prikey, p_tmp_prikey, prikey_size);
        DBG_DUMP(DBG_UTIL, DBG_INFO, (void *)"openssl_get_25519_prikey", p_prikey, prikey_size);
    }
    else
    {
        DBG_PRINT(DBG_UTIL, DBG_ERROR, (void *)"Error : (%s)\n",  __FUNCTION__);
        prikey_size = 0;
    }
    
    return (prikey_size);
}

int32_t openssl_get_25519_pubkey(EVP_PKEY *p_pkey, uint8_t *p_pubkey)
{
    int32_t ret;
    int32_t pubkey_size = X25519_PUBLIC_KEY_LEN_;
    uint8_t tmp_pubkey[X25519_PUBLIC_KEY_LEN_];
    uint8_t *p_tmp_pubkey = tmp_pubkey;

    ret = EVP_PKEY_get_raw_public_key(p_pkey, p_tmp_pubkey, (size_t *)&pubkey_size);
    if (ret == 1)
    {
        ASSERT_M(X25519_PRIVATE_KEY_LEN_ == pubkey_size);
        MEMCPY_M(p_pubkey, p_tmp_pubkey, X25519_PUBLIC_KEY_LEN_);
        DBG_DUMP(DBG_UTIL, DBG_INFO, (void *)"openssl_get_25519_pubkey", p_pubkey, pubkey_size);
    }
    else
    {
        DBG_PRINT(DBG_UTIL, DBG_ERROR, (void *)"Error : (%s)\n",  __FUNCTION__);
        pubkey_size = 0;
    }
    
    return (pubkey_size);
}

/////////////////////////////////////////////////////////////////////////////////////////////////////
// Key Generation With Private Key
int32_t openssl_111_25519_keygen_with_prikey(char *p_path, char *p_prikey, int32_t type)
{
    int32_t ret = ERROR_;
    // EVP_PKEY_CTX *pctx;

    DBG_PRINT(DBG_UTIL, DBG_TRACE, (void *)"(%s)\n",  __FUNCTION__);

    // pctx = EVP_PKEY_CTX_new_id(type, NULL);
    // if (!pctx)
    // {
    //     DBG_PRINT(DBG_UTIL, DBG_ERROR, (void *)"ERROR : pctx\n");

    //     return (ret);
    // }

    do
    {
        // EVP_PKEY *pkey = NULL;
        
        // EVP_PKEY_keygen_init(pctx);
        // EVP_PKEY_keygen(pctx, &pkey);

        EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(type, NULL, (uint8_t *)p_prikey, X25519_PRIVATE_KEY_LEN_);

        if (!pkey)
        {
            break;
        }

        do
        {
            char pubkey_dir[SSL_PATH_SIZE];
            char prikey_dir[SSL_PATH_SIZE];

            if (p_path)
            {
                if (type == ED25519)
                {
                    sprintf(pubkey_dir, "%s%s", p_path, (char *)"ed_pubkey.pem");
                    sprintf(prikey_dir, "%s%s", p_path, (char *)"ed_privkey.pem");
                }
                else
                {
                    sprintf(pubkey_dir, "%s%s", p_path, (char *)"x_pubkey.pem");
                    sprintf(prikey_dir, "%s%s", p_path, (char *)"x_privkey.pem");
                }
            }
            else
            {
                if (type == ED25519)
                {
                    sprintf(pubkey_dir, "%s", (char *)"ed_pubkey.pem");
                    sprintf(prikey_dir, "%s", (char *)"ed_privkey.pem");
                }
                else
                {
                    sprintf(pubkey_dir, "%s", (char *)"x_pubkey.pem");
                    sprintf(prikey_dir, "%s", (char *)"x_privkey.pem");
                }
            }
            
            // ED Pubkey Key
            PEM_new_write_PUBKEY(pubkey_dir, pkey);
            // ED Private Key
            PEM_new_write_PRIKEY(prikey_dir, pkey);

            ret = SUCCESS_;
        } while (0);

        EVP_PKEY_free(pkey);
    } while (0);

    // EVP_PKEY_CTX_free(pctx);

    return (ret);
}

// Key Generation
int32_t openssl_111_25519_keygen(char *p_path, int32_t type)
{
    int32_t ret = ERROR_;
    EVP_PKEY_CTX *pctx;

    DBG_PRINT(DBG_UTIL, DBG_TRACE, (void *)"(%s)\n",  __FUNCTION__);

    pctx = EVP_PKEY_CTX_new_id(type, NULL);
    if (!pctx)
    {
        DBG_PRINT(DBG_UTIL, DBG_ERROR, (void *)"ERROR : pctx\n");

        return (ret);
    }

    do
    {
        EVP_PKEY *pkey = NULL;
        
        EVP_PKEY_keygen_init(pctx);
        EVP_PKEY_keygen(pctx, &pkey);

        if (!pkey)
        {
            break;
        }

        do
        {
            char pubkey_dir[SSL_PATH_SIZE];
            char prikey_dir[SSL_PATH_SIZE];

            if (p_path)
            {
                if (type == ED25519)
                {
                    sprintf(pubkey_dir, "%s%s", p_path, (char *)"ed_pubkey.pem");
                    sprintf(prikey_dir, "%s%s", p_path, (char *)"ed_privkey.pem");
                }
                else
                {
                    sprintf(pubkey_dir, "%s%s", p_path, (char *)"x_pubkey.pem");
                    sprintf(prikey_dir, "%s%s", p_path, (char *)"x_privkey.pem");
                }
            }
            else
            {
                if (type == ED25519)
                {
                    sprintf(pubkey_dir, "%s", (char *)"ed_pubkey.pem");
                    sprintf(prikey_dir, "%s", (char *)"ed_privkey.pem");
                }
                else
                {
                    sprintf(pubkey_dir, "%s", (char *)"x_pubkey.pem");
                    sprintf(prikey_dir, "%s", (char *)"x_privkey.pem");
                }
            }
            
            // ED Pubkey Key
            PEM_new_write_PUBKEY(pubkey_dir, pkey);
            // ED Private Key
            PEM_new_write_PRIKEY(prikey_dir, pkey);

            ret = SUCCESS_;
        } while (0);

        EVP_PKEY_free(pkey);
    } while (0);

    EVP_PKEY_CTX_free(pctx);

    return (ret);
}

int32_t openssl_111_25519_keygen_pubkey(char *p_path, int32_t type)
{
    int32_t ret = ERROR_;
    EVP_PKEY_CTX *pctx;

    DBG_PRINT(DBG_UTIL, DBG_TRACE, (void *)"(%s)\n",  __FUNCTION__);

    pctx = EVP_PKEY_CTX_new_id(type, NULL);
    if (!pctx)
    {
        DBG_PRINT(DBG_UTIL, DBG_ERROR, (void *)"ERROR : pctx\n");

        return (ret);
    }

    do
    {
        EVP_PKEY *pkey = NULL;
        
        EVP_PKEY_keygen_init(pctx);
        EVP_PKEY_keygen(pctx, &pkey);

        if (!pkey)
        {
            break;
        }

        do
    {
            char pubkey_dir[SSL_PATH_SIZE];
            // char prikey_dir[SSL_PATH_SIZE];

            if (p_path)
            {
                sprintf(pubkey_dir, "%s%s", p_path, (char *)"ed_pubkey.pem");
                // sprintf(prikey_dir, "%s%s", p_path, (char *)"ed_privkey.pem");
            }
            else
            {
                sprintf(pubkey_dir, "%s", (char *)"ed_pubkey.pem");
                // sprintf(prikey_dir, "%s", (char *)"ed_privkey.pem");
            }

            // ED Public Key
            PEM_new_write_PUBKEY(pubkey_dir, pkey);
            // // ED Private Key
            // PEM_new_write_PRIKEY(prikey_dir, pkey);

            ret = SUCCESS_;
        } while (0);

        EVP_PKEY_free(pkey);
    } while (0);

    EVP_PKEY_CTX_free(pctx);

    return (ret);
}

//
int32_t openssl_111_25519_keygen_fin_with_prikey(char *p_path, char *p_prikey, int32_t type, uint8_t *p_seed, uint32_t seed_len)
{
    int32_t ret = ERROR_;
    // EVP_PKEY_CTX *pctx;

    DBG_PRINT(DBG_UTIL, DBG_TRACE, (void *)"(%s)\n",  __FUNCTION__);

    // pctx = EVP_PKEY_CTX_new_id(type, NULL);
    // if (!pctx)
    // {
    //     DBG_PRINT(DBG_UTIL, DBG_ERROR, (void *)"ERROR : pctx\n");

    //     return (ret);
    // }

    do
    {
        // EVP_PKEY *pkey = NULL;
        
        // EVP_PKEY_keygen_init(pctx);
        // EVP_PKEY_keygen(pctx, &pkey);

        EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(type, NULL, (uint8_t *)p_prikey, X25519_PRIVATE_KEY_LEN_);

        if (!pkey)
        {
            break;
        }

        do
        {
            char pubkey_dir[SSL_PATH_SIZE];
            char prikey_dir[SSL_PATH_SIZE];
            char prikey_fin_dir[SSL_PATH_SIZE];

            if (p_path)
            {
                sprintf(pubkey_dir, "%s%s", p_path, (char *)"ed_pubkey.pem");
                sprintf(prikey_dir, "%s%s", p_path, (char *)"ed_privkey.pem");
                sprintf(prikey_fin_dir, "%s%s", p_path, (char *)"ed_privkey.fin");
            }
            else
            {
                sprintf(pubkey_dir, "%s", (char *)"ed_pubkey.pem");
                sprintf(prikey_dir, "%s", (char *)"ed_privkey.pem");
                sprintf(prikey_fin_dir, "%s", (char *)"ed_privkey.fin");
            }
            // ED Private Key
            PEM_new_write_PUBKEY(pubkey_dir, pkey);
            // ED Public Key
            PEM_new_write_PRIKEY(prikey_dir, pkey);

            //
            ret = openssl_aes_encrpt_file(prikey_dir, prikey_fin_dir, p_seed, seed_len);

            // Delete Private Key Pem file
            util_remove_file(prikey_dir);

            ret = SUCCESS_;
        } while (0);

        EVP_PKEY_free(pkey);
    } while (0);

    // EVP_PKEY_CTX_free(pctx);

    return (ret);
}

//
int32_t openssl_111_25519_keygen_fin(char *p_path, int32_t type, uint8_t *p_seed, uint32_t seed_len)
{
    int32_t ret = ERROR_;
    EVP_PKEY_CTX *pctx;

    DBG_PRINT(DBG_UTIL, DBG_TRACE, (void *)"(%s)\n",  __FUNCTION__);

    pctx = EVP_PKEY_CTX_new_id(type, NULL);
    if (!pctx)
    {
        DBG_PRINT(DBG_UTIL, DBG_ERROR, (void *)"ERROR : pctx\n");

        return (ret);
    }

    do
    {
        EVP_PKEY *pkey = NULL;
        
        EVP_PKEY_keygen_init(pctx);
        EVP_PKEY_keygen(pctx, &pkey);

        if (!pkey)
        {
            break;
        }

        do
        {
            char pubkey_dir[SSL_PATH_SIZE];
            char prikey_dir[SSL_PATH_SIZE];
            char prikey_fin_dir[SSL_PATH_SIZE];

            if (p_path)
            {
                sprintf(pubkey_dir, "%s%s", p_path, (char *)"ed_pubkey.pem");
                sprintf(prikey_dir, "%s%s", p_path, (char *)"ed_privkey.pem");
                sprintf(prikey_fin_dir, "%s%s", p_path, (char *)"ed_privkey.fin");
            }
            else
            {
                sprintf(pubkey_dir, "%s", (char *)"ed_pubkey.pem");
                sprintf(prikey_dir, "%s", (char *)"ed_privkey.pem");
                sprintf(prikey_fin_dir, "%s", (char *)"ed_privkey.fin");
            }
            // ED Private Key
            PEM_new_write_PUBKEY(pubkey_dir, pkey);
            // ED Public Key
            PEM_new_write_PRIKEY(prikey_dir, pkey);

            //
            ret = openssl_aes_encrpt_file(prikey_dir, prikey_fin_dir, p_seed, seed_len);

            // Delete Private Key Pem file
            util_remove_file(prikey_dir);

            ret = SUCCESS_;
        } while (0);

        EVP_PKEY_free(pkey);
    } while (0);

    EVP_PKEY_CTX_free(pctx);

    return (ret);
}
#endif // OPENSSL_111

//
int32_t openssl_ed25519_keygen_with_prikey(char *p_path, char *p_prikey)
{
    int32_t ret = ERROR_;

#if (OPENSSL_111 == ENABLED)
    ret = openssl_111_25519_keygen_with_prikey(p_path, p_prikey, EVP_PKEY_ED25519);
#elif (OPENSSL_102 == ENABLED)
    //
#endif // OPENSSL_111

    return (ret);
}

//
int32_t openssl_ed25519_keygen(char *p_path)
{
    int32_t ret = ERROR_;
    
#if (OPENSSL_111 == ENABLED)
    ret = openssl_111_25519_keygen(p_path, EVP_PKEY_ED25519);
#elif (OPENSSL_102 == ENABLED)
    //
#endif // OPENSSL_111

    return (ret);
}

//
int32_t openssl_ed25519_keygen_pubkey(char *p_path)
{
    int32_t ret = ERROR_;
    
#if (OPENSSL_111 == ENABLED)
    ret = openssl_111_25519_keygen_pubkey(p_path, EVP_PKEY_ED25519);
#elif (OPENSSL_102 == ENABLED)
    //
#endif // OPENSSL_111

    return (ret);
}

//
int32_t openssl_ed25519_keygen_fin_with_prikey(char *p_path, char *p_prikey, uint8_t *p_seed, uint32_t seed_len)
{
    int32_t ret = ERROR_;
    
#if (OPENSSL_111 == ENABLED)
    ret = openssl_111_25519_keygen_fin_with_prikey(p_path, p_prikey, EVP_PKEY_ED25519, p_seed, seed_len);
#elif (OPENSSL_102 == ENABLED)
    //
#endif // OPENSSL_111

    return (ret);
}

//
int32_t openssl_ed25519_keygen_fin(char *p_path, uint8_t *p_seed, uint32_t seed_len)
{
    int32_t ret = ERROR_;
    
#if (OPENSSL_111 == ENABLED)
    ret = openssl_111_25519_keygen_fin(p_path, EVP_PKEY_ED25519, p_seed, seed_len);
#elif (OPENSSL_102 == ENABLED)
    //
#endif // OPENSSL_111

    return (ret);
}
