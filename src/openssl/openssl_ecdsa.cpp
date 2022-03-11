/**
 * Description : 
 *
 * @date 2021/01/21
 * @author FINL Chain Team
 * @version 1.0
 */

#include "global.hpp"

//
int32_t raw_SIG_new_ECDSA_SIG(ECDSA_SIG *sig, SSL_SIG_U *p_sig_hex)
{
    int32_t ret = ERROR_;
    
    do
    {
        char *hexR, *hexS;
        /*print R & S value in hex format */
#if (OPENSSL_111 == ENABLED)
        const BIGNUM *r_bn = ECDSA_SIG_get0_r(sig);
        const BIGNUM *r_sn = ECDSA_SIG_get0_s(sig);

        if (!r_bn || !r_sn)
        {
            break;
        }
        
        hexR = BN_bn2hex_z(r_bn);
        hexS = BN_bn2hex_z(r_sn);
#elif (OPENSSL_102 == ENABLED)
        hexR = BN_bn2hex_z(sig->r);
        hexS = BN_bn2hex_z(sig->s);
#endif // OPENSSL_111
        if(!hexR) break;
        if(!hexS)
        {
            OPENSSL_free(hexR);
            break;
        }
        
        DBG_PRINT(DBG_UTIL, DBG_INFO, (void *)"hexR(%d) hexS(%d)\n", STRLEN_M(hexR), STRLEN_M(hexS));
        DBG_PRINT(DBG_UTIL, DBG_INFO, (void *)"R: %s \nS: %s\n", hexR, hexS);

        ASSERT_M(STRLEN_M(hexR) == (SIG_R_SIZE*2));
        ASSERT_M(STRLEN_M(hexS) == (SIG_S_SIZE*2));

        do
        {
            int32_t len;
            
            // String to Hex
            len = SIG_R_SIZE;
            util_str2hex(hexR, p_sig_hex->ec.r, &len);
            len = SIG_S_SIZE;
            util_str2hex(hexS, p_sig_hex->ec.s, &len);

            ret = SUCCESS_;
        } while(0);

        OPENSSL_free(hexR);
        OPENSSL_free(hexS);
    } while(0);

    return (ret);
}

//
int32_t ECDSA_new_do_verify(uint8_t *p_data, uint32_t data_len, ECDSA_SIG *p_sig, EC_KEY *p_eckey)
{
    int32_t ret = ERROR_, ssl_ret;
    
    ssl_ret = ECDSA_do_verify(p_data, data_len, p_sig, p_eckey);
    
    if(ssl_ret == SSL_VERIFY_SUCCESS) 
    {
        DBG_PRINT(DBG_UTIL, DBG_INFO, (void *)"verified SSL_VERIFY_SUCCESS\n");
        ret = SUCCESS_;
    }
    else if(ssl_ret == SSL_VERIFY_INCORRECT)
    {
        DBG_PRINT(DBG_UTIL, DBG_ERROR, (void *)"verified SSL_VERIFY_INCORRECT\n");
    }
    else if(ssl_ret == SSL_VERIFY_ERROR)
    {
        DBG_PRINT(DBG_UTIL, DBG_ERROR, (void *)"verified SSL_VERIFY_ERROR\n"); 
    }

    return (ret);
}

/////////////////////////////////////////////////////////////////////////////////////////////////////
// Key Generation



///////////////////////////////////////////////////////////////////////
// Signature

EVP_PKEY *openssl_get_ec_pkey(char *p_prikey_str, int32_t ec_algo) 
{
    // int32_t ret = ERROR_;
    EVP_PKEY *pkey = NULL;

    DBG_PRINT(DBG_UTIL, DBG_TRACE, (void *)"(%s)\n",  __FUNCTION__);
    
    if(!p_prikey_str) return (pkey);

    do
    {
        EC_KEY* eckey = EC_KEY_new();
        if(!eckey) break;

        do
        {
            EC_GROUP* ecgroup = EC_GROUP_new_by_curve_name(ec_algo);
            if(!ecgroup) break;

            do
            {
                EC_KEY_set_group(eckey, ecgroup);
                EC_KEY_set_asn1_flag(eckey, OPENSSL_EC_NAMED_CURVE);

                /* pri key */
                BIGNUM* prv = BN_new();
                if(!prv) break;

                BN_hex2bn(&prv, p_prikey_str);
                DBG_PRINT(DBG_UTIL, DBG_INFO, (void *)"Private key: %s \n", p_prikey_str);

                do
                {
                    EC_POINT* pub = EC_POINT_new(ecgroup);
                    if(!pub) break;
                    
                    do
                    {
                        /* pub key */
                        EC_POINT_mul(ecgroup, pub, prv, NULL, NULL, NULL);

                        /* add the private & public key to the EC_KEY structure */
                        EC_KEY_set_private_key(eckey, prv);
                        EC_KEY_set_public_key(eckey, pub);

                        char* hexPKey;

                        hexPKey = EC_POINT_point2hex(ecgroup, pub, POINT_CONVERSION_UNCOMPRESSED, NULL);
                        if(!hexPKey) break;

                        do
                        {
                            //EC_POINT_hex2point(ecgroup, hexPKey, POINT_CONVERSION_UNCOMPRESSED, BN_CTX *)
                            /* create hash */

                            pkey = EVP_PKEY_new();
                            DBG_PRINT(DBG_UTIL, DBG_INFO, (void *)"Public key:  %s \n", hexPKey);
                            if(!pkey) break;

                            do
                            {
                                EVP_PKEY_set1_EC_KEY(pkey, eckey);

                                // PEM_new_write_PUBKEY((char *)"pubkey.pem", pkey);
                                // PEM_new_write_PRIKEY((char *)"privkey.pem", pkey);

                                // ret = SUCCESS_;
                            }while(0);
                            
                            // EVP_PKEY_free(pkey);
                        }while(0);
                        
                        OPENSSL_free(hexPKey);
                        
                    }while(0);
                    EC_POINT_free(pub);
                        
                }while(0);
                BN_free(prv);
                
            }while(0);
            EC_GROUP_free(ecgroup);
            
        } while(0);
        EC_KEY_free(eckey);        
        
    }while(0);
    
    return (pkey);
}

int32_t openssl_ecdsa_sig(EVP_PKEY *p_pkey, uint8_t *p_data, uint32_t data_len, SSL_SIG_U *p_sig_hex)
{
    /* Read private key */
    int32_t ret = ERROR_;
    
    DBG_PRINT(DBG_UTIL, DBG_TRACE, (void *)"(%s)\n",  __FUNCTION__);

    do
    {
        uint8_t hash[HASH_SIZE];
        
        EC_KEY* eckey_in = EVP_PKEY_get1_EC_KEY(p_pkey);
        if(!eckey_in) break;

        DBG_DUMP(DBG_UTIL, DBG_INFO, (void *)"Data : ", p_data, data_len);    
        
        // Data Hash
        openssl_sha256(hash, p_data, data_len);

        DBG_DUMP(DBG_UTIL, DBG_INFO, (void *)"Hash : ", hash, HASH_SIZE);

        do
        {
            // Create and verify signature
            ECDSA_SIG *sig = ECDSA_do_sign(hash, HASH_SIZE, eckey_in);
            if(!sig) break;
            
            do 
            {
                // Verify signature with Private Key
                ret = ECDSA_new_do_verify(hash, HASH_SIZE, sig, eckey_in);

                if (ret == SUCCESS_)
                {
                    ret = raw_SIG_new_ECDSA_SIG(sig, p_sig_hex);
                }
            }while(0);
            
            ECDSA_SIG_free(sig);
            
        }while(0);

        EC_KEY_free(eckey_in);
    }while(0);

    return (ret);
}

///////////////////////////////////////////////////////////////////////
// Verify
//
int32_t openssl_ecdsa_verify(uint8_t *p_data, uint32_t data_len, SSL_SIG_U *p_sig_hex, uint8_t *p_comp_pubkey, int32_t ec_algo)
{
    int32_t ret = ERROR_;
    uint8_t data_hash[HASH_SIZE];

    openssl_sha256(data_hash, p_data, data_len);
    
    do
    {
        ECDSA_SIG *sig;
        
        sig = ECDSA_SIG_new_raw_SIG(p_sig_hex);
        if(!sig) break;

        do
        {
            EC_KEY *eckey;

            eckey = EC_KEY_new_raw_PUBKEY(p_comp_pubkey, ec_algo);
            if (!eckey) break;

            do
            {
                ret = ECDSA_new_do_verify(data_hash, HASH_SIZE, sig, eckey);
            } while(0);

            EC_KEY_free(eckey);
        } while(0);
        

        ECDSA_SIG_free(sig);
    } while(0);

    return (ret);
}
