/**
 * Description : 
 *
 * @date 2021/01/21
 * @author FINL Chain Team
 * @version 1.0
 */

#include "global.hpp"

//
void EC_KEY_print(EC_KEY *eckey)
{
    const BIGNUM *d = EC_KEY_get0_private_key(eckey);
    const EC_POINT *Q = EC_KEY_get0_public_key(eckey);
    const EC_GROUP *ecgroup = EC_KEY_get0_group(eckey);
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    char *p_d, *p_x, *p_y;
    
    if (!EC_POINT_get_affine_coordinates_GFp(ecgroup, Q, x, y, NULL)) return;
    
    p_d = BN_bn2hex_z(d);
    p_x = BN_bn2hex_z(x);
    p_y = BN_bn2hex_z(y);
    DBG_PRINT(DBG_UTIL, DBG_INFO, (void *) "private key : (%s)\n", p_d);
    DBG_PRINT(DBG_UTIL, DBG_INFO, (void *) "public key : (04%s%s)\n", p_x, p_y);
    // ~Print
    
    BN_free(x);
    BN_free(y);
    
    OPENSSL_free(p_d);
    OPENSSL_free(p_x);
    OPENSSL_free(p_y);
}

//
ECDSA_SIG *ECDSA_SIG_new_raw_SIG(SSL_SIG_U *p_sig_hex)
{
    int32_t ret = ERROR_;
    ECDSA_SIG *sig;
    
    do
    {
        sig = ECDSA_SIG_new();
        
        if(!sig) break;
        
        do
        {
            char sig_r_str[SIG_R_STR_SIZE];
            char sig_s_str[SIG_S_STR_SIZE];

            util_hex2str_temp(p_sig_hex->ec.r, SIG_R_SIZE, sig_r_str, SIG_R_STR_SIZE, false);
            util_hex2str_temp(p_sig_hex->ec.s, SIG_S_SIZE, sig_s_str, SIG_S_STR_SIZE, false);

            do
            {
#if (OPENSSL_111 == ENABLED)
                BIGNUM *r_bn = BN_new();
                BIGNUM *s_bn = BN_new();

                ASSERT_M (r_bn && s_bn);
                
                BN_hex2bn(&r_bn, sig_r_str);
                BN_hex2bn(&s_bn, sig_s_str);
                
                ECDSA_SIG_set0(sig, r_bn, s_bn);
#elif (OPENSSL_102 == ENABLED)
                BN_hex2bn(&sig->r, sig_r_str);
                BN_hex2bn(&sig->s, sig_s_str);
#endif // OPENSSL_111

                ret = SUCCESS_;
            } while (0);
        } while(0);

        if (ret != SUCCESS_)
        {
            ECDSA_SIG_free(sig);

            sig = NULL;
        }
    } while(0);

    return (sig);
}

//
EC_KEY *EC_KEY_new_raw_PUBKEY(uint8_t *p_pubkey, int32_t ec_algo)
{
    int32_t ret = ERROR_;
    EC_KEY *eckey = NULL;

    do
    {
        eckey = EC_KEY_new();
        if (!eckey) break;
        
        do
        {
            EC_GROUP *ecgroup;

            ecgroup = EC_GROUP_new_by_curve_name(ec_algo);
            if (!ecgroup) break;

            EC_KEY_set_group(eckey, ecgroup);
            EC_KEY_set_asn1_flag(eckey, OPENSSL_EC_NAMED_CURVE);

            do
            {
                EC_POINT *pubkey;

                pubkey = EC_POINT_new(ecgroup);
                if (!pubkey) break;

                do
                {
                    char pubkey_str[UNCOMP_PUBKEY_STR_SIZE];
                    
                    if (p_pubkey[0] == PUBKEY_DELIMITER_EC_UNCOMP)
                    {
                        ret = util_hex2str_temp(p_pubkey, UNCOMP_PUBKEY_SIZE, pubkey_str, UNCOMP_PUBKEY_STR_SIZE, false);
                    
                        DBG_PRINT(DBG_UTIL, DBG_INFO, (void *)"uncomp_pubkey_str(%s)\n",  pubkey_str);
                    }
                    else
                    {
                        ret = util_hex2str_temp(p_pubkey, COMP_PUBKEY_SIZE, pubkey_str, COMP_PUBKEY_STR_SIZE, false);
                    
                        DBG_PRINT(DBG_UTIL, DBG_INFO, (void *)"comp_pubkey_str(%s)\n",  pubkey_str);
                    }

                    if (ret == SUCCESS_)
                    {
                        EC_POINT_hex2point(ecgroup, (const char*)pubkey_str, pubkey, NULL);
                        EC_KEY_set_public_key(eckey, pubkey);
                    }
                } while(0);

                EC_POINT_free(pubkey);
            } while(0);

            EC_GROUP_free(ecgroup);
        } while(0);

        if (ret != SUCCESS_)
        {
            EC_KEY_free(eckey);

            eckey = NULL;
        }
    } while(0);

    return (eckey);
}

///////////////////////////////////////////////////////////////////////
//
int32_t openssl_ec_prikey_pem2hex(bool b_enc, char *p_prikey_path, uint8_t *p_prikey)
{
    int32_t ret = ERROR_;
    EVP_PKEY *p_pkey = NULL;

    DBG_PRINT(DBG_UTIL, DBG_TRACE, (void *)"(%s)\n",  __FUNCTION__);

    p_pkey = EVP_PKEY_new_read_PRIKEY_pem(b_enc, p_prikey_path);
    if (!p_pkey)
    {
        DBG_PRINT(DBG_UTIL, DBG_ERROR, (void *)"ERROR : prikey parse\n");
        return (ret);
    }

    do
    {
        EC_KEY* eckey = EVP_PKEY_get1_EC_KEY(p_pkey);
        if(!eckey) break;

        // EC_KEY_print(eckey);

        do
        {
            const BIGNUM *d = EC_KEY_get0_private_key(eckey);
            const EC_POINT *Q = EC_KEY_get0_public_key(eckey);
            const EC_GROUP *ecgroup = EC_KEY_get0_group(eckey);
            BIGNUM *x = BN_new();
            BIGNUM *y = BN_new();
            char *p_d, *p_x, *p_y;
            
            if (!EC_POINT_get_affine_coordinates_GFp(ecgroup, Q, x, y, NULL)) break;
            
            p_d = BN_bn2hex_z(d);
            p_x = BN_bn2hex_z(x);
            p_y = BN_bn2hex_z(y);
            DBG_PRINT(DBG_UTIL, DBG_INFO, (void *) "private key : (%s)\n", p_d);
            DBG_PRINT(DBG_UTIL, DBG_INFO, (void *) "public key : (04%s%s)\n", p_x, p_y);

            util_str2hex_temp(p_d, p_prikey, PRIKEY_SIZE, false);
            
            BN_free(x);
            BN_free(y);
            
            OPENSSL_free(p_d);
            OPENSSL_free(p_x);
            OPENSSL_free(p_y);

            ret = SUCCESS_;
        } while (0);

        EC_KEY_free(eckey);
    } while (0);

    EVP_PKEY_free(p_pkey);

    return ret;
}

int32_t openssl_ec_pubkey_hex2pem(char *p_pubkey_path, uint8_t *p_pubkey, int32_t ec_algo)
{
    int32_t ret = ERROR_;
    EC_KEY *eckey;

    DBG_PRINT(DBG_UTIL, DBG_TRACE, (void *)"(%s)\n",  __FUNCTION__);

    ASSERT_M(p_pubkey_path);
    ASSERT_M(p_pubkey);
    
    do
    {
        eckey = EC_KEY_new_raw_PUBKEY(p_pubkey, ec_algo);
        if (!eckey) break;

        do
        {
            EVP_PKEY *pkey;
            
            pkey = EVP_PKEY_new();
            if (!pkey) break;

            do
            {
                EVP_PKEY_set1_EC_KEY(pkey, eckey);
                
                ret = PEM_new_write_PUBKEY(p_pubkey_path, pkey);
            } while(0);

            EC_KEY_free(eckey);
        } while(0);

        EC_KEY_free(eckey);
    } while (0);
    
    return (ret);
}

int32_t openssl_ec_pubkey_pem2hex(char *p_pubkey_path, uint8_t *p_pubkey, int32_t ec_algo)
{
    int32_t ret = ERROR_;
    
    EVP_PKEY *pubkey_in = NULL;
    EC_KEY *pubKey;
    EC_GROUP *ecgroup;
    EC_POINT *pub;
    char *comp_pubkey_str;
    FILE* fp_in;    

    DBG_PRINT(DBG_UTIL, DBG_TRACE, (void *)"(%s)\n",  __FUNCTION__);

    fp_in = fopen (p_pubkey_path, "r");
    if (!fp_in) return (ret);

    do
    {
        pubkey_in = PEM_read_PUBKEY(fp_in, NULL, NULL, NULL);
        
        if(!pubkey_in) break;

        do 
        {
            pubKey = EVP_PKEY_get1_EC_KEY(pubkey_in);
            if (!pubKey) break;

            do
            {
                ecgroup = EC_GROUP_new_by_curve_name(ec_algo);
                if (!ecgroup) break;

                do
                {
                    pub = (EC_POINT *)EC_KEY_get0_public_key((const EC_KEY*)pubKey);
                    if (!pub) break;

                    do
                    {

                        comp_pubkey_str = EC_POINT_point2hex(ecgroup, pub, POINT_CONVERSION_COMPRESSED, NULL);
                        if (!comp_pubkey_str) break;

                        DBG_PRINT(DBG_UTIL, DBG_NONE, (void *)"my_comp_pubkey : (%s)\n", comp_pubkey_str);
                        
                        util_str2hex_temp(comp_pubkey_str, p_pubkey, COMP_PUBKEY_SIZE, false);
                        OPENSSL_free(comp_pubkey_str);

                        ret = SUCCESS_;
                        
                    }while(0);

                    //EC_POINT_free(pub);
                }while(0);
               
                EC_GROUP_free(ecgroup);
            }while(0);

            EC_KEY_free(pubKey);
        } while(0);

        EVP_PKEY_free(pubkey_in);
    }while(0);

    fclose (fp_in);

    return (ret);
}

///////////////////////////////////////////////////////////////////////
int32_t openssl_ec_key_gen_with_prikey(char *p_path, int32_t ec_algo, char *p_prikey_str) 
{
    int32_t ret = ERROR_;
    EVP_PKEY *pkey = NULL;

    DBG_PRINT(DBG_UTIL, DBG_TRACE, (void *)"(%s)\n",  __FUNCTION__);
    
    if(!p_prikey_str) return (ret);

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

                                if (p_path)
                                {
                                    char pubkey_dir[SSL_PATH_SIZE];
                                    char prikey_dir[SSL_PATH_SIZE];
                                    
                                    sprintf(pubkey_dir, "%s%s", p_path, (char *)"pubkey.pem");
                                    sprintf(prikey_dir, "%s%s", p_path, (char *)"privkey.pem");

                                    // ED Private Key
                                    PEM_new_write_PRIKEY(prikey_dir, pkey);
                                    
                                    // ED Public Key
                                    PEM_new_write_PUBKEY(pubkey_dir, pkey);
                                }
                                else
                                {
                                    PEM_new_write_PUBKEY((char *)"pubkey.pem", pkey);
                                    PEM_new_write_PRIKEY((char *)"privkey.pem", pkey);
                                }
                                // PEM_new_write_PUBKEY((char *)"pubkey.pem", pkey);
                                // PEM_new_write_PRIKEY((char *)"privkey.pem", pkey);

                                ret = SUCCESS_;
                            }while(0);
                            
                            EVP_PKEY_free(pkey);
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
    
    return (ret);
}

//
int32_t openssl_ec_key_gen(char *p_path, int32_t ec_algo)
{
    EC_KEY* eckey = NULL;
    EVP_PKEY* pkey = NULL;
    int32_t ret = ERROR_;

    DBG_PRINT(DBG_UTIL, DBG_TRACE, (void *)"(%s)\n",  __FUNCTION__);

    // These function calls initialize openssl for correct work.  
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    do
    {
        // Create a EC key sructure, setting the group type from NID
        eckey = EC_KEY_new_by_curve_name(ec_algo);
        if(!eckey) return ret;

        do

        {
            // For cert signing, we use the OPENSSL_EC_NAMED_CURVE flag
            EC_KEY_set_asn1_flag(eckey, OPENSSL_EC_NAMED_CURVE);

            // Create the public/private EC key pair here
            if (!EC_KEY_generate_key(eckey))
            {
                break;
            }

            EC_KEY_print(eckey);

            // Converting the EC key into a PKEY structure let us
            // handle the key just like any other key pair./
            pkey = EVP_PKEY_new();
            if(!pkey) break;

            do
            {
                if (!EVP_PKEY_assign_EC_KEY(pkey, eckey)) break;

                // Now we show how to extract EC-specifics from the key
                eckey = EVP_PKEY_get1_EC_KEY(pkey);

                EVP_PKEY_set1_EC_KEY(pkey, eckey);

                if (p_path)
                {
                    char pubkey_dir[SSL_PATH_SIZE];
                    char prikey_dir[SSL_PATH_SIZE];
                    
                    sprintf(pubkey_dir, "%s%s", p_path, (char *)"pubkey.pem");
                    sprintf(prikey_dir, "%s%s", p_path, (char *)"privkey.pem");

                    // ED Private Key
                    PEM_new_write_PRIKEY(prikey_dir, pkey);
                    
                    // ED Public Key
                    PEM_new_write_PUBKEY(pubkey_dir, pkey);
                }
                else
                {
                    PEM_new_write_PUBKEY((char *)"pubkey.pem", pkey);
                    PEM_new_write_PRIKEY((char *)"privkey.pem", pkey);
                }

                ret = SUCCESS_;
            } while(0);
            EVP_PKEY_free(pkey);
        } while(0);
        
        EC_KEY_free(eckey);
    }while(0);

    return (ret);
}

///////////////////////////////////////////////////////////////////////
//
int32_t openssl_ec_pubkey_decompress(char *p_comp_pubkey, char *p_uncomp_pubkey, int32_t ec_algo)
{
    int32_t ret = ERROR_;
    EC_KEY *eckey;

    DBG_PRINT(DBG_UTIL, DBG_TRACE, (void *)"(%s)\n",  __FUNCTION__);

    eckey = EC_KEY_new();
    if(!eckey) return ret;

    do
    {
        EC_GROUP* ecgroup = EC_GROUP_new_by_curve_name(ec_algo);
        if(!ecgroup) break;
        
        EC_KEY_set_group(eckey, ecgroup);
        EC_KEY_set_asn1_flag(eckey, OPENSSL_EC_NAMED_CURVE);
        
        DBG_PRINT(DBG_UTIL, DBG_NONE, (void *)"Compressed PubKey:  %s \n", p_comp_pubkey);

        do
        {
            
            EC_POINT* pubkey = EC_POINT_new(ecgroup);
            if(!pubkey) break;

            EC_POINT_hex2point(ecgroup, (const char*)p_comp_pubkey, pubkey, NULL);

            do
            {
                char *uncomp_pubkey_str;

                uncomp_pubkey_str = EC_POINT_point2hex(ecgroup, pubkey, POINT_CONVERSION_UNCOMPRESSED, NULL);
                if(!uncomp_pubkey_str) break;
                
                STRCPY_M(p_uncomp_pubkey, uncomp_pubkey_str);
                
                DBG_PRINT(DBG_UTIL, DBG_NONE, (void *)"Uncompressed PubKey:  %s \n", p_uncomp_pubkey);

                OPENSSL_free(uncomp_pubkey_str);
                
                ret = SUCCESS_;
            }while(0);
            
            EC_POINT_free(pubkey);
            
        }while(0);
        EC_GROUP_free(ecgroup);
        
    }while(0);
    EC_KEY_free(eckey);
    
    return (ret);
}

int32_t openssl_ec_pubkey_compress(char *p_uncomp_pubkey, char *p_comp_pubkey, int32_t ec_algo)
{ // temporary
    int32_t ret = ERROR_;
    
    EC_KEY *eckey;

    DBG_PRINT(DBG_UTIL, DBG_TRACE, (void *)"(%s)\n",  __FUNCTION__);

    eckey = EC_KEY_new();
    if(!eckey) return ret;

    do
    {
        EC_GROUP* ecgroup = EC_GROUP_new_by_curve_name(ec_algo);
        if(!ecgroup) break;
        
        EC_KEY_set_group(eckey, ecgroup);
        EC_KEY_set_asn1_flag(eckey, OPENSSL_EC_NAMED_CURVE);

        DBG_PRINT(DBG_UTIL, DBG_NONE, (void *)"Uncompressed PubKey:  %s \n", p_uncomp_pubkey);

        do 
        {
            EC_POINT* pubkey = EC_POINT_new(ecgroup);
            if(!pubkey) break;
            EC_POINT_hex2point(ecgroup, (const char*)p_uncomp_pubkey, pubkey, NULL);

            do
            {
                char *comp_pubkey_str;
                
                comp_pubkey_str = EC_POINT_point2hex(ecgroup, pubkey, POINT_CONVERSION_COMPRESSED, NULL);
                if(!comp_pubkey_str) break;
                
                STRCPY_M(p_comp_pubkey, comp_pubkey_str);

                DBG_PRINT(DBG_UTIL, DBG_NONE, (void *)"Compressed PubKey:  %s \n", p_comp_pubkey);

                OPENSSL_free(comp_pubkey_str);

                ret = SUCCESS_;
            }while(0);
            EC_POINT_free(pubkey);
            
        }while(0);
        EC_GROUP_free(ecgroup);
        
    }while(0);
    EC_KEY_free(eckey);
    
    return (ret);
}
