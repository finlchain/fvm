/**
 * Description : 
 *
 * @date 2021/01/21
 * @author FINL Chain Team
 * @version 1.0
 */

#include "cpp_if.hpp"

//
std::string curl_http_get_proc(std::string url, std::string fields)
{
    int32_t ret = ERROR_;
    std::string url_rtn_str = STR_ERROR_;

    //
    if (chkUndefinedStr(url) == 0)
    {
        return (url_rtn_str);
    }

    //
    if (chkUndefinedStr(fields) == 0)
    {
        return (url_rtn_str);
    }

    //
    STRING_T ret_str;

    //
    init_string(&ret_str);
    
    ret = curl_http_get((char *)url.c_str(), (char *)fields.c_str(), &ret_str);

    if (ret == SUCCESS_)
    {
        url_rtn_str = ret_str.p_ptr;
    }

    //
    free_string(&ret_str);

    return (url_rtn_str);
}

//
std::string curl_http_post_proc(std::string url, std::string fields)
{
    int32_t ret = ERROR_;
    std::string url_rtn_str = STR_ERROR_;

    //
    if (chkUndefinedStr(url) == 0)
    {
        return (url_rtn_str);
    }

    //
    if (chkUndefinedStr(fields) == 0)
    {
        return (url_rtn_str);
    }

    //
    STRING_T ret_str;

    //
    init_string(&ret_str);
    
    ret = curl_http_post((char *)url.c_str(), (char *)fields.c_str(), &ret_str);

    if (ret == SUCCESS_)
    {
        url_rtn_str = ret_str.p_ptr;
    }

    //
    free_string(&ret_str);

    return (url_rtn_str);
}

////////////////////////////////////////////////////////////////////////
//
int32_t openssl_ec_keygen_with_mnemonic_proc(std::string path, int32_t ec_algo, std::string pw, std::string mnemonic1, std::string mnemonic2, uint32_t rand_num)
{
    int32_t ret = ERROR_;

    //
    if (chkUndefinedStr(path) == 0)
    {
        return (ret);
    }

    //
    if (chkUndefinedStr(pw) == 0)
    {
        return (ret);
    }

    //
    if (chkUndefinedStr(mnemonic1) == 0)
    {
        return (ret);
    }

    //
    if (chkUndefinedStr(mnemonic2) == 0)
    {
        return (ret);
    }

    // //
    // std::string PrikeyStr = "";
    // uint8_t *p_prikey = OPENSSL_hexstr2buf(PrikeyStr.c_str(), NULL);

    //
    uint8_t prikey[PRIKEY_SIZE];
    // int32_t rand_num = 1;

    // if (!mnemonic1.length() && !mnemonic2.length())
    // {
    //     for (int32_t idx = 0; idx < PRIKEY_SIZE; idx++)
    //     {
    //         prikey[idx] = util_randint(1, 255);
    //     }
    // }
    // else
    // {
    //     for (int32_t idx = 0; idx < PRIKEY_SIZE; idx++)
    //     {
    //         prikey[idx] = util_randint(1, 255);
    //     }
    // }

    //
    uint8_t chain_code[HMAC_SHA_512_MAX_SIZE];
    int32_t chain_code_len = key_master((char *)pw.c_str(), (char *)mnemonic1.c_str(), (char *)mnemonic2.c_str(), &rand_num, chain_code);
    if (chain_code_len > 0)
    {
        // std::string chain_code_str = ByteToHexString(chain_code, chain_code_len);

        // std::cout << "Chain Code : " << chain_code_str << "\n";

        MEMCPY_M(prikey, chain_code, PRIKEY_SIZE);
    }
    else
    {
        return (ret);
    }
    
    //
    uint8_t *p_prikey = prikey;
    // DBG_DUMP(DBG_UTIL, DBG_INFO, (void *) "p_prikey ec", (uint8_t *)p_prikey, PRIKEY_SIZE);

    //
    char prikey_str[PRIKEY_STR_SIZE];
    util_hex2str_temp(p_prikey, PRIKEY_SIZE, prikey_str, PRIKEY_STR_SIZE, false);

    //
    ret = openssl_ec_key_gen_with_prikey((char *)path.c_str(), ec_algo, (char *)prikey_str);
    if (ret == SUCCESS_) ret = rand_num;

    return (ret);
}

//
int32_t openssl_ec_keygen_with_mnemonic_ori_proc(std::string path, int32_t ec_algo, std::string mnemonic1, std::string pw)
{
    int32_t ret = ERROR_;

    //
    if (chkUndefinedStr(path) == 0)
    {
        return (ret);
    }

    //
    if (chkUndefinedStr(pw) == 0)
    {
        return (ret);
    }

    //
    if (chkUndefinedStr(mnemonic1) == 0)
    {
        return (ret);
    }

    // //
    // std::string PrikeyStr = "";
    // uint8_t *p_prikey = OPENSSL_hexstr2buf(PrikeyStr.c_str(), NULL);

    //
    uint8_t prikey[PRIKEY_SIZE];
    // int32_t rand_num = 1;

    // if (!mnemonic1.length())
    // {
    //     for (int32_t idx = 0; idx < PRIKEY_SIZE; idx++)
    //     {
    //         prikey[idx] = util_randint(1, 255);
    //     }
    // }
    // else
    // {
    //     for (int32_t idx = 0; idx < PRIKEY_SIZE; idx++)
    //     {
    //         prikey[idx] = util_randint(1, 255);
    //     }
    // }

    //
    uint8_t chain_code[HMAC_SHA_512_MAX_SIZE];
    int32_t chain_code_len = key_master_ori((char *)mnemonic1.c_str(), (char *)pw.c_str(), chain_code);
    if (chain_code_len > 0)
    {
        // std::string chain_code_str = ByteToHexString(chain_code, chain_code_len);

        // std::cout << "Chain Code : " << chain_code_str << "\n";

        MEMCPY_M(prikey, chain_code, PRIKEY_SIZE);
    }
    else
    {
        return (ret);
    }
    
    //
    uint8_t *p_prikey = prikey;
    // DBG_DUMP(DBG_UTIL, DBG_INFO, (void *) "p_prikey ec", (uint8_t *)p_prikey, PRIKEY_SIZE);

    //
    char prikey_str[PRIKEY_STR_SIZE];
    util_hex2str_temp(p_prikey, PRIKEY_SIZE, prikey_str, PRIKEY_STR_SIZE, false);

    //
    ret = openssl_ec_key_gen_with_prikey((char *)path.c_str(), ec_algo, (char *)prikey_str);

    return (ret);
}

//
int32_t openssl_ec_keygen_proc(std::string path, int32_t ec_algo)
{
	int32_t ret = ERROR_;

	//
	if (chkUndefinedStr(path) == 0)
	{
		return (ret);
	}

	//
	ret = openssl_ec_key_gen((char *)path.c_str(), ec_algo);

	return (ret);
}

//
std::string openssl_ecdsa_sig_hex(std::string prikey, std::string data, int32_t ec_algo)
{
    //
	std::string signature = STR_ERROR_;

	//
	if ((chkUndefinedStr(data) == 0) || (chkUndefinedStr(prikey) == 0))
	{
		return (signature);
	}

    //
	EVP_PKEY *p_pkey = NULL;

	//
	p_pkey = openssl_get_ec_pkey((char *)prikey.c_str(), ec_algo);
	if (p_pkey)
	{
		int32_t ret = ERROR_;
		SSL_SIG_U *p_sig_hex = (SSL_SIG_U *)MALLOC_M(sizeof(SSL_SIG_U));

		uint8_t *p_data = OPENSSL_hexstr2buf(data.c_str(), NULL);
		uint32_t data_len = data.length()/2;

		ret = openssl_ecdsa_sig(p_pkey, p_data, data_len, p_sig_hex);
		OPENSSL_free(p_data);

		if (ret == SUCCESS_)
		{
			signature = ByteToHexString(p_sig_hex->sig, SIG_SIZE);
			
		}

		// std::cout << "SIG : " << signature << "\n";
		
		FREE_M(p_sig_hex);

        EVP_PKEY_free(p_pkey);
	}
    else
	{
		std::cout << "Error : p_pkey\n";
	}
	
	return (signature);
}

//
std::string openssl_ecdsa_sig_pem(bool b_enc, std::string prikey_path, std::string data)
{
    //
	std::string signature = STR_ERROR_;

	//
	if ((chkUndefinedStr(data) == 0) || (chkUndefinedStr(prikey_path) == 0))
	{
		return (signature);
	}

    //
	EVP_PKEY *p_pkey = NULL;

	//
	p_pkey = openssl_get_pkey(b_enc, (char *)prikey_path.c_str());
	if (p_pkey)
	{
		int32_t ret = ERROR_;
		SSL_SIG_U *p_sig_hex = (SSL_SIG_U *)MALLOC_M(sizeof(SSL_SIG_U));

		uint8_t *p_data = OPENSSL_hexstr2buf(data.c_str(), NULL);
		uint32_t data_len = data.length()/2;

		ret = openssl_ecdsa_sig(p_pkey, p_data, data_len, p_sig_hex);
		OPENSSL_free(p_data);

		if (ret == SUCCESS_)
		{
			signature = ByteToHexString(p_sig_hex->sig, SIG_SIZE);
		}

		// std::cout << "SIG : " << signature << "\n";
		
		FREE_M(p_sig_hex);

        EVP_PKEY_free(p_pkey);
	}
    else
	{
		std::cout << "Error : p_pkey\n";
	}
	
	return (signature);
}

//
int32_t openssl_ecdsa_verify_hex(std::string data, std::string sig_r, std::string sig_s, std::string comp_pubkey, int32_t ec_algo)
{
    int32_t ret = ERROR_;

	//
	if ((chkUndefinedStr(data) == 0) || (chkUndefinedStr(sig_r) == 0) || (chkUndefinedStr(sig_s) == 0) || (chkUndefinedStr(comp_pubkey) == 0))
	{
		return (ret);
	}

	//
    // uint8_t data_hash[HASH_SIZE];
    SSL_SIG_U sig_hex;

    //
    uint8_t *p_data = OPENSSL_hexstr2buf(data.c_str(), NULL);
    uint8_t *p_sig_r = OPENSSL_hexstr2buf(sig_r.c_str(), NULL);
    uint8_t *p_sig_s = OPENSSL_hexstr2buf(sig_s.c_str(), NULL);
    uint8_t *p_comp_pubkey = OPENSSL_hexstr2buf(comp_pubkey.c_str(), NULL);
    uint32_t data_len = data.length()/2;

    MEMCPY_M(sig_hex.ec.r, p_sig_r, SIG_R_SIZE);
    MEMCPY_M(sig_hex.ec.s, p_sig_s, SIG_S_SIZE);

    DBG_PRINT (DBG_UTIL, DBG_INFO, (void *)"data_len(%d) : p_data(%s)\n", data_len, data.c_str());
    DBG_PRINT (DBG_UTIL, DBG_INFO, (void *)"sig_r(%s)\n", sig_r.c_str());
    DBG_PRINT (DBG_UTIL, DBG_INFO, (void *)"sig_s(%s)\n", sig_s.c_str());
    DBG_PRINT (DBG_UTIL, DBG_INFO, (void *)"comp_pubkey(%s)\n", comp_pubkey.c_str());
    DBG_PRINT (DBG_UTIL, DBG_INFO, (void *)"ec_algo(%d)\n", ec_algo);


    ret = openssl_ecdsa_verify(p_data, data_len, &sig_hex, p_comp_pubkey, ec_algo);

	OPENSSL_free(p_data);
	OPENSSL_free(p_sig_r);
	OPENSSL_free(p_sig_s);
	OPENSSL_free(p_comp_pubkey);

    return (ret);
}

///////////////////////////////////////
//
std::string openssl_ec_prikey_pem2hex_proc(bool b_enc, std::string prikey_path)
{
    //
	std::string prikey_str = STR_ERROR_;

	//
	if (chkUndefinedStr(prikey_path) == 0)
	{
		return (prikey_str);
	}

    //
	int32_t ret;
	uint8_t prikey[PRIKEY_SIZE];

	//
	ret = openssl_ec_prikey_pem2hex(b_enc, (char *)prikey_path.c_str(), prikey);

	DBG_DUMP(DBG_UTIL, DBG_NONE, (void *)"prikey", prikey, PRIKEY_SIZE);

	if (ret == SUCCESS_)
	{
		prikey_str = ByteToHexString(prikey, PRIKEY_SIZE);
	}

	return (prikey_str);
}

//
std::string openssl_ec_pubkey_pem2hex_proc(std::string pubkey_path, int32_t ec_algo)
{
    //
	std::string pubkey_str = STR_ERROR_;

	//
	if (chkUndefinedStr(pubkey_path) == 0)
	{
		return (pubkey_str);
	}

    //
	int32_t ret;
	uint8_t pubkey[COMP_PUBKEY_SIZE];

	//
	ret = openssl_ec_pubkey_pem2hex((char *)pubkey_path.c_str(), pubkey, ec_algo);

	DBG_DUMP(DBG_UTIL, DBG_INFO, (void *)"2 pubkey", pubkey, COMP_PUBKEY_SIZE);

	if (ret == SUCCESS_)
	{
		pubkey_str = ByteToHexString(pubkey, COMP_PUBKEY_SIZE);
	}

	// std::cout << "pubkey_str : " << pubkey_str << "\n";

	return (pubkey_str);
}

///////////////////////////////////////
//
std::string openssl_ed_prikey_pemstr2hex_proc(std::string pem_str)
{
    //
    std::string prikey_str = STR_ERROR_;

    //
    if (chkUndefinedStr(pem_str) == 0)
    {
        return (prikey_str);
    }

    //
    int32_t ret;
    uint8_t prikey[X25519_PRIVATE_KEY_LEN_];

    //
    ret = openssl_ed_prikey_pemstr2hex((char *)pem_str.c_str(), prikey);

    DBG_DUMP(DBG_UTIL, DBG_NONE, (void *)"prikey", prikey, X25519_PRIVATE_KEY_LEN_);

    if (ret == SUCCESS_)
    {
        prikey_str = ByteToHexString(prikey, X25519_PRIVATE_KEY_LEN_);
    }

    // std::cout << "prikey_str : " << prikey_str << "\n";

    return (prikey_str);
}

std::string openssl_ed_pubkey_pemstr2hex_proc(std::string pem_str)
{
    std::string pubkey_str = STR_ERROR_;

    //
    if (chkUndefinedStr(pem_str) == 0)
    {
        return (pubkey_str);
    }

    //
    int32_t ret;
    uint8_t pubkey[ED25519_PUBLIC_KEY_LEN_];

    //
    ret = openssl_ed_pubkey_pemstr2hex((char *)pem_str.c_str(), pubkey);

    if (ret == SUCCESS_)
    {
        pubkey_str = ByteToHexString(pubkey, ED25519_PUBLIC_KEY_LEN_);
    }

    // // std::cout << "pubkey_str : " << pubkey_str << "\n";

    return (pubkey_str);
}

//
std::string openssl_ed_prikey_pem2hex_proc(bool b_enc, std::string prikey_path)
{
    //
    std::string prikey_str = STR_ERROR_;

    //
    if (chkUndefinedStr(prikey_path) == 0)
    {
        return (prikey_str);
    }

    //
    int32_t ret;
    uint8_t prikey[X25519_PRIVATE_KEY_LEN_];

    //
    ret = openssl_ed_prikey_pem2hex(b_enc, (char *)prikey_path.c_str(), prikey);

    DBG_DUMP(DBG_UTIL, DBG_NONE, (void *)"prikey", prikey, X25519_PRIVATE_KEY_LEN_);

    if (ret == SUCCESS_)
    {
        prikey_str = ByteToHexString(prikey, X25519_PRIVATE_KEY_LEN_);
    }

    // std::cout << "prikey_str : " << prikey_str << "\n";

    return (prikey_str);
}

//
std::string openssl_ed_pubkey_pem2hex_proc(std::string pubkey_path)
{
    std::string pubkey_str = STR_ERROR_;

    //
    if (chkUndefinedStr(pubkey_path) == 0)
    {
        return (pubkey_str);
    }

    //
    int32_t ret;
    uint8_t pubkey[ED25519_PUBLIC_KEY_LEN_];

    //
    ret = openssl_ed_pubkey_pem2hex((char *)pubkey_path.c_str(), pubkey);

    if (ret == SUCCESS_)
    {
        pubkey_str = ByteToHexString(pubkey, ED25519_PUBLIC_KEY_LEN_);
    }

    // // std::cout << "pubkey_str : " << pubkey_str << "\n";

    return (pubkey_str);
}

//
int32_t openssl_ed25519_keygen_with_mnemonic_proc(std::string path, std::string pw, std::string mnemonic1, std::string mnemonic2, uint32_t rand_num)
{
    int32_t ret = ERROR_;

    //
    if (chkUndefinedStr(path) == 0)
    {
        return (ret);
    }

    //
    if (chkUndefinedStr(pw) == 0)
    {
        return (ret);
    }

    //
    if (chkUndefinedStr(mnemonic1) == 0)
    {
        return (ret);
    }

    //
    if (chkUndefinedStr(mnemonic2) == 0)
    {
        return (ret);
    }

    // //
    // std::string PrikeyStr = "";
    // uint8_t *p_prikey = OPENSSL_hexstr2buf(PrikeyStr.c_str(), NULL);

    //
    uint8_t prikey[X25519_PRIVATE_KEY_LEN_];
    // int32_t rand_num = 1;

    // //
    // if (!mnemonic1.length() && !mnemonic2.length())
    // {
    //     for (int32_t idx = 0; idx < X25519_PRIVATE_KEY_LEN_; idx++)
    //     {
    //         prikey[idx] = util_randint(1, 255);
    //     }
    // }
    // else
    // {
    //     for (int32_t idx = 0; idx < X25519_PRIVATE_KEY_LEN_; idx++)
    //     {
    //         prikey[idx] = util_randint(1, 255);
    //     }
    // }

    //
    uint8_t chain_code[HMAC_SHA_512_MAX_SIZE];
    int32_t chain_code_len = key_master((char *)pw.c_str(), (char *)mnemonic1.c_str(), (char *)mnemonic2.c_str(), &rand_num, chain_code);
    if (chain_code_len > 0)
    {
        // std::string chain_code_str = ByteToHexString(chain_code, chain_code_len);

        // std::cout << "Chain Code : " << chain_code_str << "\n";

        MEMCPY_M(prikey, chain_code, PRIKEY_SIZE);
    }
    else
    {
        return (ret);
    }

    //
    uint8_t *p_prikey = prikey;
    // DBG_DUMP(DBG_UTIL, DBG_INFO, (void *) "p_prikey 1", (uint8_t *)p_prikey, X25519_PRIVATE_KEY_LEN_);

    //
    ret = openssl_ed25519_keygen_with_prikey((char *)path.c_str(), (char *)p_prikey);
    if (ret == SUCCESS_) ret = rand_num;

    return (ret);
}

//
int32_t openssl_ed25519_keygen_with_mnemonic_ori_proc(std::string path, std::string mnemonic1, std::string pw)
{
    int32_t ret = ERROR_;

    //
    if (chkUndefinedStr(path) == 0)
    {
        return (ret);
    }

    //
    if (chkUndefinedStr(pw) == 0)
    {
        return (ret);
    }

    //
    if (chkUndefinedStr(mnemonic1) == 0)
    {
        return (ret);
    }

    // //
    // std::string PrikeyStr = "";
    // uint8_t *p_prikey = OPENSSL_hexstr2buf(PrikeyStr.c_str(), NULL);

    //
    uint8_t prikey[X25519_PRIVATE_KEY_LEN_];

    // //
    // if (!mnemonic1.length())
    // {
    //     for (int32_t idx = 0; idx < X25519_PRIVATE_KEY_LEN_; idx++)
    //     {
    //         prikey[idx] = util_randint(1, 255);
    //     }
    // }
    // else
    // {
    //     for (int32_t idx = 0; idx < X25519_PRIVATE_KEY_LEN_; idx++)
    //     {
    //         prikey[idx] = util_randint(1, 255);
    //     }
    // }

    //
    uint8_t chain_code[HMAC_SHA_512_MAX_SIZE];
    int32_t chain_code_len = key_master_ori((char *)mnemonic1.c_str(), (char *)pw.c_str(), chain_code);
    if (chain_code_len > 0)
    {
        // std::string chain_code_str = ByteToHexString(chain_code, chain_code_len);

        // std::cout << "Chain Code : " << chain_code_str << "\n";

        MEMCPY_M(prikey, chain_code, PRIKEY_SIZE);
    }
    else
    {
        return (ret);
    }

    //
    uint8_t *p_prikey = prikey;
    // DBG_DUMP(DBG_UTIL, DBG_INFO, (void *) "p_prikey 1", (uint8_t *)p_prikey, X25519_PRIVATE_KEY_LEN_);

    //
    ret = openssl_ed25519_keygen_with_prikey((char *)path.c_str(), (char *)p_prikey);

    return (ret);
}

//
int32_t openssl_ed25519_keygen_proc(std::string path)
{
	int32_t ret = ERROR_;

	//
	if (chkUndefinedStr(path) == 0)
	{
		return (ret);
	}
	
	//
	ret = openssl_ed25519_keygen((char *)path.c_str());

	return (ret);
}

//
int32_t openssl_ed25519_keygen_pubkey_proc(std::string path)
{
	int32_t ret = ERROR_;

	//
	if (chkUndefinedStr(path) == 0)
	{
		return (ret);
	}

	//
	ret = openssl_ed25519_keygen_pubkey((char *)path.c_str());

	return (ret);
}

//
int32_t openssl_ed25519_keygen_fin_with_mnemonic_proc(std::string path, std::string pw, std::string mnemonic1, std::string mnemonic2, uint32_t rand_num, std::string seed, uint32_t seed_len)
{
    int32_t ret = ERROR_;

    //
    if ((chkUndefinedStr(path) == 0) || (seed.length() != seed_len))
    {
        return (ret);
    }

    //
    if (chkUndefinedStr(mnemonic1) == 0)
    {
        return (ret);
    }

    //
	if (chkUndefinedStr(mnemonic2) == 0)
	{
		return (ret);
	}

    // //
    // std::string PrikeyStr = "";
    // uint8_t *p_prikey = OPENSSL_hexstr2buf(PrikeyStr.c_str(), NULL);

    //
    uint8_t prikey[X25519_PRIVATE_KEY_LEN_];
    // int32_t rand_num = 1;

    // //
    // if (!mnemonic1.length() && !mnemonic2.length())
    // {
    //     for (int32_t idx = 0; idx < X25519_PRIVATE_KEY_LEN_; idx++)
    //     {
    //         prikey[idx] = util_randint(1, 255);
    //     }
    // }
    // else
    // {
    //     for (int32_t idx = 0; idx < X25519_PRIVATE_KEY_LEN_; idx++)
    //     {
    //         prikey[idx] = util_randint(1, 255);
    //     }
    // }

    //
    uint8_t chain_code[HMAC_SHA_512_MAX_SIZE];
    int32_t chain_code_len = key_master((char *)pw.c_str(), (char *)mnemonic1.c_str(), (char *)mnemonic2.c_str(), &rand_num, chain_code);
    if (chain_code_len > 0)
    {
        // std::string chain_code_str = ByteToHexString(chain_code, chain_code_len);

        // std::cout << "Chain Code : " << chain_code_str << "\n";

        MEMCPY_M(prikey, chain_code, PRIKEY_SIZE);
    }
    else
    {
        return (ret);
    }

    //
    uint8_t *p_prikey = prikey;
    // DBG_DUMP(DBG_UTIL, DBG_INFO, (void *) "p_prikey 1", (uint8_t *)p_prikey, X25519_PRIVATE_KEY_LEN_);

    //
    uint8_t *p_seed = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(seed.c_str()));

    ret = openssl_ed25519_keygen_fin_with_prikey((char *)path.c_str(), (char *)p_prikey, p_seed, seed_len);
    if (ret == SUCCESS_) ret = rand_num;

    return (ret);
}

//
int32_t openssl_ed25519_keygen_fin_with_mnemonic_ori_proc(std::string path, std::string mnemonic1, std::string pw, std::string seed, uint32_t seed_len)
{
    int32_t ret = ERROR_;

    //
    if ((chkUndefinedStr(path) == 0) || (seed.length() != seed_len))
    {
        return (ret);
    }

    //
    if (chkUndefinedStr(mnemonic1) == 0)
    {
        return (ret);
    }

    // //
    // std::string PrikeyStr = "";
    // uint8_t *p_prikey = OPENSSL_hexstr2buf(PrikeyStr.c_str(), NULL);

    //
    uint8_t prikey[X25519_PRIVATE_KEY_LEN_];

    // //
    // if (!mnemonic1.length() && !mnemonic2.length())
    // {
    //     for (int32_t idx = 0; idx < X25519_PRIVATE_KEY_LEN_; idx++)
    //     {
    //         prikey[idx] = util_randint(1, 255);
    //     }
    // }
    // else
    // {
    //     for (int32_t idx = 0; idx < X25519_PRIVATE_KEY_LEN_; idx++)
    //     {
    //         prikey[idx] = util_randint(1, 255);
    //     }
    // }

    //
    uint8_t chain_code[HMAC_SHA_512_MAX_SIZE];
    int32_t chain_code_len = key_master_ori((char *)mnemonic1.c_str(), (char *)pw.c_str(), chain_code);
    if (chain_code_len > 0)
    {
        // std::string chain_code_str = ByteToHexString(chain_code, chain_code_len);

        // std::cout << "Chain Code : " << chain_code_str << "\n";

        MEMCPY_M(prikey, chain_code, PRIKEY_SIZE);
    }
    else
    {
        return (ret);
    }
    
    //
    uint8_t *p_prikey = prikey;
    // DBG_DUMP(DBG_UTIL, DBG_INFO, (void *) "p_prikey 1", (uint8_t *)p_prikey, X25519_PRIVATE_KEY_LEN_);

    //
    uint8_t *p_seed = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(seed.c_str()));

    ret = openssl_ed25519_keygen_fin_with_prikey((char *)path.c_str(), (char *)p_prikey, p_seed, seed_len);

    return (ret);
}

//
int32_t openssl_ed25519_keygen_fin_proc(std::string path, std::string seed, uint32_t seed_len)
{
	int32_t ret = ERROR_;

	//
	if ((chkUndefinedStr(path) == 0) || (seed.length() != seed_len))
	{
		return (ret);
	}

	//
	uint8_t *p_seed = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(seed.c_str()));

	ret = openssl_ed25519_keygen_fin((char *)path.c_str(), p_seed, seed_len);

	return (ret);
}

//
std::string openssl_ed25519_sig_hex(std::string prikey, std::string data)
{
	EVP_PKEY *p_pkey = NULL;

	std::string sig_str = STR_ERROR_;

	//
	if ((chkUndefinedStr(data) == 0) || (chkUndefinedStr(prikey) == 0))
	{
		return (sig_str);
	}

	//
	uint8_t *p_prikey = OPENSSL_hexstr2buf(prikey.c_str(), NULL);

	p_pkey = EVP_PKEY_new_read_PRIKEY_hex((char *)p_prikey, ED25519);
	if (p_pkey)
	{
		int32_t ret = ERROR_;
		SSL_SIG_U *p_sig_hex = (SSL_SIG_U *)MALLOC_M(sizeof(SSL_SIG_U));

		uint8_t *p_data = OPENSSL_hexstr2buf(data.c_str(), NULL);
		uint32_t data_len = data.length()/2;

		ret = openssl_111_ed25519_sig(p_pkey, p_data, data_len, p_sig_hex);
		OPENSSL_free(p_data);

		if (ret == SUCCESS_)
		{
			sig_str = ByteToHexString(p_sig_hex->sig, SIG_SIZE);
		}

		// std::cout << "SIG : " << sig_str << "\n";
		
		FREE_M(p_sig_hex);

		EVP_PKEY_free(p_pkey);
	}
	else
	{
		std::cout << "Error : p_pkey\n";
	}

	OPENSSL_free(p_prikey);
	
	return (sig_str);
}

std::string openssl_ed25519_sig_pem(bool b_enc, std::string prikey_path, std::string data)
{
	EVP_PKEY *p_pkey = NULL;

	std::string sig_str = STR_ERROR_;

	//
	if ((chkUndefinedStr(data) == 0) || (chkUndefinedStr(prikey_path) == 0))
	{
		return (sig_str);
	}

	//
	p_pkey = openssl_get_pkey(b_enc, (char *)prikey_path.c_str());
	if (p_pkey)
	{
		int32_t ret = ERROR_;
		SSL_SIG_U *p_sig_hex = (SSL_SIG_U *)MALLOC_M(sizeof(SSL_SIG_U));

		uint8_t *p_data = OPENSSL_hexstr2buf(data.c_str(), NULL);
		uint32_t data_len = data.length()/2;

		ret = openssl_111_ed25519_sig(p_pkey, p_data, data_len, p_sig_hex);
		OPENSSL_free(p_data);

		if (ret == SUCCESS_)
		{
			sig_str = ByteToHexString(p_sig_hex->sig, SIG_SIZE);
		}

		// std::cout << "SIG : " << sig_str << "\n";
		
		FREE_M(p_sig_hex);
	}
	else
	{
		std::cout << "Error : p_pkey\n";
	}
	
	return (sig_str);
}

//
int32_t openssl_ed25519_verify_hex(std::string data, std::string signature, std::string pubkey)
{
    int32_t ret = ERROR_;
    // uint8_t data_hash[HASH_SIZE];
    SSL_SIG_U sig_hex;

	//
	if ((chkUndefinedStr(data) == 0) || (chkUndefinedStr(signature) == 0) || (chkUndefinedStr(pubkey) == 0))
	{
		return (ret);
	}

    // 
    uint8_t *p_data = OPENSSL_hexstr2buf(data.c_str(), NULL);
    uint8_t *p_sig = OPENSSL_hexstr2buf(signature.c_str(), NULL);
    uint8_t *p_pubkey = OPENSSL_hexstr2buf(pubkey.c_str(), NULL);
    uint32_t data_len = data.length()/2;

	// // For Test
	// uint8_t *p_pubkey = OPENSSL_hexstr2buf("5261BF4F281EA120BB5E8B4DB319515F7D15E8CF041291C77942C1B606623BE7", NULL);
	// uint8_t *p_sig = OPENSSL_hexstr2buf("C790785068A8D991C8FD270B7F02ABAA819D995C0EE5E11D05D1FCBB330B176FC18CECA0EA6E7F5292D883ED1255A7AC0680BB5F86CDA8E6CF0A53DED127CF07", NULL);
	// uint8_t msg[] = "this is a test message";
	// uint8_t *p_data = msg;
	// uint32_t data_len = sizeof(msg);
	// ////////////////////////////////////////////////

    // DBG_PRINT(DBG_UTIL, DBG_INFO, (void *)"data_len : %d\n", data_len);

    MEMCPY_M(sig_hex.sig, p_sig, SIG_SIZE);

    ret = openssl_ed25519_verify(p_data, data_len, &sig_hex, p_pubkey);

	OPENSSL_free(p_data);
	OPENSSL_free(p_sig);
	OPENSSL_free(p_pubkey);
    
    return (ret);
}

//
std::string openssl_sha256_hex(std::string data_hex)
{
	//
    std::string hash_str = STR_ERROR_;

	//
	if ((chkUndefinedStr(data_hex) == 0) || (data_hex.length() % 2))
	{
		return (hash_str);
	}

	//
    uint8_t data_hash[HASH_SIZE];
    uint32_t data_len = data_hex.length()/2;

    uint8_t *p_data = OPENSSL_hexstr2buf(data_hex.c_str(), NULL);
    
    openssl_sha256(data_hash, (uint8_t *)p_data, data_len);
    hash_str = ByteToHexString(data_hash, HASH_SIZE);

    // std::cout << "HASH : " << hash_str << "\n";

	OPENSSL_free(p_data);

    return (hash_str);
}

std::string openssl_sha256_str(std::string data)
{
	//
    std::string hash_str = STR_ERROR_;

	//
	if (chkUndefinedStr(data) == 0)
	{
		return (hash_str);
	}

	//
    uint8_t data_hash[HASH_SIZE];
    uint32_t data_len = data.length();

    openssl_sha256(data_hash, (uint8_t *)data.c_str(), data_len);
    hash_str = ByteToHexString(data_hash, HASH_SIZE);

    // std::cout << "HASH : " << hash_str << "\n";

    return (hash_str);
}

//
//
int32_t openssl_x25519_keygen_with_mnemonic_proc(std::string path, std::string pw, std::string mnemonic1, std::string mnemonic2, uint32_t rand_num)
{
    int32_t ret = ERROR_;

    //
    if (chkUndefinedStr(path) == 0)
    {
        return (ret);
    }

    //
    if (chkUndefinedStr(mnemonic1) == 0)
    {
        return (ret);
    }

    //
    if (chkUndefinedStr(mnemonic2) == 0)
    {
        return (ret);
    }

    // //
    // std::string PrikeyStr = "";
    // uint8_t *p_prikey = OPENSSL_hexstr2buf(PrikeyStr.c_str(), NULL);

    //
    uint8_t prikey[X25519_PRIVATE_KEY_LEN_];
    // int32_t rand_num = 1;

    // if (!mnemonic1.length() && !mnemonic2.length())
    // {
    //     for (int32_t idx = 0; idx < X25519_PRIVATE_KEY_LEN_; idx++)
    //     {
    //         prikey[idx] = util_randint(1, 255);
    //     }
    // }
    // else
    // {
    //     for (int32_t idx = 0; idx < X25519_PRIVATE_KEY_LEN_; idx++)
    //     {
    //         prikey[idx] = util_randint(1, 255);
    //     }
    // }

    //
    uint8_t chain_code[HMAC_SHA_512_MAX_SIZE];
    int32_t chain_code_len = key_master((char *)pw.c_str(), (char *)mnemonic1.c_str(), (char *)mnemonic2.c_str(), &rand_num, chain_code);
    if (chain_code_len > 0)
    {
        // std::string chain_code_str = ByteToHexString(chain_code, chain_code_len);

        // std::cout << "Chain Code : " << chain_code_str << "\n";

        MEMCPY_M(prikey, chain_code, PRIKEY_SIZE);
    }
    else
    {
        return (ret);
    }

    //
    uint8_t *p_prikey = prikey;
    // DBG_DUMP(DBG_UTIL, DBG_INFO, (void *) "p_prikey 2", (uint8_t *)p_prikey, X25519_PRIVATE_KEY_LEN_);

    //
    ret = openssl_x25519_keygen_with_prikey((char *)path.c_str(), (char *)p_prikey);
    if (ret == SUCCESS_) ret = rand_num;

    return (ret);
}

//
int32_t openssl_x25519_keygen_with_mnemonic_ori_proc(std::string path, std::string mnemonic1, std::string pw)
{
    int32_t ret = ERROR_;

    //
    if (chkUndefinedStr(path) == 0)
    {
        return (ret);
    }

    //
    if (chkUndefinedStr(mnemonic1) == 0)
    {
        return (ret);
    }

    // //
    // std::string PrikeyStr = "";
    // uint8_t *p_prikey = OPENSSL_hexstr2buf(PrikeyStr.c_str(), NULL);

    //
    uint8_t prikey[X25519_PRIVATE_KEY_LEN_];
    // int32_t rand_num = 1;

    // if (!mnemonic1.length() && !mnemonic2.length())
    // {
    //     for (int32_t idx = 0; idx < X25519_PRIVATE_KEY_LEN_; idx++)
    //     {
    //         prikey[idx] = util_randint(1, 255);
    //     }
    // }
    // else
    // {
    //     for (int32_t idx = 0; idx < X25519_PRIVATE_KEY_LEN_; idx++)
    //     {
    //         prikey[idx] = util_randint(1, 255);
    //     }
    // }

    //
    uint8_t chain_code[HMAC_SHA_512_MAX_SIZE];
    int32_t chain_code_len = key_master_ori((char *)mnemonic1.c_str(), (char *)pw.c_str(), chain_code);
    if (chain_code_len > 0)
    {
        // std::string chain_code_str = ByteToHexString(chain_code, chain_code_len);

        // std::cout << "Chain Code : " << chain_code_str << "\n";

        MEMCPY_M(prikey, chain_code, PRIKEY_SIZE);
    }
    else
    {
        return (ret);
    }

    //
    uint8_t *p_prikey = prikey;
    // DBG_DUMP(DBG_UTIL, DBG_INFO, (void *) "p_prikey 2", (uint8_t *)p_prikey, X25519_PRIVATE_KEY_LEN_);

    //
    ret = openssl_x25519_keygen_with_prikey((char *)path.c_str(), (char *)p_prikey);

    return (ret);
}

//
int32_t openssl_x25519_keygen_proc(std::string path)
{
	int32_t ret = ERROR_;

	//
	if (chkUndefinedStr(path) == 0)
	{
		return (ret);
	}

	//
	ret = openssl_x25519_keygen((char *)path.c_str());

	return (ret);
}

std::string openssl_x25519_hex_skey(std::string prikey_hex, std::string peer_pubkey_hex)
{
	//
	std::string skey_str = STR_ERROR_;

	//
	if ((chkUndefinedStr(prikey_hex) == 0) || (chkUndefinedStr(peer_pubkey_hex) == 0))
	{
		return (skey_str);
	}

	//
	EVP_PKEY *p_prikey = NULL;
	EVP_PKEY *p_peer_pubkey = NULL;
	
	uint8_t *p_key1 = NULL;
	uint8_t *p_key2 = NULL;

	uint8_t *p_S_out = NULL;

	// std::cout << "prikey_hex : " << prikey_hex << "\n";
	// std::cout << "peer_pubkey_hex : " << peer_pubkey_hex << "\n";

	// 
	p_key1 = OPENSSL_hexstr2buf(prikey_hex.c_str(), NULL);
	p_prikey = EVP_PKEY_new_read_PRIKEY_hex((char *)p_key1, X25519);
	OPENSSL_free(p_key1);

	if (!p_prikey)
	{
		std::cout << "p_prikey error\n";
		return (skey_str);
	}

	// 
	p_key2 = OPENSSL_hexstr2buf(peer_pubkey_hex.c_str(), NULL);
	p_peer_pubkey = EVP_PKEY_new_read_PUBKEY_hex((char *)p_key2, X25519);
	OPENSSL_free(p_key2);

	if (!p_peer_pubkey)
	{
		std::cout << "p_peer_pubkey error\n";
		return (skey_str);
	}

#if (OPENSSL_111 == ENABLED)
    p_S_out = openssl_111_x25519(p_prikey, p_peer_pubkey);
    // ASSERT_M(p_S_out);
    if (!p_S_out)
    {
        return (skey_str);
    }
#elif (OPENSSL_102 == ENABLED)
    uint8_t password[X25519_SHARED_KEY_LEN_];

    p_S_out = password;

    X25519(p_S_out, p_prikey, p_peer_pubkey);
#endif // OPENSSL_111

	skey_str = ByteToHexString(p_S_out, X25519_SHARED_KEY_LEN_);

#if (OPENSSL_111 == ENABLED)
    OPENSSL_free(p_S_out);
#endif // OPENSSL_111

#if (OPENSSL_111 == ENABLED)
    EVP_PKEY_free(p_prikey);
    EVP_PKEY_free(p_peer_pubkey);
#endif // OPENSSL_111

    EVP_cleanup(); // free OpenSSL_add_all_algorithms()
    ERR_free_strings(); // free ERR_load_crypto_strings()

    // std::cout << "skey_str : " << skey_str << "\n";

    return (skey_str);
}

//
std::string openssl_x25519_pem_skey(std::string prikey_pem, std::string peer_pubkey_pem)
{
	//
	std::string skey_str = STR_ERROR_;

	//
	if ((chkUndefinedStr(prikey_pem) == 0) || (chkUndefinedStr(peer_pubkey_pem) == 0))
	{
		return (skey_str);
	}

	//
	EVP_PKEY *p_prikey = NULL;
	EVP_PKEY *p_peer_pubkey = NULL;

	uint8_t *p_S_out = NULL;

	// std::cout << "prikey_pem : " << prikey_pem << "\n";
	// std::cout << "peer_pubkey_pem : " << peer_pubkey_pem << "\n";

	//
	uint32_t prikey_len = prikey_pem.length();

	BIO *pri_b = BIO_new_mem_buf((void*)prikey_pem.c_str(), prikey_len);
	p_prikey = PEM_read_bio_PrivateKey(pri_b, NULL, NULL, NULL);

	if (!p_prikey)
	{
		std::cout << "p_prikey error\n";
		
		return (skey_str);
	}

	//
	uint32_t peer_pubkey_len = peer_pubkey_pem.length();
	BIO *pub_b = BIO_new_mem_buf((void*)peer_pubkey_pem.c_str(), peer_pubkey_len);
	p_peer_pubkey = PEM_read_bio_PUBKEY(pub_b, NULL, NULL, NULL);

	if (!p_peer_pubkey)
	{
		std::cout << "p_peer_pubkey error\n";
		return (skey_str);
	}

	//
#if (OPENSSL_111 == ENABLED)
    p_S_out = openssl_111_x25519(p_prikey, p_peer_pubkey);
    // ASSERT_M(p_S_out);
    if (!p_S_out)
    {
        return (skey_str);
    }
#elif (OPENSSL_102 == ENABLED)
    uint8_t password[X25519_SHARED_KEY_LEN_];

    p_S_out = password;

    X25519(p_S_out, p_prikey, p_peer_pubkey);
#endif // OPENSSL_111

	skey_str = ByteToHexString(p_S_out, X25519_SHARED_KEY_LEN_);

#if (OPENSSL_111 == ENABLED)
    OPENSSL_free(p_S_out);
#endif // OPENSSL_111

#if (OPENSSL_111 == ENABLED)
    EVP_PKEY_free(p_prikey);
    EVP_PKEY_free(p_peer_pubkey);
#endif // OPENSSL_111

	BIO_free(pub_b);
    BIO_free(pri_b);

    EVP_cleanup(); // free OpenSSL_add_all_algorithms()
    ERR_free_strings(); // free ERR_load_crypto_strings()

    // std::cout << "skey_str : " << skey_str << "\n";

    return (skey_str);
}

std::string openssl_x25519_mix_skey(std::string prikey_pem, std::string peer_pubkey_hex)
{
	//
	std::string skey_str = STR_ERROR_;

	//
	if ((chkUndefinedStr(prikey_pem) == 0) || (chkUndefinedStr(peer_pubkey_hex) == 0))
	{
		return (skey_str);
	}

	//
	EVP_PKEY *p_prikey = NULL;
	EVP_PKEY *p_peer_pubkey = NULL;
	
	uint8_t *p_key2 = NULL;

	uint8_t *p_S_out = NULL;

	// std::cout << "prikey_pem : " << prikey_pem << "\n";
	// std::cout << "peer_pubkey_hex : " << peer_pubkey_hex << "\n";

	//
	uint32_t prikey_len = prikey_pem.length();

	BIO *pri_b = BIO_new_mem_buf((void*)prikey_pem.c_str(), prikey_len);
	p_prikey = PEM_read_bio_PrivateKey(pri_b, NULL, NULL, NULL);

	if (!p_prikey)
	{
		std::cout << "p_prikey error\n";
		
		return (skey_str);
	}

	// 
	p_key2 = OPENSSL_hexstr2buf(peer_pubkey_hex.c_str(), NULL);
	p_peer_pubkey = EVP_PKEY_new_read_PUBKEY_hex((char *)p_key2, X25519);
	OPENSSL_free(p_key2);

	if (!p_peer_pubkey)
	{
		std::cout << "p_peer_pubkey error\n";
		return (skey_str);
	}

	//
#if (OPENSSL_111 == ENABLED)
    p_S_out = openssl_111_x25519(p_prikey, p_peer_pubkey);
    // ASSERT_M(p_S_out);
    if (!p_S_out)
    {
        return (skey_str);
    }
#elif (OPENSSL_102 == ENABLED)
    uint8_t password[X25519_SHARED_KEY_LEN_];

    p_S_out = password;

    X25519(p_S_out, p_prikey, p_peer_pubkey);
#endif // OPENSSL_111

	skey_str = ByteToHexString(p_S_out, X25519_SHARED_KEY_LEN_);

#if (OPENSSL_111 == ENABLED)
    OPENSSL_free(p_S_out);
#endif // OPENSSL_111

#if (OPENSSL_111 == ENABLED)
    EVP_PKEY_free(p_prikey);
    EVP_PKEY_free(p_peer_pubkey);
#endif // OPENSSL_111

    BIO_free(pri_b);

    EVP_cleanup(); // free OpenSSL_add_all_algorithms()
    ERR_free_strings(); // free ERR_load_crypto_strings()

    // std::cout << "skey_str : " << skey_str << "\n";

    return (skey_str);
}

//
std::string openssl_x25519_hex_enc(std::string prikey_hex, std::string peer_pubkey_hex, std::string plaintext_hex, uint32_t plaintext_hex_len)
{
	//
	std::string enc_msg_str = STR_ERROR_;

	//
	if ((chkUndefinedStr(prikey_hex) == 0) || (chkUndefinedStr(peer_pubkey_hex) == 0) || (chkUndefinedStr(plaintext_hex) == 0) || ((plaintext_hex.length() != plaintext_hex_len) || (plaintext_hex_len % 2)))
	{
		return (enc_msg_str);
	}

	//
	EVP_PKEY *p_prikey = NULL;
	EVP_PKEY *p_peer_pubkey = NULL;
	
	uint8_t *p_key1 = NULL;
	uint8_t *p_key2 = NULL;
	uint8_t *p_plaintext = NULL;
	uint32_t plaintext_len = 0;

    uint8_t *p_enc_msg = NULL;
    uint32_t enc_msg_len = 0;

	// std::cout << "prikey_hex : " << prikey_hex << "\n";
	// std::cout << "peer_pubkey_hex : " << peer_pubkey_hex << "\n";
	// std::cout << "plaintext_hex : " << plaintext_hex << "\n";


	// 
	p_key1 = OPENSSL_hexstr2buf(prikey_hex.c_str(), NULL);
	p_prikey = EVP_PKEY_new_read_PRIKEY_hex((char *)p_key1, X25519);
	OPENSSL_free(p_key1);

	if (!p_prikey)
	{
		std::cout << "p_prikey error\n";
		return (enc_msg_str);
	}

	// 
	p_key2 = OPENSSL_hexstr2buf(peer_pubkey_hex.c_str(), NULL);
	p_peer_pubkey = EVP_PKEY_new_read_PUBKEY_hex((char *)p_key2, X25519);
	OPENSSL_free(p_key2);

	if (!p_peer_pubkey)
	{
		std::cout << "p_peer_pubkey error\n";
		return (enc_msg_str);
	}

	// 
	p_plaintext = OPENSSL_hexstr2buf(plaintext_hex.c_str(), NULL);
	plaintext_len = plaintext_hex_len / 2;

	//
#if (X25519_AES_USE == ENABLED)
	enc_msg_len = plaintext_len + OPENSSL_X25519_MAC_LEN + OPENSSL_SYM_KEY_LEN + OPENSSL_EDIES_P2_LEN;
	p_enc_msg = (uint8_t *)MALLOC_M(enc_msg_len);

    openssl_x25519_aes_encrypt(p_prikey, p_peer_pubkey, NULL, 0, NULL, 0, p_plaintext, plaintext_len, p_enc_msg, &enc_msg_len);
#else
	enc_msg_len = plaintext_len + ARIA_BUFFER_SIZE;
	p_enc_msg = (uint8_t *)MALLOC_M(enc_msg_len);

	openssl_x25519_aria_encrypt(p_prikey, p_peer_pubkey, 16, p_plaintext, plaintext_len, p_enc_msg, &enc_msg_len);
#endif

    enc_msg_str = ByteToHexString(p_enc_msg, enc_msg_len);

	FREE_M(p_enc_msg);

	OPENSSL_free(p_plaintext);

#if (OPENSSL_111 == ENABLED)
    EVP_PKEY_free(p_prikey);
    EVP_PKEY_free(p_peer_pubkey);
#endif // OPENSSL_111

    EVP_cleanup(); // free OpenSSL_add_all_algorithms()
    ERR_free_strings(); // free ERR_load_crypto_strings()

    // std::cout << "enc_msg_str : " << enc_msg_str << "\n";

    return (enc_msg_str);
}

std::string openssl_x25519_hex_dec(std::string prikey_hex, std::string peer_pubkey_hex, std::string enc_msg_str, uint32_t enc_msg_str_len)
{
	//
	std::string plaintext_hex = STR_ERROR_;

	//
	if ((chkUndefinedStr(prikey_hex) == 0) || (chkUndefinedStr(peer_pubkey_hex) == 0) || (chkUndefinedStr(enc_msg_str) == 0) || ((enc_msg_str.length() != enc_msg_str_len) || (enc_msg_str_len % 2)))
	{
		return (plaintext_hex);
	}

	//
    int32_t ret = ERROR_;

	EVP_PKEY *p_prikey = NULL;
	EVP_PKEY *p_peer_pubkey = NULL;
	
	uint8_t *p_key1 = NULL;
	uint8_t *p_key2 = NULL;
	uint8_t *p_plaintext = NULL;
	uint32_t plaintext_len = 0;

    uint8_t *p_enc_msg = NULL;
    uint32_t enc_msg_len = 0;

	// std::cout << "prikey_hex : " << prikey_hex << "\n";
	// std::cout << "peer_pubkey_hex : " << peer_pubkey_hex << "\n";
	// std::cout << "enc_msg_str : " << enc_msg_str << "\n";

	// 
	p_key1 = OPENSSL_hexstr2buf(prikey_hex.c_str(), NULL);
	p_prikey = EVP_PKEY_new_read_PRIKEY_hex((char *)p_key1, X25519);
	OPENSSL_free(p_key1);

	if (!p_prikey)
	{
		std::cout << "p_prikey error\n";
		return (plaintext_hex);
	}

	// 
	p_key2 = OPENSSL_hexstr2buf(peer_pubkey_hex.c_str(), NULL);
	p_peer_pubkey = EVP_PKEY_new_read_PUBKEY_hex((char *)p_key2, X25519);
	OPENSSL_free(p_key2);

	if (!p_peer_pubkey)
	{
		std::cout << "p_peer_pubkey error\n";
		return (plaintext_hex);
	}

	// 
	p_enc_msg = OPENSSL_hexstr2buf(enc_msg_str.c_str(), NULL);
	enc_msg_len = enc_msg_str_len / 2;

	//
    // Decrypted
    p_plaintext = (uint8_t *)MALLOC_M(enc_msg_len);
    plaintext_len = 0;

#if (X25519_AES_USE == ENABLED)
    uint8_t *p_ciphertext, *p_cipher_mac;
    uint32_t ciphertext_len;
    
    ASSERT_M (enc_msg_len >= (OPENSSL_X25519_MAC_LEN));
    ciphertext_len = enc_msg_len - (OPENSSL_X25519_MAC_LEN);
    p_ciphertext = p_enc_msg;
    p_cipher_mac = &p_enc_msg[ciphertext_len];

    ret = openssl_x25519_aes_decrypt(p_prikey, p_peer_pubkey, NULL, 0, NULL, 0, p_ciphertext, ciphertext_len, p_cipher_mac, p_plaintext, &plaintext_len);
#else
	uint8_t *p_ciphertext;
	uint32_t ciphertext_len = enc_msg_len;

	p_ciphertext = p_enc_msg;

	ret = openssl_x25519_aria_decrypt(p_prikey, p_peer_pubkey, 16, p_ciphertext, ciphertext_len, p_plaintext, &plaintext_len);
#endif

    if (ret != SUCCESS_)
	{
        return (plaintext_hex);
	}

    DBG_DUMP(DBG_UTIL, DBG_NONE, (void *)"decrypted", p_plaintext, plaintext_len);

    plaintext_hex = ByteToHexString(p_plaintext, plaintext_len);

	FREE_M(p_plaintext);

	OPENSSL_free(p_enc_msg);

#if (OPENSSL_111 == ENABLED)
    EVP_PKEY_free(p_prikey);
    EVP_PKEY_free(p_peer_pubkey);
#endif // OPENSSL_111

    EVP_cleanup(); // free OpenSSL_add_all_algorithms()
    ERR_free_strings(); // free ERR_load_crypto_strings()

    // std::cout << "p_plaintext : " << p_plaintext << "\n";

    return (plaintext_hex);
}

std::string openssl_x25519_pem_enc(std::string prikey_pem, std::string peer_pubkey_pem, std::string plaintext_hex, uint32_t plaintext_hex_len)
{
	//
	std::string enc_msg_str = STR_ERROR_;

	//
	if ((chkUndefinedStr(prikey_pem) == 0) || (chkUndefinedStr(peer_pubkey_pem) == 0) || (chkUndefinedStr(plaintext_hex) == 0) || ((plaintext_hex.length() != plaintext_hex_len) || (plaintext_hex_len % 2)))
	{
		return (enc_msg_str);
	}

	//
	EVP_PKEY *p_prikey = NULL;
	EVP_PKEY *p_peer_pubkey = NULL;
	
	// uint8_t *p_key = NULL;
	uint8_t *p_plaintext = NULL;
	uint32_t plaintext_len = 0;

    uint8_t *p_enc_msg = NULL;
    uint32_t enc_msg_len = 0;

	// std::cout << "prikey_pem : " << prikey_pem << "\n";
	// std::cout << "peer_pubkey_pem : " << peer_pubkey_pem << "\n";
	// std::cout << "plaintext_hex : " << plaintext_hex << "\n";

	//
	uint32_t prikey_len = prikey_pem.length();

	BIO *pri_b = BIO_new_mem_buf((void*)prikey_pem.c_str(), prikey_len);
	p_prikey = PEM_read_bio_PrivateKey(pri_b, NULL, NULL, NULL);

	if (!p_prikey)
	{
		std::cout << "p_prikey error\n";
		
		return (enc_msg_str);
	}

	//
	uint32_t peer_pubkey_len = peer_pubkey_pem.length();
	BIO *pub_b = BIO_new_mem_buf((void*)peer_pubkey_pem.c_str(), peer_pubkey_len);
	p_peer_pubkey = PEM_read_bio_PUBKEY(pub_b, NULL, NULL, NULL);

	if (!p_peer_pubkey)
	{
		std::cout << "p_peer_pubkey error\n";
		return (enc_msg_str);
	}

	// 
	p_plaintext = OPENSSL_hexstr2buf(plaintext_hex.c_str(), NULL);
	plaintext_len = plaintext_hex_len / 2;

	//
#if (X25519_AES_USE == ENABLED)
	enc_msg_len = plaintext_len + OPENSSL_X25519_MAC_LEN + OPENSSL_SYM_KEY_LEN + OPENSSL_EDIES_P2_LEN;
	p_enc_msg = (uint8_t *)MALLOC_M(enc_msg_len);

    openssl_x25519_aes_encrypt(p_prikey, p_peer_pubkey, NULL, 0, NULL, 0, p_plaintext, plaintext_len, p_enc_msg, &enc_msg_len);
#else
	enc_msg_len = plaintext_len + ARIA_BUFFER_SIZE;
	p_enc_msg = (uint8_t *)MALLOC_M(enc_msg_len);

	openssl_x25519_aria_encrypt(p_prikey, p_peer_pubkey, 16, p_plaintext, plaintext_len, p_enc_msg, &enc_msg_len);
#endif

    enc_msg_str = ByteToHexString(p_enc_msg, enc_msg_len);

	FREE_M(p_enc_msg);

	OPENSSL_free(p_plaintext);

#if (OPENSSL_111 == ENABLED)
    EVP_PKEY_free(p_prikey);
    EVP_PKEY_free(p_peer_pubkey);
#endif // OPENSSL_111

	BIO_free(pub_b);
    BIO_free(pri_b);

    EVP_cleanup(); // free OpenSSL_add_all_algorithms()
    ERR_free_strings(); // free ERR_load_crypto_strings()

    // std::cout << "enc_msg_str : " << enc_msg_str << "\n";

    return (enc_msg_str);
}

std::string openssl_x25519_pem_dec(std::string prikey_pem, std::string peer_pubkey_pem, std::string enc_msg_str, uint32_t enc_msg_str_len)
{
	//
	std::string plaintext_hex = STR_ERROR_;

	//
	if ((chkUndefinedStr(prikey_pem) == 0) || (chkUndefinedStr(peer_pubkey_pem) == 0) || (chkUndefinedStr(enc_msg_str) == 0) || ((enc_msg_str.length() != enc_msg_str_len) || (enc_msg_str_len % 2)))
	{
		return (plaintext_hex);
	}

	//
    int32_t ret = ERROR_;

	EVP_PKEY *p_prikey = NULL;
	EVP_PKEY *p_peer_pubkey = NULL;
	
	// uint8_t *p_key = NULL;
	uint8_t *p_plaintext = NULL;
	uint32_t plaintext_len = 0;

    uint8_t *p_enc_msg = NULL;
    uint32_t enc_msg_len = 0;

	// std::cout << "prikey_pem : " << prikey_pem << "\n";
	// std::cout << "peer_pubkey_pem : " << peer_pubkey_pem << "\n";
	// std::cout << "enc_msg_str : " << enc_msg_str << "\n";

	//
	uint32_t prikey_len = prikey_pem.length();

	BIO *pri_b = BIO_new_mem_buf((void*)prikey_pem.c_str(), prikey_len);
	p_prikey = PEM_read_bio_PrivateKey(pri_b, NULL, NULL, NULL);

	if (!p_prikey)
	{
		std::cout << "p_prikey error\n";
		return (plaintext_hex);
	}

	//
	uint32_t peer_pubkey_len = peer_pubkey_pem.length();
	std::cout << "peer_pubkey_len : " << peer_pubkey_len << "\n";
	BIO *pub_b = BIO_new_mem_buf((void*)peer_pubkey_pem.c_str(), peer_pubkey_len);
	p_peer_pubkey = PEM_read_bio_PUBKEY(pub_b, NULL, NULL, NULL);

	if (!p_peer_pubkey)
	{
		std::cout << "p_peer_pubkey error\n";
		return (plaintext_hex);
	}
	// 
	p_enc_msg = OPENSSL_hexstr2buf(enc_msg_str.c_str(), NULL);
	enc_msg_len = enc_msg_str_len / 2;

	//
    // Decrypted
    p_plaintext = (uint8_t *)MALLOC_M(enc_msg_len);
    plaintext_len = 0;

#if (X25519_AES_USE == ENABLED)
    uint8_t *p_ciphertext, *p_cipher_mac;
    uint32_t ciphertext_len;
    
    ASSERT_M (enc_msg_len >= (OPENSSL_X25519_MAC_LEN));
    ciphertext_len = enc_msg_len - (OPENSSL_X25519_MAC_LEN);
    p_ciphertext = p_enc_msg;
    p_cipher_mac = &p_enc_msg[ciphertext_len];

    ret = openssl_x25519_aes_decrypt(p_prikey, p_peer_pubkey, NULL, 0, NULL, 0, p_ciphertext, ciphertext_len, p_cipher_mac, p_plaintext, &plaintext_len);
#else
	uint8_t *p_ciphertext;
	uint32_t ciphertext_len = enc_msg_len;

	p_ciphertext = p_enc_msg;

	ret = openssl_x25519_aria_decrypt(p_prikey, p_peer_pubkey, 16, p_ciphertext, ciphertext_len, p_plaintext, &plaintext_len);
#endif

    if (ret != SUCCESS_)
	{
        return (plaintext_hex);
	}

    DBG_DUMP(DBG_UTIL, DBG_NONE, (void *)"decrypted", p_plaintext, plaintext_len);

    plaintext_hex = ByteToHexString(p_plaintext, plaintext_len);

	FREE_M(p_plaintext);

	OPENSSL_free(p_enc_msg);

	BIO_free(pub_b);
    BIO_free(pri_b);

#if (OPENSSL_111 == ENABLED)
    EVP_PKEY_free(p_prikey);
    EVP_PKEY_free(p_peer_pubkey);
#endif // OPENSSL_111

    EVP_cleanup(); // free OpenSSL_add_all_algorithms()
    ERR_free_strings(); // free ERR_load_crypto_strings()

    // std::cout << "p_plaintext : " << p_plaintext << "\n";

    return (plaintext_hex);
}

std::string openssl_x25519_mix_enc(std::string prikey_pem, std::string peer_pubkey_hex, std::string plaintext_hex, uint32_t plaintext_hex_len)
{
	//
	std::string enc_msg_str = STR_ERROR_;

	//
	if ((chkUndefinedStr(prikey_pem) == 0) || (chkUndefinedStr(peer_pubkey_hex) == 0) || (chkUndefinedStr(plaintext_hex) == 0) || ((plaintext_hex.length() != plaintext_hex_len) || (plaintext_hex_len % 2)))
	{
		return (enc_msg_str);
	}

	//
	EVP_PKEY *p_prikey = NULL;
	EVP_PKEY *p_peer_pubkey = NULL;
	
	uint8_t *p_key2 = NULL;
	uint8_t *p_plaintext = NULL;
	uint32_t plaintext_len = 0;

    uint8_t *p_enc_msg = NULL;
    uint32_t enc_msg_len = 0;

	// std::cout << "prikey_pem : " << prikey_pem << "\n";
	// std::cout << "peer_pubkey_hex : " << peer_pubkey_hex << "\n";
    // std::cout << "plaintext_hex_len : " << plaintext_hex_len << "\n";
	// std::cout << "plaintext_hex : " << plaintext_hex << "\n";

	//
	uint32_t prikey_len = prikey_pem.length();

	BIO *pri_b = BIO_new_mem_buf((void*)prikey_pem.c_str(), prikey_len);
	p_prikey = PEM_read_bio_PrivateKey(pri_b, NULL, NULL, NULL);

	if (!p_prikey)
	{
		std::cout << "p_prikey error\n";
		
		return (enc_msg_str);
	}

	// 
	p_key2 = OPENSSL_hexstr2buf(peer_pubkey_hex.c_str(), NULL);
	p_peer_pubkey = EVP_PKEY_new_read_PUBKEY_hex((char *)p_key2, X25519);
	OPENSSL_free(p_key2);

	if (!p_peer_pubkey)
	{
		std::cout << "p_peer_pubkey error\n";
		return (enc_msg_str);
	}

	// 
	p_plaintext = OPENSSL_hexstr2buf(plaintext_hex.c_str(), NULL);
	plaintext_len = plaintext_hex_len / 2;

    DBG_DUMP(DBG_UTIL, DBG_NONE, (void *)"encPlaintext", p_plaintext, plaintext_len);

	//
#if (X25519_AES_USE == ENABLED)
	enc_msg_len = plaintext_len + OPENSSL_X25519_MAC_LEN + OPENSSL_SYM_KEY_LEN + OPENSSL_EDIES_P2_LEN;
	p_enc_msg = (uint8_t *)MALLOC_M(enc_msg_len);

    openssl_x25519_aes_encrypt(p_prikey, p_peer_pubkey, NULL, 0, NULL, 0, p_plaintext, plaintext_len, p_enc_msg, &enc_msg_len);
#else
	enc_msg_len = plaintext_len + ARIA_BUFFER_SIZE;
	p_enc_msg = (uint8_t *)MALLOC_M(enc_msg_len);

	openssl_x25519_aria_encrypt(p_prikey, p_peer_pubkey, 16, p_plaintext, plaintext_len, p_enc_msg, &enc_msg_len);
#endif

    enc_msg_str = ByteToHexString(p_enc_msg, enc_msg_len);

	FREE_M(p_enc_msg);

	OPENSSL_free(p_plaintext);

#if (OPENSSL_111 == ENABLED)
    EVP_PKEY_free(p_prikey);
    EVP_PKEY_free(p_peer_pubkey);
#endif // OPENSSL_111

    BIO_free(pri_b);

    EVP_cleanup(); // free OpenSSL_add_all_algorithms()
    ERR_free_strings(); // free ERR_load_crypto_strings()

    // std::cout << "enc_msg_str : " << enc_msg_str << "\n";

    return (enc_msg_str);
}

std::string openssl_x25519_mix_dec(std::string prikey_pem, std::string peer_pubkey_hex, std::string enc_msg_str, uint32_t enc_msg_str_len)
{
	//
	std::string plaintext_hex = STR_ERROR_;

	//
	if ((chkUndefinedStr(prikey_pem) == 0) || (chkUndefinedStr(peer_pubkey_hex) == 0) || (chkUndefinedStr(enc_msg_str) == 0) || ((enc_msg_str.length() != enc_msg_str_len) || (enc_msg_str_len % 2)))
	{
		return (plaintext_hex);
	}

	//
    int ret = ERROR_;

	EVP_PKEY *p_prikey = NULL;
	EVP_PKEY *p_peer_pubkey = NULL;
	
	uint8_t *p_key2 = NULL;
	uint8_t *p_plaintext = NULL;
	uint32_t plaintext_len = 0;

    uint8_t *p_enc_msg = NULL;
    uint32_t enc_msg_len = 0;

	// std::cout << "prikey_pem : " << prikey_pem << "\n";
	// std::cout << "peer_pubkey_hex : " << peer_pubkey_hex << "\n";
	// std::cout << "enc_msg_str : " << enc_msg_str << "\n";

	//
	uint32_t prikey_len = prikey_pem.length();

	BIO *pri_b = BIO_new_mem_buf((void*)prikey_pem.c_str(), prikey_len);
	p_prikey = PEM_read_bio_PrivateKey(pri_b, NULL, NULL, NULL);

	if (!p_prikey)
	{
		std::cout << "p_prikey error\n";
		return (plaintext_hex);
	}

	// 
	p_key2 = OPENSSL_hexstr2buf(peer_pubkey_hex.c_str(), NULL);
	p_peer_pubkey = EVP_PKEY_new_read_PUBKEY_hex((char *)p_key2, X25519);
	OPENSSL_free(p_key2);

	if (!p_peer_pubkey)
	{
		std::cout << "p_peer_pubkey error\n";
		return (plaintext_hex);
	}

	// 
	p_enc_msg = OPENSSL_hexstr2buf(enc_msg_str.c_str(), NULL);
	enc_msg_len = enc_msg_str_len / 2;

	//
    // Decrypted
    p_plaintext = (uint8_t *)MALLOC_M(enc_msg_len);
    plaintext_len = 0;

#if (X25519_AES_USE == ENABLED)
    uint8_t *p_ciphertext, *p_cipher_mac;
    uint32_t ciphertext_len;
    
    ASSERT_M (enc_msg_len >= (OPENSSL_X25519_MAC_LEN));
    ciphertext_len = enc_msg_len - (OPENSSL_X25519_MAC_LEN);
    p_ciphertext = p_enc_msg;
    p_cipher_mac = &p_enc_msg[ciphertext_len];

    ret = openssl_x25519_aes_decrypt(p_prikey, p_peer_pubkey, NULL, 0, NULL, 0, p_ciphertext, ciphertext_len, p_cipher_mac, p_plaintext, &plaintext_len);
#else
	uint8_t *p_ciphertext;
	uint32_t ciphertext_len = enc_msg_len;

	p_ciphertext = p_enc_msg;

	ret = openssl_x25519_aria_decrypt(p_prikey, p_peer_pubkey, 16, p_ciphertext, ciphertext_len, p_plaintext, &plaintext_len);
#endif

    if (ret != SUCCESS_)
	{
        return (plaintext_hex);
	}

    DBG_DUMP(DBG_UTIL, DBG_NONE, (void *)"decrypted", p_plaintext, plaintext_len);

    plaintext_hex = ByteToHexString(p_plaintext, plaintext_len);

	FREE_M(p_plaintext);

	OPENSSL_free(p_enc_msg);

    BIO_free(pri_b);

#if (OPENSSL_111 == ENABLED)
    EVP_PKEY_free(p_prikey);
    EVP_PKEY_free(p_peer_pubkey);
#endif // OPENSSL_111

    EVP_cleanup(); // free OpenSSL_add_all_algorithms()
    ERR_free_strings(); // free ERR_load_crypto_strings()

    // std::cout << "p_plaintext : " << p_plaintext << "\n";

    return (plaintext_hex);
}

//
int32_t openssl_aes_encrypt_pw_proc(std::string seed_path, std::string pw, uint32_t pw_len, std::string dst_path)
{
    //
    int32_t ret = ERROR_;

    //
    if ((chkUndefinedStr(seed_path) == 0) || (chkUndefinedStr(pw) == 0) || (pw.length() != pw_len) || (chkUndefinedStr(dst_path) == 0))
    {
        return (ret);
    }

    //
    char * p_seed_path = const_cast<char *>(seed_path.c_str());
    uint8_t *p_pw = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(pw.c_str()));
    char * p_dst_path = const_cast<char*>(dst_path.c_str());

    // uint8_t *p_seed, *p_enc;
    // uint32_t seed_len, enc_len;

    // uint8_t hash[HASH_SIZE];
    // uint8_t *p_key;
    // uint8_t *p_iv;

    // std::cout << __FUNCTION__ << "\n";

    ret = openssl_aes_encrypt_pw(p_seed_path, p_pw, pw_len, p_dst_path);

    return (ret);
}

uint8_t *openssl_aes_decrypt_pw_proc(std::string seed_path, std::string src_path)
{
    uint8_t *p_pw = NULL;

    //
    if ((chkUndefinedStr(seed_path) == 0) || (chkUndefinedStr(src_path) == 0))
    {
        return (p_pw);
    }

    uint32_t pw_len;
    // char src_path_def[] = "key/me/enc_pw";
    char *p_seed_path;
    char *p_src_path;

    // uint8_t hash[HASH_SIZE];
    // uint8_t *p_key;
    // uint8_t *p_iv;

    // std::cout << __FUNCTION__ << "\n";

    p_seed_path = const_cast<char *>(seed_path.c_str());
    p_src_path = const_cast<char *>(src_path.c_str());

    //
    p_pw = openssl_aes_decrypt_pw(p_seed_path, p_src_path, &pw_len);

    return (p_pw);
}

int32_t openssl_aes_encrypt_file_proc(std::string src_path, std::string dst_path, std::string seed, uint32_t seed_len)
{
	//
    int32_t ret = ERROR_;

    //
    if ((chkUndefinedStr(src_path) == 0) || (chkUndefinedStr(dst_path) == 0) || (chkUndefinedStr(seed) == 0) || (seed.length() != seed_len))
    {
        return (ret);
    }

	//
	char *p_src_path = const_cast<char *>(src_path.c_str());
	char *p_dst_path = const_cast<char *>(dst_path.c_str());
	uint8_t *p_seed = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(seed.c_str()));

    DBG_PRINT(DBG_UTIL, DBG_TRACE, (void *)"(%s)\n",  __FUNCTION__);
	
    //
    ret = openssl_aes_encrpt_file(p_src_path, p_dst_path, p_seed, seed_len);

    return (ret);
}

uint8_t *openssl_aes_decrypt_file_proc(std::string src_path, std::string seed, uint32_t seed_len)
{
	//
    uint8_t *p_plane = NULL;

    //
    if ((chkUndefinedStr(src_path) == 0) || (chkUndefinedStr(seed) == 0) || (seed.length() != seed_len))
    {
        return (p_plane);
    }
	//
	char *p_src_path = const_cast<char *>(src_path.c_str());
	uint8_t *p_seed = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(seed.c_str()));
	
    //
    p_plane = openssl_aes_decrypt_file(p_src_path, p_seed, seed_len);

    return (p_plane);
}

uint8_t *openssl_aes_decrypt_binary_proc(std::string enc_hex_str, uint32_t enc_hex_len, std::string seed, uint32_t seed_len)
{
    //
    uint8_t *p_plane = NULL;

    //
    if ((chkUndefinedStr(enc_hex_str) == 0) || (enc_hex_len % 2) || (chkUndefinedStr(seed) == 0) || (seed.length() != seed_len))
    {
        return (p_plane);
    }

    //
    uint8_t *p_enc_hex_str = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(enc_hex_str.c_str()));
    uint8_t *p_seed = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(seed.c_str()));

    DBG_PRINT (DBG_UTIL, DBG_INFO, (void *)"enc_hex_len(%d) , p_enc_hex_str(%s)\n", enc_hex_len, p_enc_hex_str);

    //
    uint32_t enc_len = enc_hex_len / 2;
    uint8_t *p_enc = (uint8_t *)MALLOC_M(enc_len);

    util_str2hex_temp((char *)p_enc_hex_str, (unsigned char *)p_enc, enc_len, false);

    //
    p_plane = openssl_aes_decrypt_binary(p_enc, enc_len, p_seed, seed_len);

    FREE_M(p_enc);

    return (p_plane);
}

//
std::string sec_aes_256_cbc_encrypt_proc(std::string plaintext_hex_str, uint32_t plaintext_hex_len, std::string seed, uint32_t seed_len, uint32_t *p_ciphertext_len)
{
    //
    uint8_t *p_ciphertext = NULL;
    std::string ciphertext_str = STR_ERROR_;

    //
    if ((chkUndefinedStr(plaintext_hex_str) == 0) || (plaintext_hex_len % 2) || (chkUndefinedStr(seed) == 0) || (seed.length() != seed_len))
    {
        return (ciphertext_str);
    }

    //
    uint8_t *p_plaintext_hex_str = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(plaintext_hex_str.c_str()));
    uint8_t *p_seed = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(seed.c_str()));

    DBG_PRINT (DBG_UTIL, DBG_INFO, (void *)"plaintext_hex_len(%d) , p_plaintext_hex_str(%s)\n", plaintext_hex_len, p_plaintext_hex_str);

    //
    uint32_t plaintext_len = plaintext_hex_len / 2;
    uint8_t *p_plaintext = (uint8_t *)MALLOC_M(plaintext_len);

    util_str2hex_temp((char *)p_plaintext_hex_str, (unsigned char *)p_plaintext, plaintext_len, false);

    p_ciphertext = (uint8_t *)MALLOC_M(plaintext_len + AES_BLOCK_SIZE);

    *p_ciphertext_len = sec_aes_256_cbc_encrypt(p_plaintext, plaintext_len, p_seed, seed_len, p_ciphertext);

    if (*p_ciphertext_len)
    {
        ciphertext_str = ByteToHexString(p_ciphertext, *p_ciphertext_len);
    }

    FREE_M(p_plaintext);
    FREE_M(p_ciphertext);

    return (ciphertext_str);
}
//
std::string sec_aes_256_cbc_decrypt_proc(std::string ciphertext_hex_str, uint32_t ciphertext_hex_len, std::string seed, uint32_t seed_len, uint32_t *p_plaintext_len)
{
    //
    uint8_t *p_planetext = NULL;
    std::string planetext_str = STR_ERROR_;

    //
    if ((chkUndefinedStr(ciphertext_hex_str) == 0) || (ciphertext_hex_len % 2) || (chkUndefinedStr(seed) == 0) || (seed.length() != seed_len))
    {
        return (planetext_str);
    }

    //
    uint8_t *p_ciphertext_hex_str = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(ciphertext_hex_str.c_str()));
    uint8_t *p_seed = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(seed.c_str()));

    DBG_PRINT (DBG_UTIL, DBG_INFO, (void *)"enc_hex_len(%d) , p_enc_hex_str(%s)\n", ciphertext_hex_len, p_ciphertext_hex_str);

    //
    uint32_t ciphertext_len = ciphertext_hex_len / 2;
    uint8_t *p_ciphertext = (uint8_t *)MALLOC_M(ciphertext_len);

    util_str2hex_temp((char *)p_ciphertext_hex_str, (unsigned char *)p_ciphertext, ciphertext_len, false);

    p_planetext = (uint8_t *)MALLOC_M(ciphertext_len);

    *p_plaintext_len = sec_aes_256_cbc_decrypt(p_ciphertext, ciphertext_len, p_seed, seed_len, p_planetext);

    if (*p_plaintext_len)
    {
        planetext_str = ByteToHexString(p_planetext, *p_plaintext_len);
    }

    FREE_M(p_ciphertext);
    FREE_M(p_planetext);

    return (planetext_str);
}

//
std::string sec_aria_encrypt_proc(std::string plaintext_hex_str, uint32_t plaintext_hex_len, std::string seed, uint32_t seed_len, uint32_t *p_ciphertext_len)
{
    //
    uint8_t *p_ciphertext = NULL;
    std::string ciphertext_str = STR_ERROR_;

    //
    if ((chkUndefinedStr(plaintext_hex_str) == 0) || (plaintext_hex_len % 2) || (chkUndefinedStr(seed) == 0) || (seed.length() != seed_len))
    {
        return (ciphertext_str);
    }

    //
    uint8_t *p_plaintext_hex_str = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(plaintext_hex_str.c_str()));
    uint8_t *p_seed = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(seed.c_str()));

    DBG_PRINT (DBG_UTIL, DBG_INFO, (void *)"plaintext_hex_len(%d) , p_plaintext_hex_str(%s)\n", plaintext_hex_len, p_plaintext_hex_str);

    //
    uint32_t plaintext_len = plaintext_hex_len / 2;
    uint8_t *p_plaintext = (uint8_t *)MALLOC_M(plaintext_len);

    util_str2hex_temp((char *)p_plaintext_hex_str, (unsigned char *)p_plaintext, plaintext_len, false);

    p_ciphertext = (uint8_t *)MALLOC_M(plaintext_len + AES_BLOCK_SIZE);

    *p_ciphertext_len = sec_aria_encrypt(p_plaintext, plaintext_len, p_seed, seed_len, p_ciphertext);

    if (*p_ciphertext_len)
    {
        ciphertext_str = ByteToHexString(p_ciphertext, *p_ciphertext_len);
    }

    FREE_M(p_plaintext);
    FREE_M(p_ciphertext);

    return (ciphertext_str);
}
//
std::string sec_aria_decrypt_proc(std::string ciphertext_hex_str, uint32_t ciphertext_hex_len, std::string seed, uint32_t seed_len, uint32_t *p_plaintext_len)
{
    //
    uint8_t *p_planetext = NULL;
    std::string planetext_str = STR_ERROR_;

    //
    if ((chkUndefinedStr(ciphertext_hex_str) == 0) || (ciphertext_hex_len % 2) || (chkUndefinedStr(seed) == 0) || (seed.length() != seed_len))
    {
        return (planetext_str);
    }

    //
    uint8_t *p_ciphertext_hex_str = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(ciphertext_hex_str.c_str()));
    uint8_t *p_seed = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(seed.c_str()));

    DBG_PRINT (DBG_UTIL, DBG_INFO, (void *)"enc_hex_len(%d) , p_enc_hex_str(%s)\n", ciphertext_hex_len, p_ciphertext_hex_str);

    //
    uint32_t ciphertext_len = ciphertext_hex_len / 2;
    uint8_t *p_ciphertext = (uint8_t *)MALLOC_M(ciphertext_len);

    util_str2hex_temp((char *)p_ciphertext_hex_str, (unsigned char *)p_ciphertext, ciphertext_len, false);

    p_planetext = (uint8_t *)MALLOC_M(ciphertext_len);

    *p_plaintext_len = sec_aria_decrypt(p_ciphertext, ciphertext_len, p_seed, seed_len, p_planetext);

    if (*p_plaintext_len)
    {
        planetext_str = ByteToHexString(p_planetext, *p_plaintext_len);
    }

    FREE_M(p_ciphertext);
    FREE_M(p_planetext);

    return (planetext_str);
}

/////////////////////////////////////////////////////////
//
int32_t x25519_test(void)
{
	int32_t ret;

	// ret = openssl_x25519_key_test();
	ret = openssl_x25519_test();

	DBG_PRINT(DBG_UTIL, DBG_INFO, (void *)"ret : %d\n", ret);
	
	return ret;
}

//
int ed_verify()
{
	OPENSSL_init();
	int res;
	uint8_t* ed_pubkey = OPENSSL_hexstr2buf("303f1795face060281b2d9d33b40cc74e8dc79ef07c8eb7086a82b997425b005", NULL);
	uint8_t* signature = OPENSSL_hexstr2buf("16161BCB5BCEAC359707505FEED15C41D2E6E7B54C5C5A7E9969295EBD0170C167F0152835E7FE7F730F1EC310B6886F6B5D7C73282D2B18B5A75A77EA351305", NULL);
	uint8_t msg[] = "80c4b38320d63f4e65805bb77150ba68712d5348825ea7fcc07087dce3b94a9b";
	// uint8_t msg[] = "abc";
	DBG_DUMP(DBG_UTIL, DBG_INFO, (void *)"msg", msg, sizeof(msg)-1);
	
	// 
	int msgHex_len = sizeof(msg)/2;
	uint8_t *p_msgHex = (uint8_t *) MALLOC_M(msgHex_len);
	util_str2hex((char *)msg, p_msgHex, &msgHex_len);
	DBG_DUMP(DBG_UTIL, DBG_INFO, (void *)"p_msgHex", p_msgHex, msgHex_len);

    uint8_t data_hash[HASH_SIZE];
    openssl_sha256(data_hash, p_msgHex, msgHex_len);
	DBG_DUMP(DBG_UTIL, DBG_INFO, (void *)"data_hash 2", data_hash, HASH_SIZE);
	

	EVP_PKEY *p_pubkey = EVP_PKEY_new_raw_public_key(NID_ED25519, NULL, ed_pubkey, 32);
	assert(p_pubkey != NULL);
	
	EVP_MD_CTX* p_mdctx = EVP_MD_CTX_new();
	res = EVP_DigestVerifyInit(p_mdctx, NULL, NULL, NULL, p_pubkey);
	assert(res == 1);

    res = EVP_DigestVerify(p_mdctx, signature, SIG_SIZE, data_hash, HASH_SIZE);

	// res = EVP_DigestVerify(p_mdctx, signature, SIG_SIZE, p_msgHex, msgHex_len);
	if (res == 1) {
		std::cout << "Signature verified." << std::endl;
	}
	else {
		std::cout << "Signature did not verify." << std::endl;
	}
	
	EVP_MD_CTX_free(p_mdctx);
	// FREE_M(ed_pubkey);
	// FREE_M(signature);
	// FREE_M(msg);
	
	EVP_PKEY_free(p_pubkey);

	OPENSSL_free(ed_pubkey);
	OPENSSL_free(signature);
	return 0;
}

// // OK....................
// int ed_verify() {
// 	OPENSSL_init();
// 	int res;
// 	uint8_t* ed_pubkey = OPENSSL_hexstr2buf("303f1795face060281b2d9d33b40cc74e8dc79ef07c8eb7086a82b997425b005", NULL);
// 	uint8_t* signature = OPENSSL_hexstr2buf("16161BCB5BCEAC359707505FEED15C41D2E6E7B54C5C5A7E9969295EBD0170C167F0152835E7FE7F730F1EC310B6886F6B5D7C73282D2B18B5A75A77EA351305", NULL);
// 	uint8_t msg[] = "6cec3e6a7f672d65fdd6fc071bf3f05bfb7dea8e34f932ec19563f60b98059d3";
// 	int msgHex_len = sizeof(msg)/2;
// 	uint8_t *p_msgHex = (uint8_t *) MALLOC_M(msgHex_len);
	
// 	util_str2hex((char *)msg, p_msgHex, &msgHex_len);
	
// 	EVP_PKEY *p_pubkey = EVP_PKEY_new_raw_public_key(NID_ED25519, NULL, ed_pubkey, 32);
// 	assert(p_pubkey != NULL);
	
// 	EVP_MD_CTX* p_mdctx = EVP_MD_CTX_new();
// 	res = EVP_DigestVerifyInit(p_mdctx, NULL, NULL, NULL, p_pubkey);
// 	assert(res == 1);

// 	DBG_DUMP(DBG_UTIL, DBG_INFO, (void *)"p_msgHex", p_msgHex, msgHex_len);

//     // uint8_t data_hash[HASH_SIZE];
//     // openssl_sha256(data_hash, p_msgHex, msgHex_len);
//     // res = EVP_DigestVerify(p_mdctx, signature, SIG_SIZE, data_hash, HASH_SIZE);

// 	res = EVP_DigestVerify(p_mdctx, signature, SIG_SIZE, p_msgHex, msgHex_len);
// 	if (res == 1) {
// 		std::cout << "Signature verified." << std::endl;
// 	}
// 	else {
// 		std::cout << "Signature did not verify." << std::endl;
// 	}
	
// 	EVP_MD_CTX_free(p_mdctx);
// 	// FREE_M(ed_pubkey);
// 	// FREE_M(signature);
// 	// FREE_M(msg);
	
// 	EVP_PKEY_free(p_pubkey);
// 	return 0;
// }

// int ed_verify() {
// 	OPENSSL_init();
// 	int res;
// 	uint8_t* ed_pubkey = OPENSSL_hexstr2buf("5261BF4F281EA120BB5E8B4DB319515F7D15E8CF041291C77942C1B606623BE7", NULL);
// 	uint8_t* signature = OPENSSL_hexstr2buf("C790785068A8D991C8FD270B7F02ABAA819D995C0EE5E11D05D1FCBB330B176FC18CECA0EA6E7F5292D883ED1255A7AC0680BB5F86CDA8E6CF0A53DED127CF07", NULL);
// 	uint8_t msg[] = "this is a test message";
	
// 	EVP_PKEY* p_pubkey = EVP_PKEY_new_raw_public_key(NID_ED25519, NULL, ed_pubkey, 32);
// 	assert(p_pubkey != NULL);
	
// 	EVP_MD_CTX* p_mdctx = EVP_MD_CTX_new();
// 	res = EVP_DigestVerifyInit(p_mdctx, NULL, NULL, NULL, p_pubkey);
// 	assert(res == 1);

//     uint8_t data_hash[HASH_SIZE];
//     openssl_sha256(data_hash, msg, sizeof(msg));
//     res = EVP_DigestVerify(p_mdctx, signature, SIG_SIZE, data_hash, HASH_SIZE);

// 	// res = EVP_DigestVerify(p_mdctx, signature, SIG_SIZE, msg, sizeof(msg));
// 	if (res == 1) {
// 		std::cout << "Signature verified." << std::endl;
// 	}
// 	else {
// 		std::cout << "Signature did not verify." << std::endl;
// 	}
	
// 	EVP_MD_CTX_free(p_mdctx);
// 	// FREE_M(ed_pubkey);
// 	// FREE_M(signature);
// 	// FREE_M(msg);
	
// 	EVP_PKEY_free(p_pubkey);
// 	return 0;
//  OPENSSL_free(ed_pubkey);
//  OPENSSL_free(signature);
// }

//

std::string cstombs_str(char *p_new_locale, char *p_str)
{
    //
    std::string mbs_str = STR_ERROR_;

    //
    int32_t mbs_size;
    uint8_t *p_mbs;

    // printf ("p_str : %s\n", p_str);
    // 
    p_mbs = util_cstombs((char *)"C.UTF-8", p_str, &mbs_size);
    if (p_mbs != NULL)
    {
        // //
        // int required_size;
        // required_size = util_wcs_required_size(p_new_locale, (char *)p_mbs);
        // printf("required_size : %d\n", required_size);

        //
        mbs_str = ByteToHexString(p_mbs, mbs_size);

        FREE_M(p_mbs);
    }

    return (mbs_str);
}

uint32_t key_create_master_str(std::string pw, std::string mnemonic1, std::string mnemonic2)
{
    //
    uint32_t rand_num = 0;

    //
    if (chkUndefinedStr(pw) == 0)
    {
        return (rand_num);
    }

    if (chkUndefinedStr(mnemonic1) == 0)
    {
        return (rand_num);
    }

    if (chkUndefinedStr(mnemonic2) == 0)
    {
        return (rand_num);
    }

    //
    uint8_t chain_code[HMAC_SHA_512_MAX_SIZE];
    int32_t chain_code_len = key_master((char *)pw.c_str(), (char *)mnemonic1.c_str(), (char *)mnemonic2.c_str(), &rand_num, chain_code);
    if (chain_code_len > 0)
    {
        std::string chain_code_str = ByteToHexString(chain_code, chain_code_len);

        // std::cout << "Chain Code : " << chain_code_str << "\n";
    }

    return (rand_num);
}

uint32_t key_create_master_ori_str(std::string mnemonic1, std::string pw)
{
    //
    uint32_t ret = 0;

    //
    if (chkUndefinedStr(pw) == 0)
    {
        return (ret);
    }

    if (chkUndefinedStr(mnemonic1) == 0)
    {
        return (ret);
    }

    //
    uint8_t chain_code[HMAC_SHA_512_MAX_SIZE];
    int32_t chain_code_len = key_master_ori((char *)mnemonic1.c_str(), (char *)pw.c_str(), chain_code);
    if (chain_code_len > 0)
    {
        std::string chain_code_str = ByteToHexString(chain_code, chain_code_len);

        ret = chain_code_str.length();

        // std::cout << "Chain Code : " << chain_code_str << "\n";
    }

    return (ret);
}

std::string key_restore_master_str(std::string pw, std::string mnemonic1, std::string mnemonic2, uint32_t rand_num)
{
	//
    std::string chain_code_str = STR_ERROR_;

    //
    if (chkUndefinedStr(pw) == 0)
    {
        return (chain_code_str);
    }

    if (chkUndefinedStr(mnemonic1) == 0)
    {
        return (chain_code_str);
    }

    if (chkUndefinedStr(mnemonic2) == 0)
    {
        return (chain_code_str);
    }

    if ((rand_num == 0) || (rand_num > 0xFFFF))
    {
        return (chain_code_str);
    }

    //
    uint8_t chain_code[HMAC_SHA_512_MAX_SIZE];
    int32_t chain_code_len = key_master((char *)pw.c_str(), (char *)mnemonic1.c_str(), (char *)mnemonic2.c_str(), &rand_num, chain_code);
    if (chain_code_len > 0)
    {
        chain_code_str = ByteToHexString(chain_code, chain_code_len);

        // std::cout << "Chain Code : " << chain_code_str << "\n";
    }

    return (chain_code_str);
}

std::string key_restore_master_ori_str(std::string mnemonic1, std::string pw)
{
	//
    std::string chain_code_str = STR_ERROR_;

    //
    if (chkUndefinedStr(pw) == 0)
    {
        return (chain_code_str);
    }

    if (chkUndefinedStr(mnemonic1) == 0)
    {
        return (chain_code_str);
    }

    //
    uint8_t chain_code[HMAC_SHA_512_MAX_SIZE];
    int32_t chain_code_len = key_master_ori((char *)mnemonic1.c_str(), (char *)pw.c_str(), chain_code);
    if (chain_code_len > 0)
    {
        chain_code_str = ByteToHexString(chain_code, chain_code_len);

        // std::cout << "Chain Code : " << chain_code_str << "\n";
    }

    return (chain_code_str);
}