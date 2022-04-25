/**
 * Description : 
 *
 * @date 2021/01/21
 * @author FINL Chain Team
 * @version 1.0
 */

#include "cpp_if.hpp"

///////////////////////////////////////////////////////////////

// UTC MSEC
static int utcCurrMS(lua_State *L)
{
    if (lua_gettop(L) != 0)
    {
        std::cout << "Error : expecting exactly 0 arguments\n";
    }
    else
    {
        //
        uint64_t curr_utc_msec = util_curtime_ms();

        lua_pushnumber(L, curr_utc_msec);

        return 1;
    }

    return 0;
}

// UTC USEC
static int utcCurrUS(lua_State *L)
{
    if (lua_gettop(L) != 0)
    {
        std::cout << "Error : expecting exactly 0 arguments\n";
    }
    else
    {
        //
        uint64_t curr_utc_usec = util_curtime_us();

        lua_pushnumber(L, curr_utc_usec);

        return 1;
    }

    return 0;
}

//
static int msleep(lua_State *L)
{
    int m = static_cast<int> (luaL_checknumber(L,1));

    usleep(m * 1000); 
    // usleep takes microseconds. This converts the parameter to milliseconds. 
    // Change this as necessary. 
    // Alternatively, use 'sleep()' to treat the parameter as whole seconds. 
    return 0;
}

// cURL HTTP GET
static int curlHttpGet(lua_State *L)
{
    if (lua_gettop(L) != 2)
    {
        std::cout << "Error : expecting exactly 2 arguments\n";
    }
    else
    {
        //
        std::string url = std::string(luaL_checkstring(L, 1));
        std::string fields = std::string(luaL_checkstring(L, 2));

        //
        std::string ret = curl_http_get_proc(url, fields);

        if (ret.compare(STR_ERROR_)) // SUCCESS
        {
            lua_pushstring(L, ret.c_str());

            return 1;
        }
        else
        {
            std::cout << "Error : None Return Value\n";
        }
    }

    return 0;
}

// cURL HTTP POST
static int curlHttpPost(lua_State *L)
{
    if (lua_gettop(L) != 2)
    {
        std::cout << "Error : expecting exactly 2 arguments\n";
    }
    else
    {
        //
        std::string url = std::string(luaL_checkstring(L, 1));
        std::string fields = std::string(luaL_checkstring(L, 2));

        //
        std::string ret = curl_http_post_proc(url, fields);

        if (ret.compare(STR_ERROR_)) // SUCCESS
        {
            lua_pushstring(L, ret.c_str());

            return 1;
        }
        else
        {
            std::cout << "Error : None Return Value\n";
        }
    }

    return 0;
}

// EC R1
//
static int ecR1KeyGenPemWithMnemonic(lua_State *L)
{
    if (lua_gettop(L) != 5)
    {
        std::cout << "Error : expecting exactly 5 arguments (string)\n";
    }
    else
    {
        //
        std::string path = std::string(luaL_checkstring(L, 1));
        std::string pw = std::string(luaL_checkstring(L, 2));
        std::string mnemonic1 = std::string(luaL_checkstring(L, 3));
        std::string mnemonic2 = std::string(luaL_checkstring(L, 4));
        uint32_t rand_num = luaL_checkinteger(L, 5);

        //
        int32_t ret = openssl_ec_keygen_with_mnemonic_proc(path, SECP256R1, pw, mnemonic1, mnemonic2, rand_num);

        if (ret == 0) lua_pushboolean(L, true);
        else lua_pushboolean(L, false);

        lua_pushnumber(L, ret);

        return 1;
    }

    return 0;
}

//
static int ecR1KeyGenPemWithMnemonicOri(lua_State *L)
{
    if (lua_gettop(L) != 3)
    {
        std::cout << "Error : expecting exactly 3 arguments (string)\n";
    }
    else
    {
        //
        std::string path = std::string(luaL_checkstring(L, 1));
        std::string mnemonic1 = std::string(luaL_checkstring(L, 2));
        std::string pw = std::string(luaL_checkstring(L, 3));

        //
        int32_t ret = openssl_ec_keygen_with_mnemonic_ori_proc(path, SECP256R1, mnemonic1, pw);

        if (ret == 0) lua_pushboolean(L, true);
        else lua_pushboolean(L, false);
        
        lua_pushnumber(L, ret);

        return 1;
    }

    return 0;
}

//
static int ecR1KeyGenPem(lua_State *L)
{
    if (lua_gettop(L) != 1)
    {
        std::cout << "Error : expecting exactly 1 arguments (string)\n";
    }
    else
    {
        //
        std::string path = std::string(luaL_checkstring(L, 1));

        //
        int32_t ret = openssl_ec_keygen_proc(path, SECP256R1);

        if (ret == 0) lua_pushboolean(L, true);
        else lua_pushboolean(L, false);

        return 1;
    }

    return 0;
}

static int ecdsaR1VerifyHex(lua_State *L)
{
    if (lua_gettop(L) != 4)
    {
        std::cout << "Error : expecting exactly 4 arguments (string string string string)\n";
    }
    else
    {
        //
        std::string data = std::string(luaL_checkstring(L, 1));
        std::string sig_r = std::string(luaL_checkstring(L, 2));
        std::string sig_s = std::string(luaL_checkstring(L, 3));    
        std::string comp_pubkey = std::string(luaL_checkstring(L, 4));

        //
        // int32_t ret = openssl_ecdsa_r1_verify(data, sig_r, sig_s, comp_pubkey);
        int32_t ret = openssl_ecdsa_verify_hex(data, sig_r, sig_s, comp_pubkey, SECP256R1);

        if (ret == 0) lua_pushboolean(L, true);
        else lua_pushboolean(L, false);

        return 1;
    }

    return 0;
}

static int ecdsaR1SignHex(lua_State *L)
{
    if (lua_gettop(L) != 2)
    {
        std::cout << "Error : expecting exactly 2 arguments (string string)\n";
    }
    else
    {
        //
        std::string data = std::string(luaL_checkstring(L, 1));
        std::string prikey = std::string(luaL_checkstring(L, 2));

        //
        std::string signature = openssl_ecdsa_sig_hex(prikey, data, SECP256R1);

        if (signature.compare(STR_ERROR_)) // SUCCESS
        {
            lua_pushstring(L, signature.c_str());

            return 1;
        }
        else
        {
            std::cout << "Error : None Return Value\n";
        }
    }

    return 0;
}

static int ecdsaR1SignPem(lua_State *L)
{
    if (lua_gettop(L) != 2)
    {
        std::cout << "Error : expecting exactly 2 arguments (string string)\n";
    }
    else
    {
        //
        std::string data = std::string(luaL_checkstring(L, 1));
        std::string prikey_path = std::string(luaL_checkstring(L, 2));

        //
        std::string signature = openssl_ecdsa_sig_pem(false, prikey_path, data);

        if (signature.compare(STR_ERROR_)) // SUCCESS
        {
            lua_pushstring(L, signature.c_str());

            return 1;
        }
        else
        {
            std::cout << "Error : None Return Value\n";
        }
    }

    return 0;
}

// ECDSA K1
//
static int ecK1KeyGenPemWithMnemonic(lua_State *L)
{
    if (lua_gettop(L) != 5)
    {
        std::cout << "Error : expecting exactly 5 arguments (string)\n";
    }
    else
    {
        //
        std::string path = std::string(luaL_checkstring(L, 1));
        std::string pw = std::string(luaL_checkstring(L, 2));
        std::string mnemonic1 = std::string(luaL_checkstring(L, 3));
        std::string mnemonic2 = std::string(luaL_checkstring(L, 4));
        uint32_t rand_num = luaL_checkinteger(L, 5);

        //
        int32_t ret = openssl_ec_keygen_with_mnemonic_proc(path, SECP256K1, pw, mnemonic1, mnemonic2, rand_num);

        if (ret == 0) lua_pushboolean(L, true);
        else lua_pushboolean(L, false);

        lua_pushnumber(L, ret);

        return 1;
    }

    return 0;
}

//
static int ecK1KeyGenPemWithMnemonicOri(lua_State *L)
{
    if (lua_gettop(L) != 3)
    {
        std::cout << "Error : expecting exactly 3 arguments (string)\n";
    }
    else
    {
        //
        std::string path = std::string(luaL_checkstring(L, 1));
        std::string mnemonic1 = std::string(luaL_checkstring(L, 2));
        std::string pw = std::string(luaL_checkstring(L, 3));

        //
        int32_t ret = openssl_ec_keygen_with_mnemonic_ori_proc(path, SECP256K1, mnemonic1, pw);

        if (ret == 0) lua_pushboolean(L, true);
        else lua_pushboolean(L, false);

        lua_pushnumber(L, ret);

        return 1;
    }

    return 0;
}

//
static int ecK1KeyGenPem(lua_State *L)
{
    if (lua_gettop(L) != 1)
    {
        std::cout << "Error : expecting exactly 1 arguments (string)\n";
    }
    else
    {
        //
        std::string path = std::string(luaL_checkstring(L, 1));

        //
        int32_t ret = openssl_ec_keygen_proc(path, SECP256K1);

        if (ret == 0) lua_pushboolean(L, true);
        else lua_pushboolean(L, false);

        return 1;
    }

    return 0;
}

static int ecdsaK1Verify(lua_State *L)
{
    if (lua_gettop(L) != 4)
    {
        std::cout << "Error : expecting exactly 4 arguments (string string string string)\n";
    }
    else
    {
        //
        std::string data = std::string(luaL_checkstring(L, 1));
        std::string sig_r = std::string(luaL_checkstring(L, 2));
        std::string sig_s = std::string(luaL_checkstring(L, 3));
        std::string comp_pubkey = std::string(luaL_checkstring(L, 4));

        //
        // int32_t ret = openssl_ecdsa_k1_verify(data, sig_r, sig_s, comp_pubkey);
        int32_t ret = openssl_ecdsa_verify_hex(data, sig_r, sig_s, comp_pubkey, SECP256R1);

        if (ret == 0) lua_pushboolean(L, true);
        else lua_pushboolean(L, false);

        return 1;
    }

    return 0;
}
static int ecdsaK1SignHex(lua_State *L)
{
   if (lua_gettop(L) != 2)
    {
        std::cout << "Error : expecting exactly 2 arguments (string string)\n";
    }
    else
    {
        //
        std::string data = std::string(luaL_checkstring(L, 1));
        std::string prikey = std::string(luaL_checkstring(L, 2));

        //
        std::string signature = openssl_ecdsa_sig_hex(prikey, data, SECP256K1);

        if (signature.compare(STR_ERROR_)) // SUCCESS
        {
            lua_pushstring(L, signature.c_str());

            return 1;
        }
        else
        {
            std::cout << "Error : None Return Value\n";
        }
    }

    return 0;
}

static int ecdsaK1SignPem(lua_State *L)
{
    if (lua_gettop(L) != 2)
    {
        std::cout << "Error : expecting exactly 2 arguments (string string)\n";
    }
    else
    {
        //
        std::string data = std::string(luaL_checkstring(L, 1));
        std::string prikey_path = std::string(luaL_checkstring(L, 2));

        //
        std::string signature = openssl_ecdsa_sig_pem(false, prikey_path, data);

        if (signature.compare(STR_ERROR_)) // SUCCESS
        {
            lua_pushstring(L, signature.c_str());

            return 1;
        }
        else
        {
            std::cout << "Error : None Return Value\n";
        }
    }

    return 0;
}

// EDDSA
//
static int ed25519KeyGenPemWithMnemonic(lua_State *L)
{
    if (lua_gettop(L) != 5)
    {
        std::cout << "Error : expecting exactly 5 arguments (string)\n";
    }
    else
    {
        //
        std::string path = std::string(luaL_checkstring(L, 1));
        std::string pw = std::string(luaL_checkstring(L, 2));
        std::string mnemonic1 = std::string(luaL_checkstring(L, 3));
        std::string mnemonic2 = std::string(luaL_checkstring(L, 4));
        uint32_t rand_num = luaL_checkinteger(L, 5);

        //
        int32_t ret = openssl_ed25519_keygen_with_mnemonic_proc(path, pw, mnemonic1, mnemonic2, rand_num);

        if (ret == 0) lua_pushboolean(L, true);
        else lua_pushboolean(L, false);

        lua_pushnumber(L, ret);

        return 1;
    }

    return 0;
}

//
static int ed25519KeyGenPemWithMnemonicOri(lua_State *L)
{
    if (lua_gettop(L) != 3)
    {
        std::cout << "Error : expecting exactly 3 arguments (string)\n";
    }
    else
    {
        //
        std::string path = std::string(luaL_checkstring(L, 1));
        std::string mnemonic1 = std::string(luaL_checkstring(L, 2));
        std::string pw = std::string(luaL_checkstring(L, 3));

        //
        int32_t ret = openssl_ed25519_keygen_with_mnemonic_ori_proc(path, mnemonic1, pw);

        if (ret == 0) lua_pushboolean(L, true);
        else lua_pushboolean(L, false);

        lua_pushnumber(L, ret);

        return 1;
    }

    return 0;
}

//
static int ed25519KeyGenPem(lua_State *L)
{
    if (lua_gettop(L) != 1)
    {
        std::cout << "Error : expecting exactly 1 arguments (string)\n";
    }
    else
    {
        //
        std::string path = std::string(luaL_checkstring(L, 1));

        //
        int32_t ret = openssl_ed25519_keygen_proc(path);

        if (ret == 0) lua_pushboolean(L, true);
        else lua_pushboolean(L, false);

        return 1;
    }

    return 0;
}

//
static int ed25519KeyGenPemPubkey(lua_State *L)
{
    if (lua_gettop(L) != 1)
    {
        std::cout << "Error : expecting exactly 1 arguments (string)\n";
    }
    else
    {
        //
        std::string path = std::string(luaL_checkstring(L, 1));

        //
        int32_t ret = openssl_ed25519_keygen_pubkey_proc(path);

        if (ret == 0) lua_pushboolean(L, true);
        else lua_pushboolean(L, false);

        return 1;
    }

    return 0;
}

//
static int ed25519KeyGenFinWithMnemonic(lua_State *L)
{
    if (lua_gettop(L) != 7)
    {
        std::cout << "Error : expecting exactly 7 arguments (string string number)\n";
    }
    else
    {
        //
        std::string path = std::string(luaL_checkstring(L, 1));
        std::string pw = std::string(luaL_checkstring(L, 2));
        std::string mnemonic1 = std::string(luaL_checkstring(L, 3));
        std::string mnemonic2 = std::string(luaL_checkstring(L, 4));
        uint32_t rand_num = luaL_checkinteger(L, 5);
        std::string seed = std::string(luaL_checkstring(L, 6));
        uint32_t seed_len = luaL_checkinteger(L, 7);

        //
        int32_t ret = openssl_ed25519_keygen_fin_with_mnemonic_proc(path, pw, mnemonic1, mnemonic2, rand_num, seed, seed_len);

        if (ret == 0) lua_pushboolean(L, true);
        else lua_pushboolean(L, false);

        lua_pushnumber(L, ret);

        return 1;
    }

    return 0;
}

//
static int ed25519KeyGenFinWithMnemonicOri(lua_State *L)
{
    if (lua_gettop(L) != 5)
    {
        std::cout << "Error : expecting exactly 5 arguments (string string number)\n";
    }
    else
    {
        //
        std::string path = std::string(luaL_checkstring(L, 1));
        std::string mnemonic1 = std::string(luaL_checkstring(L, 2));
        std::string pw = std::string(luaL_checkstring(L, 3));
        std::string seed = std::string(luaL_checkstring(L, 4));
        uint32_t seed_len = luaL_checkinteger(L, 5);

        //
        int32_t ret = openssl_ed25519_keygen_fin_with_mnemonic_ori_proc(path, mnemonic1, pw, seed, seed_len);

        if (ret == 0) lua_pushboolean(L, true);
        else lua_pushboolean(L, false);

        lua_pushnumber(L, ret);

        return 1;
    }

    return 0;
}


//
static int ed25519KeyGenFin(lua_State *L)
{
    if (lua_gettop(L) != 3)
    {
        std::cout << "Error : expecting exactly 3 arguments (string string number)\n";
    }
    else
    {
        //
        std::string path = std::string(luaL_checkstring(L, 1));
        std::string seed = std::string(luaL_checkstring(L, 2));
        uint32_t seed_len = luaL_checkinteger(L, 3);

        //
        int32_t ret = openssl_ed25519_keygen_fin_proc(path, seed, seed_len);

        if (ret == 0) lua_pushboolean(L, true);
        else lua_pushboolean(L, false);

        return 1;
    }

    return 0;
}

static int eddsaVerifyHex(lua_State *L)
{
    if (lua_gettop(L) != 3)
    {
        std::cout << "Error : expecting exactly 3 arguments (string string string)\n";
    }
    else
    {
        //
        std::string data = std::string(luaL_checkstring(L, 1));
        std::string signature = std::string(luaL_checkstring(L, 2));
        std::string pubkey = std::string(luaL_checkstring(L, 3));

        //
        // int32_t ret = openssl_eddsa_verify(data, signature, pubkey);
        int32_t ret = openssl_ed25519_verify_hex(data, signature, pubkey);

        if (ret == 0) lua_pushboolean(L, true);
        else lua_pushboolean(L, false);

        return 1;
    }

    return 0;
}

static int eddsaSignHex(lua_State *L)
{
    if (lua_gettop(L) != 2)
    {
        std::cout << "Error : expecting exactly 2 arguments (string string)\n";
    }
    else
    {
        //
        std::string data = std::string(luaL_checkstring(L, 1));
        std::string prikey = std::string(luaL_checkstring(L, 2));

        //
        std::string signature = openssl_ed25519_sig_hex(prikey, data);

        if (signature.compare(STR_ERROR_)) // SUCCESS
        {
            lua_pushstring(L, signature.c_str());

            return 1;
        }
        else
        {
            std::cout << "Error : None Return Value\n";
        }
    }

    return 0;
}

static int eddsaSignPem(lua_State *L)
{
    if (lua_gettop(L) != 2)
    {
        std::cout << "Error : expecting exactly 2 arguments (string string)\n";
    }
    else
    {
        //
        std::string data = std::string(luaL_checkstring(L, 1));
        std::string prvkeyPath = std::string(luaL_checkstring(L, 2));

        //
        std::string signature = openssl_ed25519_sig_pem(false, prvkeyPath, data);

        if (signature.compare(STR_ERROR_)) // SUCCESS
        {
            lua_pushstring(L, signature.c_str());

            return 1;
        }
        else
        {
            std::cout << "Error : None Return Value\n";
        }
    }

    return 0;
}

//
static int eddsaTestHex(lua_State *L)
{
    if (lua_gettop(L) != 3)
    {
        std::cout << "Error : expecting exactly 3 arguments (string string)\n";
    }
    else
    {
        //
        std::string prikey = std::string(luaL_checkstring(L, 1));
        std::string pubkey = std::string(luaL_checkstring(L, 2));
        std::string data = std::string(luaL_checkstring(L, 3));

        //
        std::string signature = openssl_ed25519_sig_hex(prikey, data);

        if (signature.compare(STR_ERROR_)) // SUCCESS
        {
            int32_t ret = openssl_ed25519_verify_hex(data, signature, pubkey);

            if (ret == 0) lua_pushboolean(L, true);
            else lua_pushboolean(L, false);
        }
        else
        {
            lua_pushboolean(L, false);
        }
    }

    return 1;
}

//
static int ecK1GetPrikey(lua_State *L)
{
    if (lua_gettop(L) != 1)
    {
        std::cout << "Error : expecting exactly 1 arguments (string)\n";
    }
    else
    {
        //
        std::string prikey_path = std::string(luaL_checkstring(L, 1));

        //
        std::string prikey = openssl_ec_prikey_pem2hex_proc(false, prikey_path);

        if (prikey.compare(STR_ERROR_)) // SUCCESS
        {
            lua_pushstring(L, prikey.c_str());

            return 1;
        }
        else
        {
            std::cout << "Error : None Return Value\n";
        }
    }

    return 0;
}

static int ecK1GetPubkey(lua_State *L)
{
    if (lua_gettop(L) != 1)
    {
        std::cout << "Error : expecting exactly 1 arguments (string)\n";
    }
    else
    {
        //
        std::string pubkey_path = std::string(luaL_checkstring(L, 1));

        //
        std::string pubkey = openssl_ec_pubkey_pem2hex_proc(pubkey_path, SECP256K1);

        if (pubkey.compare(STR_ERROR_)) // SUCCESS
        {
            lua_pushstring(L, pubkey.c_str());

            return 1;
        }
        else
        {
            std::cout << "Error : None Return Value\n";
        }
    }

    return 0;
}

//
static int ecR1GetPrikey(lua_State *L)
{
    if (lua_gettop(L) != 1)
    {
        std::cout << "Error : expecting exactly 1 arguments (string)\n";
    }
    else
    {
        //
        std::string prikey_path = std::string(luaL_checkstring(L, 1));

        //
        std::string prikey = openssl_ec_prikey_pem2hex_proc(false, prikey_path);

        if (prikey.compare(STR_ERROR_)) // SUCCESS
        {
            lua_pushstring(L, prikey.c_str());

            return 1;
        }
        else
        {
            std::cout << "Error : None Return Value\n";
        }
    }

    return 0;
}

static int ecR1GetPubkey(lua_State *L)
{
    if (lua_gettop(L) != 1)
    {
        std::cout << "Error : expecting exactly 1 arguments (string)\n";
    }
    else
    {
        //
        std::string pubkey_path = std::string(luaL_checkstring(L, 1));

        //
        std::string pubkey = openssl_ec_pubkey_pem2hex_proc(pubkey_path, SECP256R1);

        if (pubkey.compare(STR_ERROR_)) // SUCCESS
        {
            lua_pushstring(L, pubkey.c_str());

            return 1;
        }
        else
        {
            std::cout << "Error : None Return Value\n";
        }
    }

    return 0;
}

//
static int ed25519GetPrikeyByPemStr(lua_State *L)
{
    if (lua_gettop(L) != 1)
    {
        std::cout << "Error : expecting exactly 1 arguments (string)\n";
    }
    else
    {
        //
        std::string pem_str = std::string(luaL_checkstring(L, 1));

        //
        std::string prikey = openssl_ed_prikey_pemstr2hex_proc(pem_str);

        if (prikey.compare(STR_ERROR_)) // SUCCESS
        {
            lua_pushstring(L, prikey.c_str());

            return 1;
        }
        else
        {
            std::cout << "Error : None Return Value\n";
        }
    }

    return 0;
}

//
static int ed25519GetPubkeyByPemStr(lua_State *L)
{
    if (lua_gettop(L) != 1)
    {
        std::cout << "Error : expecting exactly 1 arguments (string)\n";
    }
    else
    {
        //
        std::string pem_str = std::string(luaL_checkstring(L, 1));

        //
        std::string pubkey = openssl_ed_pubkey_pemstr2hex_proc(pem_str);

        if (pubkey.compare(STR_ERROR_)) // SUCCESS
        {
            lua_pushstring(L, pubkey.c_str());

            return 1;
        }
        else
        {
            std::cout << "Error : None Return Value\n";
        }
    }

    return 0;
}

//
static int ed25519GetPrikeyWithPem(lua_State *L)
{
    if (lua_gettop(L) != 1)
    {
        std::cout << "Error : expecting exactly 1 arguments (string)\n";
    }
    else
    {
        //
        std::string prikey_path = std::string(luaL_checkstring(L, 1));

        //
        std::string prikey = openssl_ed_prikey_pem2hex_proc(false, prikey_path);

        if (prikey.compare(STR_ERROR_)) // SUCCESS
        {
            lua_pushstring(L, prikey.c_str());

            return 1;
        }
        else
        {
            std::cout << "Error : None Return Value\n";
        }
    }

    return 0;
}

static int ed25519GetPubkeyWithPem(lua_State *L)
{
    if (lua_gettop(L) != 1)
    {
        std::cout << "Error : expecting exactly 1 arguments (string)\n";
    }
    else
    {
        //
        std::string pubkey_path = std::string(luaL_checkstring(L, 1));

        //
        std::string pubkey = openssl_ed_pubkey_pem2hex_proc(pubkey_path);

        if (pubkey.compare(STR_ERROR_)) // SUCCESS
        {
            lua_pushstring(L, pubkey.c_str());

            return 1;
        }
        else
        {
            std::cout << "Error : None Return Value\n";
        }
    }

    return 0;
}

// X25519
//
static int x25519KeyGenPemWithMnemonic(lua_State *L)
{
    if (lua_gettop(L) != 5)
    {
        std::cout << "Error : expecting exactly 5 arguments (string)\n";
    }
    else
    {
        //
        std::string path = std::string(luaL_checkstring(L, 1));
        std::string pw = std::string(luaL_checkstring(L, 2));
        std::string mnemonic1 = std::string(luaL_checkstring(L, 3));
        std::string mnemonic2 = std::string(luaL_checkstring(L, 4));
        uint32_t rand_num = luaL_checkinteger(L, 5);

        //
        int32_t ret = openssl_x25519_keygen_with_mnemonic_proc(path, pw, mnemonic1, mnemonic2, rand_num);

        if (ret == 0) lua_pushboolean(L, true);
        else lua_pushboolean(L, false);

        lua_pushnumber(L, ret);

        return 1;
    }

    return 0;
}

//
static int x25519KeyGenPemWithMnemonicOri(lua_State *L)
{
    if (lua_gettop(L) != 3)
    {
        std::cout << "Error : expecting exactly 3 arguments (string)\n";
    }
    else
    {
        //
        std::string path = std::string(luaL_checkstring(L, 1));
        std::string mnemonic1 = std::string(luaL_checkstring(L, 2));
        std::string pw = std::string(luaL_checkstring(L, 3));

        //
        int32_t ret = openssl_x25519_keygen_with_mnemonic_ori_proc(path, mnemonic1, pw);

        if (ret == 0) lua_pushboolean(L, true);
        else lua_pushboolean(L, false);

        lua_pushnumber(L, ret);

        return 1;
    }

    return 0;
}

//
static int x25519KeyGenPem(lua_State *L)
{
    if (lua_gettop(L) != 1)
    {
        std::cout << "Error : expecting exactly 1 arguments (string)\n";
    }
    else
    {
        //
        std::string path = std::string(luaL_checkstring(L, 1));

        //
        int32_t ret = openssl_x25519_keygen_proc(path);

        if (ret == 0) lua_pushboolean(L, true);
        else lua_pushboolean(L, false);

        return 1;
    }

    return 0;
}

//
static int x25519HexSkey(lua_State *L)
{
    if (lua_gettop(L) != 2)
    {
        std::cout << "Error : expecting exactly 2 arguments (string string)\n";
    }
    else
    {
        //
        std::string prikey_hex = std::string(luaL_checkstring(L, 1));
        std::string peer_pubkey_hex = std::string(luaL_checkstring(L, 2));

        //
        std::string skey = openssl_x25519_hex_skey(prikey_hex, peer_pubkey_hex);

        if (skey.compare(STR_ERROR_)) // SUCCESS
        {
            lua_pushstring(L, skey.c_str());

            return 1;
        }
        else
        {
            std::cout << "Error : None Return Value\n";
        }
    }

    return 0;
}

//
static int x25519PemSkey(lua_State *L)
{
    if (lua_gettop(L) != 2)
    {
        std::cout << "Error : expecting exactly 2 arguments (string string)\n";
    }
    else
    {
        //
        std::string prikey_pem = std::string(luaL_checkstring(L, 1));
        std::string peer_pubkey_pem = std::string(luaL_checkstring(L, 2));

        //
        std::string skey = openssl_x25519_pem_skey(prikey_pem, peer_pubkey_pem);

        if (skey.compare(STR_ERROR_)) // SUCCESS
        {
            lua_pushstring(L, skey.c_str());

            return 1;
        }
        else
        {
            std::cout << "Error : None Return Value\n";
        }
    }

    return 0;
}

//
static int x25519MixSkey(lua_State *L)
{
    if (lua_gettop(L) != 2)
    {
        std::cout << "Error : expecting exactly 2 arguments (string string)\n";
    }
    else
    {
        //
        std::string prikey_pem = std::string(luaL_checkstring(L, 1));
        std::string peer_pubkey_hex = std::string(luaL_checkstring(L, 2));

        //
        std::string skey = openssl_x25519_mix_skey(prikey_pem, peer_pubkey_hex);

        if (skey.compare(STR_ERROR_)) // SUCCESS
        {
            lua_pushstring(L, skey.c_str());

            return 1;
        }
        else
        {
            std::cout << "Error : None Return Value\n";
        }
    }

    return 0;
}


//
static int x25519HexEnc(lua_State *L)
{
    if (lua_gettop(L) != 4)
    {
        std::cout << "Error : expecting exactly 4 arguments (string string string number)\n";
    }
    else
    {
        //
        std::string prikey_hex = std::string(luaL_checkstring(L, 1));
        std::string peer_pubkey_hex = std::string(luaL_checkstring(L, 2));
        std::string plaintext_hex = std::string(luaL_checkstring(L, 3));
        uint32_t plaintext_hex_len = luaL_checkinteger(L, 4);

        //
        std::string encMsg = openssl_x25519_hex_enc(prikey_hex, peer_pubkey_hex, plaintext_hex, plaintext_hex_len);

        if (encMsg.compare(STR_ERROR_)) // SUCCESS
        {
            lua_pushstring(L, encMsg.c_str());

            return 1;
        }
        else
        {
            std::cout << "Error : None Return Value\n";
        }
    }

    return 0;
}

//
static int x25519HexDec(lua_State *L)
{
    if (lua_gettop(L) != 4)
    {
        std::cout << "Error : expecting exactly 4 arguments (string string string number)\n";
    }
    else
    {
        //
        std::string prikey_hex = std::string(luaL_checkstring(L, 1));
        std::string peer_pubkey_hex = std::string(luaL_checkstring(L, 2));
        std::string enc_msg_str = std::string(luaL_checkstring(L, 3));
        uint32_t enc_msg_str_len = luaL_checkinteger(L, 4);

        //
        std::string plaintext = openssl_x25519_hex_dec(prikey_hex, peer_pubkey_hex, enc_msg_str, enc_msg_str_len);

        if (plaintext.compare(STR_ERROR_)) // SUCCESS
        {
            lua_pushstring(L, plaintext.c_str());

            return 1;
        }
        else
        {
            std::cout << "Error : None Return Value\n";
        }
    }

    return 0;
}

//
static int x25519PemEnc(lua_State *L)
{
    if (lua_gettop(L) != 4)
    {
        std::cout << "Error : expecting exactly 4 arguments (string string string number)\n";
    }
    else
    {
        //
        std::string prikey_pem = std::string(luaL_checkstring(L, 1));
        std::string peer_pubkey_pem = std::string(luaL_checkstring(L, 2));
        std::string plaintext_hex = std::string(luaL_checkstring(L, 3));
        uint32_t plaintext_hex_len = luaL_checkinteger(L, 4);

        //
        std::string encMsg = openssl_x25519_pem_enc(prikey_pem, peer_pubkey_pem, plaintext_hex, plaintext_hex_len);

        if (encMsg.compare(STR_ERROR_)) // SUCCESS
        {
            lua_pushstring(L, encMsg.c_str());

            return 1;
        }
        else
        {
            std::cout << "Error : None Return Value\n";
        }
    }

    return 0;
}

//
static int x25519PemDec(lua_State *L)
{
    if (lua_gettop(L) != 4)
    {
        std::cout << "Error : expecting exactly 4 arguments (string string string number)\n";
    }
    else
    {
        //
        std::string prikey_pem = std::string(luaL_checkstring(L, 1));
        std::string peer_pubkey_pem = std::string(luaL_checkstring(L, 2));
        std::string enc_msg_str = std::string(luaL_checkstring(L, 3));
        uint32_t enc_msg_str_len = luaL_checkinteger(L, 4);

        //
        std::string plaintext = openssl_x25519_pem_dec(prikey_pem, peer_pubkey_pem, enc_msg_str, enc_msg_str_len);

        if (plaintext.compare(STR_ERROR_)) // SUCCESS
        {
            lua_pushstring(L, plaintext.c_str());

            return 1;
        }
        else
        {
            std::cout << "Error : None Return Value\n";
        }
    }

    return 0;
}

//
static int x25519MixEnc(lua_State *L)
{
    if (lua_gettop(L) != 4)
    {
        std::cout << "Error : expecting exactly 4 arguments (string string string number)\n";
    }
    else
    {
        //
        std::string prikey_pem = std::string(luaL_checkstring(L, 1));
        std::string peer_pubkey_hex = std::string(luaL_checkstring(L, 2));
        std::string plaintext_hex = std::string(luaL_checkstring(L, 3));
        uint32_t plaintext_hex_len = luaL_checkinteger(L, 4);

        //
        std::string encMsg = openssl_x25519_mix_enc(prikey_pem, peer_pubkey_hex, plaintext_hex, plaintext_hex_len);

        if (encMsg.compare(STR_ERROR_)) // SUCCESS
        {
            lua_pushstring(L, encMsg.c_str());

            return 1;
        }
        else
        {
            std::cout << "Error : None Return Value\n";
        }
    }

    return 0;
}

//
static int x25519MixDec(lua_State *L)
{
    if (lua_gettop(L) != 4)
    {
        std::cout << "Error : expecting exactly 4 arguments (string string string number)\n";
    }
    else
    {
        //
        std::string prikey_pem = std::string(luaL_checkstring(L, 1));
        std::string peer_pubkey_hex = std::string(luaL_checkstring(L, 2));
        std::string enc_msg_str = std::string(luaL_checkstring(L, 3));
        uint32_t enc_msg_str_len = luaL_checkinteger(L, 4);

        //
        std::string plaintext = openssl_x25519_mix_dec(prikey_pem, peer_pubkey_hex, enc_msg_str, enc_msg_str_len);

        if (plaintext.compare(STR_ERROR_)) // SUCCESS
        {
            lua_pushstring(L, plaintext.c_str());

            return 1;
        }
        else
        {
            std::cout << "Error : None Return Value\n";
        }
    }

    return 0;
}

//
static int aesEncPw(lua_State *L)
{
    if (lua_gettop(L) != 4)
    {
        std::cout << "Error : expecting exactly 4 arguments (string string number string)\n";
    }
    else
    {
        //
        std::string seed_path = std::string(luaL_checkstring(L, 1));
        std::string pw = std::string(luaL_checkstring(L, 2));
        uint32_t pw_len = luaL_checkinteger(L, 3);
        std::string dst_path = std::string(luaL_checkstring(L, 4));

        //
        int32_t ret = openssl_aes_encrypt_pw_proc(seed_path, pw, pw_len, dst_path);

        if (ret == 0) lua_pushboolean(L, true);
        else lua_pushboolean(L, false);

        return 1;
    }

    return 0;
}

// 
static int aesDecPw(lua_State *L)
{
    if (lua_gettop(L) != 2)
    {
        std::cout << "Error : expecting exactly 2 arguments (string string)\n";
    }
    else
    {
        //
        std::string seed_path = std::string(luaL_checkstring(L, 1));
        std::string src_path = std::string(luaL_checkstring(L, 2));

        //
        uint8_t *p_retPw = openssl_aes_decrypt_pw_proc(seed_path, src_path);

        if (p_retPw)
        {
            lua_pushstring(L, (char *)p_retPw);

            FREE_M(p_retPw);

            return 1;
        }
    }

    return 0;
}
// 
static int aesEncFile(lua_State *L)
{
    if (lua_gettop(L) != 4)
    {
        std::cout << "Error : expecting exactly 4 arguments (string string string number)\n";
    }
    else
    {
        //
        std::string src_path = std::string(luaL_checkstring(L, 1));
        std::string dst_path = std::string(luaL_checkstring(L, 2));
        std::string seed = std::string(luaL_checkstring(L, 3));
        uint32_t seed_len = luaL_checkinteger(L, 4);

        //
        int32_t ret = openssl_aes_encrypt_file_proc(src_path, dst_path, seed, seed_len);

        if (ret == 0) lua_pushboolean(L, true);
        else lua_pushboolean(L, false);

        return 1;
    }

    return 0;
}

// 
static int aesDecFile(lua_State *L)
{
    if (lua_gettop(L) != 3)
    {
        std::cout << "Error : expecting exactly 3 arguments (string string number)\n";
    }
    else
    {
        //
        std::string src_path = std::string(luaL_checkstring(L, 1));
        std::string seed = std::string(luaL_checkstring(L, 2));
		uint32_t seed_len = luaL_checkinteger(L, 3);

        //
        uint8_t *p_plane = openssl_aes_decrypt_file_proc(src_path, seed, seed_len);

        if (p_plane)
        {
            lua_pushstring(L, (char *)p_plane);

            FREE_M(p_plane);

            return 1;
        }
    }

    return 0;
}

// 
static int aesDecBinary(lua_State *L)
{
    if (lua_gettop(L) != 3)
    {
        std::cout << "Error : expecting exactly 3 arguments (string string number)\n";
    }
    else
    {
        //
        std::string enc_hex_str = std::string(luaL_checkstring(L, 1));
        std::string seed = std::string(luaL_checkstring(L, 2));
		uint32_t seed_len = luaL_checkinteger(L, 3);

        //
        uint8_t *p_plane = openssl_aes_decrypt_binary_proc(enc_hex_str, enc_hex_str.length(), seed, seed_len);

        if (p_plane)
        {
            lua_pushstring(L, (char *)p_plane);

            FREE_M(p_plane);

            return 1;
        }
    }

    return 0;
}

//
static int aes256CbcEnc(lua_State *L)
{
    if (lua_gettop(L) != 2)
    {
        std::cout << "Error : expecting exactly 3 arguments (string string number)\n";
    }
    else
    {
        //
        std::string plaintext_str = std::string(luaL_checkstring(L, 1));
        std::string seed = std::string(luaL_checkstring(L, 2));

        //
        uint32_t ciphertext_len;

        //
        std::string ciphertext = sec_aes_256_cbc_encrypt_proc(plaintext_str, plaintext_str.length(), seed, seed.length(), &ciphertext_len);

        if (ciphertext.compare(STR_ERROR_)) // SUCCESS
        {
            lua_pushstring(L, ciphertext.c_str());

            return 1;
        }
        else
        {
            std::cout << "Error : None Return Value\n";
        }
    }

    return 0;
}

//
static int aes256CbcDec(lua_State *L)
{
    if (lua_gettop(L) != 2)
    {
        std::cout << "Error : expecting exactly 3 arguments (string string number)\n";
    }
    else
    {
        //
        std::string ciphertext_hex_str = std::string(luaL_checkstring(L, 1));
        std::string seed = std::string(luaL_checkstring(L, 2));

        //
        uint32_t planetext_len;

        //
        std::string plaintext = sec_aes_256_cbc_decrypt_proc(ciphertext_hex_str, ciphertext_hex_str.length(), seed, seed.length(), &planetext_len);

        if (plaintext.compare(STR_ERROR_)) // SUCCESS
        {
            lua_pushstring(L, plaintext.c_str());

            return 1;
        }
        else
        {
            std::cout << "Error : None Return Value\n";
        }
    }

    return 0;
}

//
static int ariaEnc(lua_State *L)
{
    if (lua_gettop(L) != 2)
    {
        std::cout << "Error : expecting exactly 3 arguments (string string number)\n";
    }
    else
    {
        //
        std::string plaintext_str = std::string(luaL_checkstring(L, 1));
        std::string seed = std::string(luaL_checkstring(L, 2));

        //
        uint32_t ciphertext_len;

        //
        std::string ciphertext = sec_aria_encrypt_proc(plaintext_str, plaintext_str.length(), seed, seed.length(), &ciphertext_len);

        if (ciphertext.compare(STR_ERROR_)) // SUCCESS
        {
            lua_pushstring(L, ciphertext.c_str());

            return 1;
        }
        else
        {
            std::cout << "Error : None Return Value\n";
        }
    }

    return 0;
}

//
static int ariaDec(lua_State *L)
{
    if (lua_gettop(L) != 2)
    {
        std::cout << "Error : expecting exactly 3 arguments (string string number)\n";
    }
    else
    {
        //
        std::string ciphertext_hex_str = std::string(luaL_checkstring(L, 1));
        std::string seed = std::string(luaL_checkstring(L, 2));

        //
        uint32_t planetext_len;

        //
        std::string plaintext = sec_aria_decrypt_proc(ciphertext_hex_str, ciphertext_hex_str.length(), seed, seed.length(), &planetext_len);

        if (plaintext.compare(STR_ERROR_)) // SUCCESS
        {
            lua_pushstring(L, plaintext.c_str());

            return 1;
        }
        else
        {
            std::cout << "Error : None Return Value\n";
        }
    }

    return 0;
}

//
static int genSha256Hex(lua_State *L)
{
    if (lua_gettop(L) != 1)
    {
        std::cout << "Error : expecting exactly 1 arguments (string)\n";
    }
    else
    {
        //
        std::string data_hex = std::string(luaL_checkstring(L, 1));

        //
        std::string hashStr = openssl_sha256_hex(data_hex);

        if (hashStr.compare(STR_ERROR_)) // SUCCESS
        {
            lua_pushstring(L, hashStr.c_str());

            return 1;
        }
        else
        {
            std::cout << "Error : None Return Value\n";
        }
    }

    return 0;
}

static int genSha256Str(lua_State *L)
{
    if (lua_gettop(L) != 1)
    {
        std::cout << "Error : expecting exactly 1 arguments (string)\n";
    }
    else
    {
        //
        std::string data = std::string(luaL_checkstring(L, 1));
            
        //
        std::string hashStr = openssl_sha256_str(data);

        if (hashStr.compare(STR_ERROR_)) // SUCCESS
        {
            lua_pushstring(L, hashStr.c_str());

            return 1;
        }
        else
        {
            std::cout << "Error : None Return Value\n";
        }
    }

    return 0;
}

//
static int eddsaTest(lua_State *L)
{
    ed_verify();

	return 0;
}

static int x25519Test(lua_State *L)
{
    x25519_test();

	return 0;
}

static int aesTest(lua_State *L)
{
    aes_test();

	return 0;
}

static int ariaTest(lua_State *L)
{
    ARIA_test();

	return 0;
}
///////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////
//
static int luaRegOutTest(lua_State *L)
{
	lua_pushstring(L, "Lua ZZang");
	lua_pushnumber(L, 7);

	return 2;
}

static int luaRegInTest(lua_State *L)
{
	if (lua_gettop(L) != 2)
	{
		return luaL_error(L, "expecting exactly 2 arguments");
	}

	int count = 0;

#if 0
	char str[256] = {0x00, };
	STRCPY_M(str, (char *)luaL_checkstring(L, 1));
#elif 0
	std::string str = luaL_checkstring(L, 1);
#elif 0
	std::string str = std::string(luaL_checkstring(L, 1));
#else
	const char *str = luaL_checkstring(L, 1);
	if (!str)
	{
		return luaL_error(L, "luaL_checkstring");
	}
#endif

	count = (int)luaL_checkinteger(L, 2);

	while (count-- > 0)
	{
		printf("Message: %s\n", str);
	}

	return 0;
}
///////////////////////////////////////////////////////////////

/*
* define a function that returns version information to lua scripts
*/
static int hostgetversion(lua_State *L)
{
	/* Push the return values */
	lua_pushnumber(L, 0);
	lua_pushnumber(L, 99);
	lua_pushnumber(L, 32);
	/* Return the count of return values */
	return 3;
}

static int getHexStr(lua_State *L)
{
	char hash[32];

	for (int idx=0; idx<32; idx++)
	{
		hash[idx] = idx;
	}

	/* Push the return values */
	lua_pushlstring(L, hash, 32);

	/* Return the count of return values */
	return 1;
}

//
static int charToUtf8(lua_State *L)
{
    if (lua_gettop(L) != 1)
    {
        std::cout << "Error : expecting exactly 1 arguments (string)\n";
    }
    else
    {
        //
        std::string data = std::string(luaL_checkstring(L, 1));

        //
        std::string mbsStr = cstombs_str((char *)"C.UTF-8", (char *)data.c_str());

        if (mbsStr.compare(STR_ERROR_)) // SUCCESS
        {
            lua_pushstring(L, mbsStr.c_str());

            return 1;
        }
        else
        {
            std::cout << "Error : None Return Value\n";
        }
    }

    return 0;
}

//
static int utf8Test(lua_State *L)
{
    if (lua_gettop(L) != 1)
    {
        std::cout << "Error : expecting exactly 1 arguments (string)\n";
    }
    else
    {
        //
        std::string data = std::string(luaL_checkstring(L, 1));

        crt_wcstombs_test();
        crt_mbstowcs_test();

        //
        wchar_t *p_wcs;
        p_wcs = util_mbstowcs((char *)"C.UTF-8", (char *)data.c_str());

        //
        int32_t mbs_size;
        uint8_t *p_mbs;
        p_mbs = util_wcstombs((char *)"C.UTF-8", p_wcs, &mbs_size);
        FREE_M(p_mbs);
        // p_mbs = util_wcstombs((char *)"C.UTF-8", (wchar_t *)L"�ѱ���", &mbs_size);
        // FREE_M(p_mbs);

        // 
        p_mbs = util_cstombs((char *)"C.UTF-8", (char *)data.c_str(), &mbs_size);
        FREE_M(p_mbs);

        //
        FREE_M(p_wcs);

        lua_pushboolean(L, true);
    }

    return 0;
}

//
static int keyCreateMasterChainCode(lua_State *L)
{
    if (lua_gettop(L) != 3)
    {
        std::cout << "Error : expecting exactly 3 arguments\n";
    }
    else
    {
        //
        std::string pw = std::string(luaL_checkstring(L, 1));
        std::string mnemonic1 = std::string(luaL_checkstring(L, 2));
        std::string mnemonic2 = std::string(luaL_checkstring(L, 3));

        //
        uint32_t rand_num = key_create_master_str(pw, mnemonic1, mnemonic2);

        lua_pushnumber(L, rand_num);

        return 1;
    }

    return 0;
}

//
static int keyRestoreMasterChainCode(lua_State *L)
{
    if (lua_gettop(L) != 4)
    {
        std::cout << "Error : expecting exactly 4 arguments\n";
    }
    else
    {
        //
        std::string pw = std::string(luaL_checkstring(L, 1));
        std::string mnemonic1 = std::string(luaL_checkstring(L, 2));
        std::string mnemonic2 = std::string(luaL_checkstring(L, 3));
        uint32_t rand_num = luaL_checkinteger(L, 4);

        //
        std::string masterChainCodeStr = key_restore_master_str(pw, mnemonic1, mnemonic2, rand_num);

        if (masterChainCodeStr.compare(STR_ERROR_)) // SUCCESS
        {
            lua_pushstring(L, masterChainCodeStr.c_str());

            return 1;
        }
        else
        {
            std::cout << "Error : None Return Value\n";
        }
    }

    return 0;
}

//
static int keyCreateMasterChainCodeOri(lua_State *L)
{
    if (lua_gettop(L) != 2)
    {
        std::cout << "Error : expecting exactly 2 arguments\n";
    }
    else
    {
        //
        std::string mnemonic1 = std::string(luaL_checkstring(L, 1));
        std::string pw = std::string(luaL_checkstring(L, 2));

        //
        uint32_t masterChainCodeStrLen = key_create_master_ori_str(mnemonic1, pw);

        lua_pushnumber(L, masterChainCodeStrLen);

        return 1;
    }

    return 0;
}

//
static int keyRestoreMasterChainCodeOri(lua_State *L)
{
    if (lua_gettop(L) != 2)
    {
        std::cout << "Error : expecting exactly 2 arguments\n";
    }
    else
    {
        //
        std::string mnemonic1 = std::string(luaL_checkstring(L, 1));
        std::string pw = std::string(luaL_checkstring(L, 2));

        //
        std::string masterChainCodeStr = key_restore_master_ori_str(mnemonic1, pw);

        if (masterChainCodeStr.compare(STR_ERROR_)) // SUCCESS
        {
            lua_pushstring(L, masterChainCodeStr.c_str());

            return 1;
        }
        else
        {
            std::cout << "Error : None Return Value\n";
        }
    }

    return 0;
}

///////////////////////////////////////////////////////////////
int my_require(lua_State *L)
{
    if (lua_gettop(L) != 2)
    {
        std::cout << "Error : expecting exactly 1 arguments (string)\n";
    }
    else
    {
        // get the module name
        std::string filename = std::string(luaL_checkstring(L, 1));
        std::string filecontents = std::string(luaL_checkstring(L, 2));

        // find if you have such module loaded
        // if (mymodules.find(filename) != mymodules.end())
        {
            luaL_loadbuffer(L, filecontents.c_str(), filecontents.length(), filename.c_str());
            // the chunk is now at the top of the stack

            lua_pcall (L, 0, 0, 0);  /* execute */
            return 1;
        }
    }

    // didn't find anything
    return 0;
}
///////////////////////////////////////////////////////////////
int pre_require(lua_State *L)
{
    if (lua_gettop(L) != 2)
    {
        std::cout << "Error : expecting exactly 1 arguments (string)\n";
    }
    else
    {
        // Refer to  : https://stackoverflow.com/questions/50896799/is-it-possible-to-require-a-script-that-is-loaded-using-lual-loadstring
        // get the module name
        std::string filename = std::string(luaL_checkstring(L, 1));
        std::string filecontents = std::string(luaL_checkstring(L, 2));

        //
        // ---- Register our "fromstring" module ----
        lua_getglobal(L, "package");
        lua_getfield(L, -1, "preload");
        // lua_getfield(L, -1, "loaders");
        luaL_loadstring(L, filecontents.c_str());
        lua_setfield(L, -2, filename.c_str());
        // ------------------------------------------
        // lua_pcall(L, 0, LUA_MULTRET, 0);

        return 1;
    }

    // didn't find anything
    return 0;
}

//
void l_pushtableStr(lua_State* L , char* key , char* value)
{
    lua_pushstring(L, key);
    lua_pushstring(L, value);
    lua_settable(L, -3);
}

void l_pushtableStr2(lua_State* L , uint32_t key , char* value)
{
    lua_pushnumber(L, key);
    lua_pushstring(L, value);
    lua_settable(L, -3);
}

///////////////////////////////////////////////////////////////
// int32_t lua_addon (void)
int32_t lua_addon (int argc, char *argv[])
{
	lua_State *L = luaL_newstate();
	luaL_openlibs(L);

    //
    lua_register(L, "utcCurrMS", utcCurrMS);
    lua_register(L, "utcCurrUS", utcCurrUS);

    //
    lua_register(L, "msleep", msleep);

    //
    lua_register(L, "curlHttpGet", curlHttpGet);
    lua_register(L, "curlHttpPost", curlHttpPost);

	//
	/*  */
	lua_register(L, "luaRegOutTest", luaRegOutTest);
	lua_register(L, "luaRegInTest", luaRegInTest);

	/* register host API for script */
	lua_register(L, "hostgetversion", hostgetversion);
	lua_register(L, "getHexStr", getHexStr);

    //
    lua_register(L, "ecR1KeyGenPemWithMnemonic", ecR1KeyGenPemWithMnemonic);
    lua_register(L, "ecR1KeyGenPemWithMnemonicOri", ecR1KeyGenPemWithMnemonicOri);
    lua_register(L, "ecR1KeyGenPem", ecR1KeyGenPem);
    lua_register(L, "ecdsaR1VerifyHex", ecdsaR1VerifyHex);
    lua_register(L, "ecdsaR1SignHex", ecdsaR1SignHex);
    lua_register(L, "ecdsaR1SignPem", ecdsaR1SignPem);

    //
    lua_register(L, "ecK1KeyGenPemWithMnemonic", ecK1KeyGenPemWithMnemonic);
    lua_register(L, "ecK1KeyGenPemWithMnemonicOri", ecK1KeyGenPemWithMnemonicOri);
    lua_register(L, "ecK1KeyGenPem", ecK1KeyGenPem);
    lua_register(L, "ecdsaK1Verify", ecdsaK1Verify);
    lua_register(L, "ecdsaK1SignHex", ecdsaK1SignHex);
    lua_register(L, "ecdsaK1SignPem", ecdsaK1SignPem);

    //
    lua_register(L, "ed25519KeyGenPemWithMnemonic", ed25519KeyGenPemWithMnemonic);
    lua_register(L, "ed25519KeyGenPemWithMnemonicOri", ed25519KeyGenPemWithMnemonicOri);
    lua_register(L, "ed25519KeyGenPem", ed25519KeyGenPem);
    lua_register(L, "ed25519KeyGenPemPubkey", ed25519KeyGenPemPubkey);
    lua_register(L, "ed25519KeyGenFinWithMnemonic", ed25519KeyGenFinWithMnemonic);
    lua_register(L, "ed25519KeyGenFinWithMnemonicOri", ed25519KeyGenFinWithMnemonicOri);
    lua_register(L, "ed25519KeyGenFin", ed25519KeyGenFin);
    lua_register(L, "eddsaVerifyHex", eddsaVerifyHex);
    lua_register(L, "eddsaSignHex", eddsaSignHex);
    lua_register(L, "eddsaSignPem", eddsaSignPem);
    lua_register(L, "eddsaTestHex", eddsaTestHex);
    
    //
    lua_register(L, "ecK1GetPrikey", ecK1GetPrikey);
    lua_register(L, "ecK1GetPubkey", ecK1GetPubkey);

    //
    lua_register(L, "ecR1GetPrikey", ecR1GetPrikey);
    lua_register(L, "ecR1GetPubkey", ecR1GetPubkey);

    //
    lua_register(L, "ed25519GetPrikey", ed25519GetPrikeyWithPem);
    lua_register(L, "ed25519GetPubkey", ed25519GetPubkeyWithPem);

    //
    lua_register(L, "ed25519GetPrikeyWithPem", ed25519GetPrikeyWithPem);
    lua_register(L, "ed25519GetPubkeyWithPem", ed25519GetPubkeyWithPem);

    //
    lua_register(L, "ed25519GetPrikeyByPemStr", ed25519GetPrikeyByPemStr);
    lua_register(L, "ed25519GetPubkeyByPemStr", ed25519GetPubkeyByPemStr);

    //
    lua_register(L, "ed25519GetPrikeyNoFile", ed25519GetPrikeyByPemStr);
    lua_register(L, "ed25519GetPubkeyNoFile", ed25519GetPubkeyByPemStr);

    //
    lua_register(L, "ed25519GetPrikeyWithRawPem", ed25519GetPrikeyByPemStr);
    lua_register(L, "ed25519GetPubkeyWithRawPem", ed25519GetPubkeyByPemStr);

    //
    lua_register(L, "x25519KeyGenPemWithMnemonic", x25519KeyGenPemWithMnemonic);
    lua_register(L, "x25519KeyGenPemWithMnemonicOri", x25519KeyGenPemWithMnemonicOri);
    lua_register(L, "x25519KeyGenPem", x25519KeyGenPem);
    //
    lua_register(L, "x25519HexSkey", x25519HexSkey);
    lua_register(L, "x25519PemSkey", x25519PemSkey);
    lua_register(L, "x25519MixSkey", x25519MixSkey);
    //
    lua_register(L, "x25519HexEnc", x25519HexEnc);
    lua_register(L, "x25519HexDec", x25519HexDec);
    lua_register(L, "x25519PemEnc", x25519PemEnc);
    lua_register(L, "x25519PemDec", x25519PemDec);
    lua_register(L, "x25519MixEnc", x25519MixEnc);
    lua_register(L, "x25519MixDec", x25519MixDec);

    //
    lua_register(L, "genSha256Hex", genSha256Hex);
    lua_register(L, "genSha256Str", genSha256Str);

    //
    lua_register(L, "aesEncPw", aesEncPw);
    lua_register(L, "aesDecPw", aesDecPw);
	lua_register(L, "aesEncFile", aesEncFile);
    lua_register(L, "aesDecFile", aesDecFile);
    lua_register(L, "aesDecBinary", aesDecBinary);

    //
    lua_register(L, "aes256CbcEnc", aes256CbcEnc);
    lua_register(L, "aes256CbcDec", aes256CbcDec);
    lua_register(L, "ariaEnc", ariaEnc);
    lua_register(L, "ariaDec", ariaDec);

    //
    lua_register(L, "eddsaTest", eddsaTest);
    lua_register(L, "x25519Test", x25519Test);
    lua_register(L, "aesTest", aesTest);
    lua_register(L, "ariaTest", ariaTest);

    //
    lua_register(L, "charToUtf8", charToUtf8);
    lua_register(L, "utf8Test", utf8Test);
    lua_register(L, "keyCreateMasterChainCode", keyCreateMasterChainCode);
    lua_register(L, "keyRestoreMasterChainCode", keyRestoreMasterChainCode);
    lua_register(L, "keyCreateMasterChainCodeOri", keyCreateMasterChainCodeOri);
    lua_register(L, "keyRestoreMasterChainCodeOri", keyRestoreMasterChainCodeOri);

    /* load script */
    luaL_dofile(L, "main.lua");
    
    /* call luaConn() provided by script */
    lua_getglobal(L, "luaConn");
#if 0
    lua_call(L, 0, 1);
#else
    lua_newtable(L);
    for (int cnt=0; cnt<argc; cnt++)
    {
        // char str[10];
        // sprintf(str, "%d", cnt);

        // printf("cnt [%d] : %s\n", cnt, argv[cnt]);
        // l_pushtableStr(L, str, argv[cnt]);
        l_pushtableStr2(L, cnt+1, argv[cnt]);
    }

    lua_call(L, 1, 1);
#endif

    printf("The luaConn return %s\n", lua_tostring(L, -1));
    lua_pop(L, 1);

    //
    lua_close(L);

    return 0;
}


int main (int argc, char *argv[])
{
    printf("argc : %d\n", argc);

    for (int cnt =0; cnt<argc; cnt++)
    {
        printf("cnt [%d] : %s\n", cnt, argv[cnt]);
    }
    lua_addon(argc-1, &argv[1]);
}
