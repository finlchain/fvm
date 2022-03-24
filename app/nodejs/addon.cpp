/**
 * Description : 
 *
 * @date 2021/01/21
 * @author FINL Chain Team
 * @version 1.0
 */

// Refer to : 
//    https://github.com/bcoin-org/bcrypto/issues/7
//    https://stackoverflow.com/questions/47114090/what-does-an-empty-maybelocal-mean

#include <string>
#include <iostream>
#include <bitset>
#include <node.h>

#include "cpp_if.hpp"

//
using namespace v8;

// UTC MSEC
void utcCurrMS(const FunctionCallbackInfo<Value> &args)
{
    if(args.Length() != 0)
    {
        args.GetReturnValue().Set(false);
    }
    else
    {
        //
        v8::Isolate *isolate = args.GetIsolate();

        //
        uint64_t curr_utc_msec = util_curtime_ms();

        Local<Number> num = Number::New(isolate, curr_utc_msec);
        args.GetReturnValue().Set(num);
    }
}

// UTC USEC
void utcCurrUS(const FunctionCallbackInfo<Value> &args)
{
    if(args.Length() != 0)
    {
        args.GetReturnValue().Set(false);
    }
    else
    {
        //
        v8::Isolate *isolate = args.GetIsolate();

        //
        uint64_t curr_utc_usec = util_curtime_us();

        Local<Number> num = Number::New(isolate, curr_utc_usec);
        args.GetReturnValue().Set(num);
    }
}

// cURL HTTP GET
void curlHttpGet(const FunctionCallbackInfo<Value> &args)
{
    if(args.Length() != 2)
    {
        args.GetReturnValue().Set(false);
    }
    else
    {
        //
        v8::Isolate *isolate = args.GetIsolate();

        //
        v8::String::Utf8Value param1(isolate, args[0]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string url = std::string(*param1);

        //
        v8::String::Utf8Value param2(isolate, args[1]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string fields = std::string(*param2);

        //
        std::string ret = curl_http_get_proc(url, fields);

        if (ret.compare(STR_ERROR_)) // SUCCESS
        {
            // Local<String> returnRet = String::NewFromUtf8(isolate, ret.c_str()).ToLocalChecked();
            // args.GetReturnValue().Set(returnRet);
            Local<String> returnRet;
            v8::MaybeLocal<v8::String> temp = String::NewFromUtf8(isolate, ret.c_str());
            if (temp.ToLocal(&returnRet))
            {
                args.GetReturnValue().Set(returnRet);
            }
            else
            {
                // Error
            }
        }
        else
        {
            args.GetReturnValue().Set(false);
        }
    }
}

// cURL HTTP POST
void curlHttpPost(const FunctionCallbackInfo<Value> &args)
{
    if(args.Length() != 2)
    {
        args.GetReturnValue().Set(false);
    }
    else
    {
        //
        v8::Isolate *isolate = args.GetIsolate();

        //
        v8::String::Utf8Value param1(isolate, args[0]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string url = std::string(*param1);

        //
        v8::String::Utf8Value param2(isolate, args[1]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string fields = std::string(*param2);

        //
        std::string ret = curl_http_post_proc(url, fields);

        if (ret.compare(STR_ERROR_)) // SUCCESS
        {
            // Local<String> returnRet = String::NewFromUtf8(isolate, ret.c_str()).ToLocalChecked();
            // args.GetReturnValue().Set(returnRet);
            Local<String> returnRet;
            v8::MaybeLocal<v8::String> temp = String::NewFromUtf8(isolate, ret.c_str());
            if (temp.ToLocal(&returnRet))
            {
                args.GetReturnValue().Set(returnRet);
            }
            else
            {
                // Error
            }
        }
        else
        {
            args.GetReturnValue().Set(false);
        }
    }
}

// EC R1
//
void ecR1KeyGenPemWithMnemonic(const FunctionCallbackInfo<Value> &args)
{
    if(args.Length() != 5)
    {
        args.GetReturnValue().Set(false);
    }
    else
    {
        //
        v8::Isolate *isolate = args.GetIsolate();

        //
        v8::String::Utf8Value param1(isolate, args[0]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string path = std::string(*param1);

        //
        v8::String::Utf8Value param2(isolate, args[1]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string pw = std::string(*param2);

        //
        v8::String::Utf8Value param3(isolate, args[2]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string mnemonic1 = std::string(*param3);

        //
        v8::String::Utf8Value param4(isolate, args[3]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string mnemonic2 = std::string(*param4);

        uint32_t rand_num = args[4]->NumberValue(isolate->GetCurrent()->GetCurrentContext()).FromJust();

        //
        int32_t ret = openssl_ec_keygen_with_mnemonic_proc(path, SECP256R1, pw, mnemonic1, mnemonic2, rand_num);

        if (ret == 0) args.GetReturnValue().Set(true);
        else args.GetReturnValue().Set(false);
    }
}

//
void ecR1KeyGenPemWithMnemonicOri(const FunctionCallbackInfo<Value> &args)
{
    if(args.Length() != 3)
    {
        args.GetReturnValue().Set(false);
    }
    else
    {
        //
        v8::Isolate *isolate = args.GetIsolate();

        //
        v8::String::Utf8Value param1(isolate, args[0]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string path = std::string(*param1);

        //
        v8::String::Utf8Value param2(isolate, args[1]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string mnemonic1 = std::string(*param2);

        //
        v8::String::Utf8Value param3(isolate, args[2]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string pw = std::string(*param3);

        //
        int32_t ret = openssl_ec_keygen_with_mnemonic_ori_proc(path, SECP256R1, mnemonic1, pw);

        if (ret == 0) args.GetReturnValue().Set(true);
        else args.GetReturnValue().Set(false);
    }
}

//
void ecR1KeyGenPem(const FunctionCallbackInfo<Value> &args)
{
    if(args.Length() != 1)
    {
        args.GetReturnValue().Set(false);
    }
    else
    {
        //
        v8::Isolate *isolate = args.GetIsolate();

        //
        v8::String::Utf8Value param1(isolate, args[0]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string path = std::string(*param1);

        //
        int32_t ret = openssl_ec_keygen_proc(path, SECP256R1);

        if (ret == 0) args.GetReturnValue().Set(true);
        else args.GetReturnValue().Set(false);
    }
}

void ecdsaR1VerifyHex(const FunctionCallbackInfo<Value> &args)
{
    if(args.Length() != 4)
    {
        args.GetReturnValue().Set(false);
    }
    else
    {
        //
        v8::Isolate *isolate = args.GetIsolate();

        //
        v8::String::Utf8Value param1(isolate, args[0]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string data = std::string(*param1);
        v8::String::Utf8Value param2(isolate, args[1]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string sig_r = std::string(*param2);
        v8::String::Utf8Value param3(isolate, args[2]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string sig_s = std::string(*param3);      
        v8::String::Utf8Value param4(isolate, args[3]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string comp_pubkey = std::string(*param4);

        //
        // int32_t ret = openssl_ecdsa_r1_verify(data, sig_r, sig_s, comp_pubkey);
        int32_t ret = openssl_ecdsa_verify_hex(data, sig_r, sig_s, comp_pubkey, SECP256R1);

        if(ret == 0) args.GetReturnValue().Set(true);
        else args.GetReturnValue().Set(false);
    }
}

void ecdsaR1SignHex(const FunctionCallbackInfo<Value> &args)
{
    if (args.Length() != 2)
    {
        args.GetReturnValue().Set(false);
    }
    else
    {
        //
        v8::Isolate *isolate = args.GetIsolate();

        //
        v8::String::Utf8Value param1(isolate, args[0]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string data = std::string(*param1);
        v8::String::Utf8Value param2(isolate, args[1]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string prikey = std::string(*param2);

        //
        std::string signature = openssl_ecdsa_sig_hex(prikey, data, SECP256R1);

        if (signature.compare(STR_ERROR_)) // SUCCESS
        {
            // Local<String> returnSig = String::NewFromUtf8(isolate, signature.c_str()).ToLocalChecked();
            // args.GetReturnValue().Set(returnSig);
            Local<String> returnSig;
            v8::MaybeLocal<v8::String> temp = String::NewFromUtf8(isolate, signature.c_str());
            if (temp.ToLocal(&returnSig))
            {
                args.GetReturnValue().Set(returnSig);
            }
            else
            {
                // Error
            }
        }
        else
        {
            args.GetReturnValue().Set(false);
        }
    }
}

void ecdsaR1SignPem(const FunctionCallbackInfo<Value> &args)
{
    if (args.Length() != 2)
    {
        args.GetReturnValue().Set(false);
    }
    else
    {
        //
        v8::Isolate *isolate = args.GetIsolate();

        //
        v8::String::Utf8Value param1(isolate, args[0]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string data = std::string(*param1);
        v8::String::Utf8Value param2(isolate, args[1]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string prikey_path = std::string(*param2);

        //
        std::string signature = openssl_ecdsa_sig_pem(false, prikey_path, data);

        if (signature.compare(STR_ERROR_)) // SUCCESS
        {
            // Local<String> returnSig = String::NewFromUtf8(isolate, signature.c_str()).ToLocalChecked();
            // args.GetReturnValue().Set(returnSig);
            Local<String> returnSig;
            v8::MaybeLocal<v8::String> temp = String::NewFromUtf8(isolate, signature.c_str());
            if (temp.ToLocal(&returnSig))
            {
                args.GetReturnValue().Set(returnSig);
            }
            else
            {
                // Error
            }
        }
        else
        {
            args.GetReturnValue().Set(false);
        }
    }
}

// ECDSA K1
//
void ecK1KeyGenPemWithMnemonic(const FunctionCallbackInfo<Value> &args)
{
    if(args.Length() != 5)
    {
        args.GetReturnValue().Set(false);
    }
    else
    {
        //
        v8::Isolate *isolate = args.GetIsolate();

        //
        v8::String::Utf8Value param1(isolate, args[0]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string path = std::string(*param1);

        //
        v8::String::Utf8Value param2(isolate, args[1]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string pw = std::string(*param2);

        //
        v8::String::Utf8Value param3(isolate, args[2]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string mnemonic1 = std::string(*param3);

        //
        v8::String::Utf8Value param4(isolate, args[3]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string mnemonic2 = std::string(*param4);

        uint32_t rand_num = args[4]->NumberValue(isolate->GetCurrent()->GetCurrentContext()).FromJust();

        //
        int32_t ret = openssl_ec_keygen_with_mnemonic_proc(path, SECP256K1, pw, mnemonic1, mnemonic2, rand_num);

        if (ret == 0) args.GetReturnValue().Set(true);
        else args.GetReturnValue().Set(false);
    }
}

//
void ecK1KeyGenPemWithMnemonicOri(const FunctionCallbackInfo<Value> &args)
{
    if(args.Length() != 3)
    {
        args.GetReturnValue().Set(false);
    }
    else
    {
        //
        v8::Isolate *isolate = args.GetIsolate();

        //
        v8::String::Utf8Value param1(isolate, args[0]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string path = std::string(*param1);

        //
        v8::String::Utf8Value param2(isolate, args[1]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string mnemonic1 = std::string(*param2);

        //
        v8::String::Utf8Value param3(isolate, args[2]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string pw = std::string(*param3);

        //
        int32_t ret = openssl_ec_keygen_with_mnemonic_ori_proc(path, SECP256K1, mnemonic1, pw);

        if (ret == 0) args.GetReturnValue().Set(true);
        else args.GetReturnValue().Set(false);
    }
}

//
void ecK1KeyGenPem(const FunctionCallbackInfo<Value> &args)
{
    if(args.Length() != 1)
    {
        args.GetReturnValue().Set(false);
    }
    else
    {
        //
        v8::Isolate *isolate = args.GetIsolate();

        //
        v8::String::Utf8Value param1(isolate, args[0]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string path = std::string(*param1);

        //
        int32_t ret = openssl_ec_keygen_proc(path, SECP256K1);

        if (ret == 0) args.GetReturnValue().Set(true);
        else args.GetReturnValue().Set(false);
    }
}

void ecdsaK1Verify(const FunctionCallbackInfo<Value> &args)
{
    if (args.Length() != 4)
    {
        args.GetReturnValue().Set(false);
    }
    else
    {
        //
        v8::Isolate *isolate = args.GetIsolate();

        //
        v8::String::Utf8Value param1(isolate, args[0]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string data = std::string(*param1);
        v8::String::Utf8Value param2(isolate, args[1]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string sig_r = std::string(*param2);
        v8::String::Utf8Value param3(isolate, args[2]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string sig_s = std::string(*param3);
        v8::String::Utf8Value param4(isolate, args[3]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string comp_pubkey = std::string(*param4);

        //
        // int32_t ret = openssl_ecdsa_k1_verify(data, sig_r, sig_s, comp_pubkey);
        int32_t ret = openssl_ecdsa_verify_hex(data, sig_r, sig_s, comp_pubkey, SECP256R1);

        if (ret == 0) args.GetReturnValue().Set(true);
        else args.GetReturnValue().Set(false);
    }
}
void ecdsaK1SignHex(const FunctionCallbackInfo<Value> &args)
{
    if (args.Length() != 2)
    {
        args.GetReturnValue().Set(false);
    }
    else
    {
        //
        v8::Isolate *isolate = args.GetIsolate();

        //
        v8::String::Utf8Value param1(isolate, args[0]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string data = std::string(*param1);
        v8::String::Utf8Value param2(isolate, args[1]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string prikey = std::string(*param2);

        //
        std::string signature = openssl_ecdsa_sig_hex(prikey, data, SECP256K1);

        if (signature.compare(STR_ERROR_)) // SUCCESS
        {
            // Local<String> returnSig = String::NewFromUtf8(isolate, signature.c_str()).ToLocalChecked();
            // args.GetReturnValue().Set(returnSig);
            Local<String> returnSig;
            v8::MaybeLocal<v8::String> temp = String::NewFromUtf8(isolate, signature.c_str());
            if (temp.ToLocal(&returnSig))
            {
                args.GetReturnValue().Set(returnSig);
            }
            else
            {
                // Error
            }
        }
        else
        {
            args.GetReturnValue().Set(false);
        }
    }
}

void ecdsaK1SignPem(const FunctionCallbackInfo<Value> &args)
{
    if (args.Length() != 2)
    {
        args.GetReturnValue().Set(false);
    }
    else
    {
        //
        v8::Isolate *isolate = args.GetIsolate();

        //
        v8::String::Utf8Value param1(isolate, args[0]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string data = std::string(*param1);
        v8::String::Utf8Value param2(isolate, args[1]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string prikey_path = std::string(*param2);

        //
        std::string signature = openssl_ecdsa_sig_pem(false, prikey_path, data);

        if (signature.compare(STR_ERROR_)) // SUCCESS
        {
            // Local<String> returnSig = String::NewFromUtf8(isolate, signature.c_str()).ToLocalChecked();
            // args.GetReturnValue().Set(returnSig);
            Local<String> returnSig;
            v8::MaybeLocal<v8::String> temp = String::NewFromUtf8(isolate, signature.c_str());
            if (temp.ToLocal(&returnSig))
            {
                args.GetReturnValue().Set(returnSig);
            }
            else
            {
                // Error
            }
        }
        else
        {
            args.GetReturnValue().Set(false);
        }
    }
}


// EDDSA
//
void ed25519KeyGenPemWithMnemonic(const FunctionCallbackInfo<Value> &args)
{
    if(args.Length() != 5)
    {
        args.GetReturnValue().Set(false);
    }
    else
    {
        //
        v8::Isolate *isolate = args.GetIsolate();

        //
        v8::String::Utf8Value param1(isolate, args[0]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string path = std::string(*param1);

        //
        v8::String::Utf8Value param2(isolate, args[1]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string pw = std::string(*param2);

        //
        v8::String::Utf8Value param3(isolate, args[2]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string mnemonic1 = std::string(*param3);

        //
        v8::String::Utf8Value param4(isolate, args[3]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string mnemonic2 = std::string(*param4);

        uint32_t rand_num = args[4]->NumberValue(isolate->GetCurrent()->GetCurrentContext()).FromJust();

        //
        int32_t ret = openssl_ed25519_keygen_with_mnemonic_proc(path, pw, mnemonic1, mnemonic2, rand_num);

        if (ret == 0) args.GetReturnValue().Set(true);
        else args.GetReturnValue().Set(false);
    }
}

//
void ed25519KeyGenPemWithMnemonicOri(const FunctionCallbackInfo<Value> &args)
{
    if(args.Length() != 3)
    {
        args.GetReturnValue().Set(false);
    }
    else
    {
        //
        v8::Isolate *isolate = args.GetIsolate();

        //
        v8::String::Utf8Value param1(isolate, args[0]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string path = std::string(*param1);

        //
        v8::String::Utf8Value param2(isolate, args[1]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string mnemonic1 = std::string(*param2);

        //
        v8::String::Utf8Value param3(isolate, args[2]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string pw = std::string(*param3);

        //
        int32_t ret = openssl_ed25519_keygen_with_mnemonic_ori_proc(path, mnemonic1, pw);

        if (ret == 0) args.GetReturnValue().Set(true);
        else args.GetReturnValue().Set(false);
    }
}


//
void ed25519KeyGenPem(const FunctionCallbackInfo<Value> &args)
{
    if(args.Length() != 1)
    {
        args.GetReturnValue().Set(false);
    }
    else
    {
        //
        v8::Isolate *isolate = args.GetIsolate();

        //
        v8::String::Utf8Value param1(isolate, args[0]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string path = std::string(*param1);

        //
        int32_t ret = openssl_ed25519_keygen_proc(path);

        if (ret == 0) args.GetReturnValue().Set(true);
        else args.GetReturnValue().Set(false);
    }
}

//
void ed25519KeyGenPemPubkey(const FunctionCallbackInfo<Value> &args)
{
    if(args.Length() != 1)
    {
        args.GetReturnValue().Set(false);
    }
    else
    {
        //
        v8::Isolate *isolate = args.GetIsolate();

        //
        v8::String::Utf8Value param1(isolate, args[0]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string path = std::string(*param1);

        //
        int32_t ret = openssl_ed25519_keygen_pubkey_proc(path);

        if (ret == 0) args.GetReturnValue().Set(true);
        else args.GetReturnValue().Set(false);
    }
}

//
void ed25519KeyGenFinWithMnemonic(const FunctionCallbackInfo<Value> &args)
{
    if(args.Length() != 7)
    {
        args.GetReturnValue().Set(false);
    }
    else
    {
        //
        v8::Isolate *isolate = args.GetIsolate();

        //
        v8::String::Utf8Value param1(isolate, args[0]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string path = std::string(*param1);
        v8::String::Utf8Value param2(isolate, args[1]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string pw = std::string(*param2);
        v8::String::Utf8Value param3(isolate, args[2]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string mnemonic1 = std::string(*param3);
        v8::String::Utf8Value param4(isolate, args[3]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string mnemonic2 = std::string(*param4);
        uint32_t rand_num = args[4]->NumberValue(isolate->GetCurrent()->GetCurrentContext()).FromJust();
        v8::String::Utf8Value param6(isolate, args[5]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string seed = std::string(*param6);
        uint32_t seed_len = args[6]->NumberValue(isolate->GetCurrent()->GetCurrentContext()).FromJust();

        //
        int32_t ret = openssl_ed25519_keygen_fin_with_mnemonic_proc(path, pw, mnemonic1, mnemonic2, rand_num, seed, seed_len);

        if (ret == 0) args.GetReturnValue().Set(true);
        else args.GetReturnValue().Set(false);
    }
}

//
void ed25519KeyGenFinWithMnemonicOri(const FunctionCallbackInfo<Value> &args)
{
    if(args.Length() != 5)
    {
        args.GetReturnValue().Set(false);
    }
    else
    {
        //
        v8::Isolate *isolate = args.GetIsolate();

        //
        v8::String::Utf8Value param1(isolate, args[0]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string path = std::string(*param1);
        v8::String::Utf8Value param2(isolate, args[1]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string mnemonic1 = std::string(*param2);
        v8::String::Utf8Value param3(isolate, args[2]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string pw = std::string(*param3);
        v8::String::Utf8Value param4(isolate, args[3]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string seed = std::string(*param4);
        uint32_t seed_len = args[4]->NumberValue(isolate->GetCurrent()->GetCurrentContext()).FromJust();

        //
        int32_t ret = openssl_ed25519_keygen_fin_with_mnemonic_ori_proc(path, mnemonic1, pw, seed, seed_len);

        if (ret == 0) args.GetReturnValue().Set(true);
        else args.GetReturnValue().Set(false);
    }
}

//
void ed25519KeyGenFin(const FunctionCallbackInfo<Value> &args)
{
    if(args.Length() != 3)
    {
        args.GetReturnValue().Set(false);
    }
    else
    {
        //
        v8::Isolate *isolate = args.GetIsolate();

        //
        v8::String::Utf8Value param1(isolate, args[0]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string path = std::string(*param1);
        v8::String::Utf8Value param2(isolate, args[1]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string seed = std::string(*param2);
        uint32_t seed_len = args[2]->NumberValue(isolate->GetCurrent()->GetCurrentContext()).FromJust();

        //
        int32_t ret = openssl_ed25519_keygen_fin_proc(path, seed, seed_len);

        if (ret == 0) args.GetReturnValue().Set(true);
        else args.GetReturnValue().Set(false);
    }
}

void eddsaVerifyHex(const FunctionCallbackInfo<Value> &args)
{

    if(args.Length() != 3)
    {
        args.GetReturnValue().Set(false);
    }
    else
    {
        //
        v8::Isolate *isolate = args.GetIsolate();

        //
        v8::String::Utf8Value param1(isolate, args[0]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string data = std::string(*param1);
        v8::String::Utf8Value param2(isolate, args[1]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string signature = std::string(*param2);
        v8::String::Utf8Value param3(isolate, args[2]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string pubkey = std::string(*param3);

        //
        // int32_t ret = openssl_eddsa_verify(data, signature, pubkey);
        int32_t ret = openssl_ed25519_verify_hex(data, signature, pubkey);

        if (ret == 0) args.GetReturnValue().Set(true);
        else args.GetReturnValue().Set(false);
    }
}

void eddsaSignHex(const FunctionCallbackInfo<Value> &args)
{
    if (args.Length() != 2)
    {
        args.GetReturnValue().Set(false);
    }
    else
    {
        //
        v8::Isolate *isolate = args.GetIsolate();

        //
        v8::String::Utf8Value param1(isolate, args[0]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string data = std::string(*param1);
        v8::String::Utf8Value param2(isolate, args[1]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string prikey = std::string(*param2);

        //
        std::string signature = openssl_ed25519_sig_hex(prikey, data);

        if (signature.compare(STR_ERROR_)) // SUCCESS
        {
            // Local<String> returnSig = String::NewFromUtf8(isolate, signature.c_str()).ToLocalChecked();
            // args.GetReturnValue().Set(returnSig);
            Local<String> returnSig;
            v8::MaybeLocal<v8::String> temp = String::NewFromUtf8(isolate, signature.c_str());
            if (temp.ToLocal(&returnSig))
            {
                args.GetReturnValue().Set(returnSig);
            }
            else
            {
                // Error
            }
        }
        else
        {
            args.GetReturnValue().Set(false);
        }
    }
}

void eddsaSignPem(const FunctionCallbackInfo<Value> &args)
{
    if (args.Length() != 2)
    {
        args.GetReturnValue().Set(false);
    }
    else
    {
        //
        v8::Isolate *isolate = args.GetIsolate();

        //
        v8::String::Utf8Value param1(isolate, args[0]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string data = std::string(*param1);
        v8::String::Utf8Value param2(isolate, args[1]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string prvkeyPath = std::string(*param2);

        //
        std::string signature = openssl_ed25519_sig_pem(false, prvkeyPath, data);

        if (signature.compare(STR_ERROR_)) // SUCCESS
        {
            // Local<String> returnSig = String::NewFromUtf8(isolate, signature.c_str()).ToLocalChecked();
            // args.GetReturnValue().Set(returnSig);
            Local<String> returnSig;
            v8::MaybeLocal<v8::String> temp = String::NewFromUtf8(isolate, signature.c_str());
            if (temp.ToLocal(&returnSig))
            {
                args.GetReturnValue().Set(returnSig);
            }
            else
            {
                // Error
            }
        }
        else
        {
            args.GetReturnValue().Set(false);
        }
    }
}

//
void ecK1GetPrikey(const FunctionCallbackInfo<Value> &args)
{
    if (args.Length() != 1)
    {
        args.GetReturnValue().Set(false);
    }
    else
    {
        //
        v8::Isolate *isolate = args.GetIsolate();

        //
        v8::String::Utf8Value param1(isolate, args[0]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string prikey_path = std::string(*param1);

        //
        std::string prikey = openssl_ec_prikey_pem2hex_proc(false, prikey_path);

        if (prikey.compare(STR_ERROR_)) // SUCCESS
        {
            // Local<String> retPrikey = String::NewFromUtf8(isolate, prikey.c_str()).ToLocalChecked();
            // args.GetReturnValue().Set(retPrikey);
            Local<String> retPrikey;
            v8::MaybeLocal<v8::String> temp = String::NewFromUtf8(isolate, prikey.c_str());
            if (temp.ToLocal(&retPrikey))
            {
                args.GetReturnValue().Set(retPrikey);
            }
            else
            {
                // Error
            }
        }
        else
        {
            args.GetReturnValue().Set(false);
        }
    }
}

void ecK1GetPubkey(const FunctionCallbackInfo<Value> &args)
{
    if (args.Length() != 1)
    {
        args.GetReturnValue().Set(false);
    }
    else
    {
        //
        v8::Isolate *isolate = args.GetIsolate();

        //
        v8::String::Utf8Value param1(isolate, args[0]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string pubkey_path = std::string(*param1);

        //
        std::string pubkey = openssl_ec_pubkey_pem2hex_proc(pubkey_path, SECP256K1);

        if (pubkey.compare(STR_ERROR_)) // SUCCESS
        {
            // Local<String> retPubkey = String::NewFromUtf8(isolate, pubkey.c_str()).ToLocalChecked();
            // args.GetReturnValue().Set(retPubkey);
            Local<String> retPubkey;
            v8::MaybeLocal<v8::String> temp = String::NewFromUtf8(isolate, pubkey.c_str());
            if (temp.ToLocal(&retPubkey))
            {
                args.GetReturnValue().Set(retPubkey);
            }
            else
            {
                // Error
            }
        }
        else
        {
            args.GetReturnValue().Set(false);
        }
    }
}

//
void ecR1GetPrikey(const FunctionCallbackInfo<Value> &args)
{
    if (args.Length() != 1)
    {
        args.GetReturnValue().Set(false);
    }
    else
    {
        //
        v8::Isolate *isolate = args.GetIsolate();

        //
        v8::String::Utf8Value param1(isolate, args[0]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string prikey_path = std::string(*param1);

        //
        std::string prikey = openssl_ec_prikey_pem2hex_proc(false, prikey_path);

        if (prikey.compare(STR_ERROR_)) // SUCCESS
        {
            // Local<String> retPrikey = String::NewFromUtf8(isolate, prikey.c_str()).ToLocalChecked();
            // args.GetReturnValue().Set(retPrikey);
            Local<String> retPrikey;
            v8::MaybeLocal<v8::String> temp = String::NewFromUtf8(isolate, prikey.c_str());
            if (temp.ToLocal(&retPrikey))
            {
                args.GetReturnValue().Set(retPrikey);
            }
            else
            {
                // Error
            }
        }
        else
        {
            args.GetReturnValue().Set(false);
        }
    }
}

void ecR1GetPubkey(const FunctionCallbackInfo<Value> &args)
{
    if (args.Length() != 1)
    {
        args.GetReturnValue().Set(false);
    }
    else
    {
        //
        v8::Isolate *isolate = args.GetIsolate();

        //
        v8::String::Utf8Value param1(isolate, args[0]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string pubkey_path = std::string(*param1);

        //
        std::string pubkey = openssl_ec_pubkey_pem2hex_proc(pubkey_path, SECP256R1);

        if (pubkey.compare(STR_ERROR_)) // SUCCESS
        {
            // Local<String> retPubkey = String::NewFromUtf8(isolate, pubkey.c_str()).ToLocalChecked();
            // args.GetReturnValue().Set(retPubkey);
            Local<String> retPubkey;
            v8::MaybeLocal<v8::String> temp = String::NewFromUtf8(isolate, pubkey.c_str());
            if (temp.ToLocal(&retPubkey))
            {
                args.GetReturnValue().Set(retPubkey);
            }
            else
            {
                // Error
            }
        }
        else
        {
            args.GetReturnValue().Set(false);
        }
    }
}

//
void ed25519GetPrikeyByPemStr(const FunctionCallbackInfo<Value> &args)
{
    if (args.Length() != 1)
    {
        args.GetReturnValue().Set(false);
    }
    else
    {
        //
        v8::Isolate *isolate = args.GetIsolate();

        //
        v8::String::Utf8Value param1(isolate, args[0]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string pem_str = std::string(*param1);

        //
        std::string prikey = openssl_ed_prikey_pemstr2hex_proc(pem_str);

        if (prikey.compare(STR_ERROR_)) // SUCCESS
        {
            // Local<String> retPrikey = String::NewFromUtf8(isolate, prikey.c_str()).ToLocalChecked();
            // args.GetReturnValue().Set(retPrikey);
            Local<String> retPrikey;
            v8::MaybeLocal<v8::String> temp = String::NewFromUtf8(isolate, prikey.c_str());
            if (temp.ToLocal(&retPrikey))
            {
                args.GetReturnValue().Set(retPrikey);
            }
            else
            {
                // Error
            }
        }
        else
        {
            args.GetReturnValue().Set(false);
        }
    }
}

//
void ed25519GetPrikey(const FunctionCallbackInfo<Value> &args)
{
    if (args.Length() != 1)
    {
        args.GetReturnValue().Set(false);
    }
    else
    {
        //
        v8::Isolate *isolate = args.GetIsolate();

        //
        v8::String::Utf8Value param1(isolate, args[0]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string prikey_path = std::string(*param1);

        //
        std::string prikey = openssl_ed_prikey_pem2hex_proc(false, prikey_path);

        if (prikey.compare(STR_ERROR_)) // SUCCESS
        {
            // Local<String> retPrikey = String::NewFromUtf8(isolate, prikey.c_str()).ToLocalChecked();
            // args.GetReturnValue().Set(retPrikey);
            Local<String> retPrikey;
            v8::MaybeLocal<v8::String> temp = String::NewFromUtf8(isolate, prikey.c_str());
            if (temp.ToLocal(&retPrikey))
            {
                args.GetReturnValue().Set(retPrikey);
            }
            else
            {
                // Error
            }
        }
        else
        {
            args.GetReturnValue().Set(false);
        }
    }
}

void ed25519GetPubkey(const FunctionCallbackInfo<Value> &args)
{
    if (args.Length() != 1)
    {
        args.GetReturnValue().Set(false);
    }
    else
    {
        //
        v8::Isolate *isolate = args.GetIsolate();

        //
        v8::String::Utf8Value param1(isolate, args[0]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string pubkey_path = std::string(*param1);

        //
        std::string pubkey = openssl_ed_pubkey_pem2hex_proc(pubkey_path);

        if (pubkey.compare(STR_ERROR_)) // SUCCESS
        {
            // Local<String> retPubkey = String::NewFromUtf8(isolate, pubkey.c_str()).ToLocalChecked();
            // args.GetReturnValue().Set(retPubkey);
            Local<String> retPubkey;
            v8::MaybeLocal<v8::String> temp = String::NewFromUtf8(isolate, pubkey.c_str());
            if (temp.ToLocal(&retPubkey))
            {
                args.GetReturnValue().Set(retPubkey);
            }
            else
            {
                // Error
            }
        }
        else
        {
            args.GetReturnValue().Set(false);
        }
    }
}

//
// X25519
//
void x25519KeyGenPemWithMnemonic(const FunctionCallbackInfo<Value> &args)
{
    if(args.Length() != 5)
    {
        args.GetReturnValue().Set(false);
    }
    else
    {
        //
        v8::Isolate *isolate = args.GetIsolate();

        //
        v8::String::Utf8Value param1(isolate, args[0]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string path = std::string(*param1);

        //
        v8::String::Utf8Value param2(isolate, args[1]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string pw = std::string(*param2);

        //
        v8::String::Utf8Value param3(isolate, args[2]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string mnemonic1 = std::string(*param3);

        //
        v8::String::Utf8Value param4(isolate, args[3]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string mnemonic2 = std::string(*param4);

        uint32_t rand_num = args[4]->NumberValue(isolate->GetCurrent()->GetCurrentContext()).FromJust();

        //
        int32_t ret = openssl_x25519_keygen_with_mnemonic_proc(path, pw, mnemonic1, mnemonic2, rand_num);

        if (ret == 0) args.GetReturnValue().Set(true);
        else args.GetReturnValue().Set(false);
    }
}

//
void x25519KeyGenPemWithMnemonicOri(const FunctionCallbackInfo<Value> &args)
{
    if(args.Length() != 3)
    {
        args.GetReturnValue().Set(false);
    }
    else
    {
        //
        v8::Isolate *isolate = args.GetIsolate();

        //
        v8::String::Utf8Value param1(isolate, args[0]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string path = std::string(*param1);

        //
        v8::String::Utf8Value param2(isolate, args[1]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string mnemonic1 = std::string(*param2);

        //
        v8::String::Utf8Value param3(isolate, args[2]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string pw = std::string(*param3);

        //
        int32_t ret = openssl_x25519_keygen_with_mnemonic_ori_proc(path, mnemonic1, pw);

        if (ret == 0) args.GetReturnValue().Set(true);
        else args.GetReturnValue().Set(false);
    }
}

//
void x25519KeyGenPem(const FunctionCallbackInfo<Value> &args)
{
    if(args.Length() != 1)
    {
        args.GetReturnValue().Set(false);
    }
    else
    {
        //
        v8::Isolate *isolate = args.GetIsolate();

        //
        v8::String::Utf8Value param1(isolate, args[0]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string path = std::string(*param1);

        //
        int32_t ret = openssl_x25519_keygen_proc(path);

        if (ret == 0) args.GetReturnValue().Set(true);
        else args.GetReturnValue().Set(false);
    }
}

//
void x25519HexSkey(const FunctionCallbackInfo<Value> &args)
{
    if (args.Length() != 2)
    {
        args.GetReturnValue().Set(false);
    }
    else
    {
        //
        v8::Isolate *isolate = args.GetIsolate();

        //
        v8::String::Utf8Value param1(isolate, args[0]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string prikey_hex = std::string(*param1);
        v8::String::Utf8Value param2(isolate, args[1]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string peer_pubkey_hex = std::string(*param2);

        //
        std::string skey = openssl_x25519_hex_skey(prikey_hex, peer_pubkey_hex);

        if (skey.compare(STR_ERROR_)) // SUCCESS
        {
            // Local<String> returnSkey = String::NewFromUtf8(isolate, skey.c_str()).ToLocalChecked();
            // args.GetReturnValue().Set(returnSkey);
            Local<String> returnSkey;
            v8::MaybeLocal<v8::String> temp = String::NewFromUtf8(isolate, skey.c_str());
            if (temp.ToLocal(&returnSkey))
            {
                args.GetReturnValue().Set(returnSkey);
            }
            else
            {
                // Error
            }
        }
        else
        {
            args.GetReturnValue().Set(false);
        }
    }
}

//
void x25519PemSkey(const FunctionCallbackInfo<Value> &args)
{
    if (args.Length() != 2)
    {
        args.GetReturnValue().Set(false);
    }
    else
    {
        //
        v8::Isolate *isolate = args.GetIsolate();

        //
        v8::String::Utf8Value param1(isolate, args[0]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string prikey_pem = std::string(*param1);
        v8::String::Utf8Value param2(isolate, args[1]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string peer_pubkey_pem = std::string(*param2);

        //
        std::string skey = openssl_x25519_pem_skey(prikey_pem, peer_pubkey_pem);

        if (skey.compare(STR_ERROR_)) // SUCCESS
        {
            // Local<String> returnSkey = String::NewFromUtf8(isolate, skey.c_str()).ToLocalChecked();
            // args.GetReturnValue().Set(returnSkey);
            Local<String> returnSkey;
            v8::MaybeLocal<v8::String> temp = String::NewFromUtf8(isolate, skey.c_str());
            if (temp.ToLocal(&returnSkey))
            {
                args.GetReturnValue().Set(returnSkey);
            }
            else
            {
                // Error
            }
        }
        else
        {
            args.GetReturnValue().Set(false);
        }
    }
}

//
void x25519MixSkey(const FunctionCallbackInfo<Value> &args)
{
    if (args.Length() != 2)
    {
        args.GetReturnValue().Set(false);
    }
    else
    {
        //
        v8::Isolate *isolate = args.GetIsolate();

        //
        v8::String::Utf8Value param1(isolate, args[0]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string prikey_pem = std::string(*param1);
        v8::String::Utf8Value param2(isolate, args[1]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string peer_pubkey_hex = std::string(*param2);

        //
        std::string skey = openssl_x25519_mix_skey(prikey_pem, peer_pubkey_hex);

        if (skey.compare(STR_ERROR_)) // SUCCESS
        {
            // Local<String> returnSkey = String::NewFromUtf8(isolate, skey.c_str()).ToLocalChecked();
            // args.GetReturnValue().Set(returnSkey);
            Local<String> returnSkey;
            v8::MaybeLocal<v8::String> temp = String::NewFromUtf8(isolate, skey.c_str());
            if (temp.ToLocal(&returnSkey))
            {
                args.GetReturnValue().Set(returnSkey);
            }
            else
            {
                // Error
            }
        }
        else
        {
            args.GetReturnValue().Set(false);
        }
    }
}

//
void x25519HexEnc(const FunctionCallbackInfo<Value> &args)
{
    if (args.Length() != 4)
    {
        args.GetReturnValue().Set(false);
    }
    else
    {
        //
        v8::Isolate *isolate = args.GetIsolate();

        //
        v8::String::Utf8Value param1(isolate, args[0]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string prikey_hex = std::string(*param1);
        v8::String::Utf8Value param2(isolate, args[1]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string peer_pubkey_hex = std::string(*param2);
        v8::String::Utf8Value param3(isolate, args[2]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string plaintext_hex = std::string(*param3);
        uint32_t plaintext_hex_len = args[3]->NumberValue(isolate->GetCurrent()->GetCurrentContext()).FromJust();

        //
        std::string encMsg = openssl_x25519_hex_enc(prikey_hex, peer_pubkey_hex, plaintext_hex, plaintext_hex_len);

        if (encMsg.compare(STR_ERROR_)) // SUCCESS
        {
            // Local<String> returnEncMsg = String::NewFromUtf8(isolate, encMsg.c_str()).ToLocalChecked();
            // args.GetReturnValue().Set(returnEncMsg);
            Local<String> returnEncMsg;
            v8::MaybeLocal<v8::String> temp = String::NewFromUtf8(isolate, encMsg.c_str());
            if (temp.ToLocal(&returnEncMsg))
            {
                args.GetReturnValue().Set(returnEncMsg);
            }
            else
            {
                // Error
            }
        }
        else
        {
            args.GetReturnValue().Set(false);
        }
    }
}

//
void x25519HexDec(const FunctionCallbackInfo<Value> &args)
{
    if (args.Length() != 4)
    {
        args.GetReturnValue().Set(false);
    }
    else
    {
        //
        v8::Isolate *isolate = args.GetIsolate();

        //
        v8::String::Utf8Value param1(isolate, args[0]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string prikey_hex = std::string(*param1);
        v8::String::Utf8Value param2(isolate, args[1]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string peer_pubkey_hex = std::string(*param2);
        v8::String::Utf8Value param3(isolate, args[2]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string enc_msg_str = std::string(*param3);
        uint32_t enc_msg_str_len = args[3]->NumberValue(isolate->GetCurrent()->GetCurrentContext()).FromJust();

        //
        std::string plaintext = openssl_x25519_hex_dec(prikey_hex, peer_pubkey_hex, enc_msg_str, enc_msg_str_len);

        if (plaintext.compare(STR_ERROR_)) // SUCCESS
        {
            // Local<String> returnPlainText = String::NewFromUtf8(isolate, plaintext.c_str()).ToLocalChecked();
            // args.GetReturnValue().Set(returnPlainText);
            Local<String> returnPlainText;
            v8::MaybeLocal<v8::String> temp = String::NewFromUtf8(isolate, plaintext.c_str());
            if (temp.ToLocal(&returnPlainText))
            {
                args.GetReturnValue().Set(returnPlainText);
            }
            else
            {
                // Error
            }
        }
        else
        {
            args.GetReturnValue().Set(false);
        }
    }
}

//
void x25519PemEnc(const FunctionCallbackInfo<Value> &args)
{
    if (args.Length() != 4)
    {
        args.GetReturnValue().Set(false);
    }
    else
    {
        //
        v8::Isolate *isolate = args.GetIsolate();

        //
        v8::String::Utf8Value param1(isolate, args[0]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string prikey_pem = std::string(*param1);
        v8::String::Utf8Value param2(isolate, args[1]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string peer_pubkey_pem = std::string(*param2);
        v8::String::Utf8Value param3(isolate, args[2]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string plaintext_hex = std::string(*param3);
        uint32_t plaintext_hex_len = args[3]->NumberValue(isolate->GetCurrent()->GetCurrentContext()).FromJust();

        //
        std::string encMsg = openssl_x25519_pem_enc(prikey_pem, peer_pubkey_pem, plaintext_hex, plaintext_hex_len);

        if (encMsg.compare(STR_ERROR_)) // SUCCESS
        {
            // Local<String> returnEncMsg = String::NewFromUtf8(isolate, encMsg.c_str()).();
            // args.GetReturnValue().Set(returnEncMsg);
            Local<String> returnEncMsg;
            v8::MaybeLocal<v8::String> temp = String::NewFromUtf8(isolate, encMsg.c_str());
            if (temp.ToLocal(&returnEncMsg))
            {
                args.GetReturnValue().Set(returnEncMsg);
            }
            else
            {
                // Error
            }
        }
        else
        {
            args.GetReturnValue().Set(false);
        }
    }
}

//
void x25519PemDec(const FunctionCallbackInfo<Value> &args)
{
    if (args.Length() != 4)
    {
        args.GetReturnValue().Set(false);
    }
    else
    {
        //
        v8::Isolate *isolate = args.GetIsolate();

        //
        v8::String::Utf8Value param1(isolate, args[0]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string prikey_pem = std::string(*param1);
        v8::String::Utf8Value param2(isolate, args[1]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string peer_pubkey_pem = std::string(*param2);
        v8::String::Utf8Value param3(isolate, args[2]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string enc_msg_str = std::string(*param3);
        uint32_t enc_msg_str_len = args[3]->NumberValue(isolate->GetCurrent()->GetCurrentContext()).FromJust();

        //
        std::string plaintext = openssl_x25519_pem_dec(prikey_pem, peer_pubkey_pem, enc_msg_str, enc_msg_str_len);

        if (plaintext.compare(STR_ERROR_)) // SUCCESS
        {
            // Local<String> returnPlaintext = String::NewFromUtf8(isolate, plaintext.c_str()).ToLocalChecked();
            // args.GetReturnValue().Set(returnPlaintext);
            Local<String> returnPlainText;
            v8::MaybeLocal<v8::String> temp = String::NewFromUtf8(isolate, plaintext.c_str());
            if (temp.ToLocal(&returnPlainText))
            {
                args.GetReturnValue().Set(returnPlainText);
            }
            else
            {
                // Error
            }
        }
        else
        {
            args.GetReturnValue().Set(false);
        }
    }
}

//
void x25519MixEnc(const FunctionCallbackInfo<Value> &args)
{
    if (args.Length() != 4)
    {
        args.GetReturnValue().Set(false);
    }
    else
    {
        //
        v8::Isolate *isolate = args.GetIsolate();

        //
        v8::String::Utf8Value param1(isolate, args[0]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string prikey_pem = std::string(*param1);
        v8::String::Utf8Value param2(isolate, args[1]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string peer_pubkey_hex = std::string(*param2);
        v8::String::Utf8Value param3(isolate, args[2]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string plaintext_hex = std::string(*param3);
        uint32_t plaintext_hex_len = args[3]->NumberValue(isolate->GetCurrent()->GetCurrentContext()).FromJust();

        //
        std::string encMsg = openssl_x25519_mix_enc(prikey_pem, peer_pubkey_hex, plaintext_hex, plaintext_hex_len);

        if (encMsg.compare(STR_ERROR_)) // SUCCESS
        {
            // Local<String> returnEncMsg = String::NewFromUtf8(isolate, encMsg.c_str()).ToLocalChecked();
            // args.GetReturnValue().Set(returnEncMsg);
            Local<String> returnEncMsg;
            v8::MaybeLocal<v8::String> temp = String::NewFromUtf8(isolate, encMsg.c_str());
            if (temp.ToLocal(&returnEncMsg))
            {
                args.GetReturnValue().Set(returnEncMsg);
            }
            else
            {
                // Error
            }
        }
        else
        {
            args.GetReturnValue().Set(false);
        }
    }
}

//
void x25519MixDec(const FunctionCallbackInfo<Value> &args)
{
    if (args.Length() != 4)
    {
        args.GetReturnValue().Set(false);
    }
    else
    {
        //
        v8::Isolate *isolate = args.GetIsolate();

        //
        v8::String::Utf8Value param1(isolate, args[0]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string prikey_pem = std::string(*param1);
        v8::String::Utf8Value param2(isolate, args[1]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string peer_pubkey_hex = std::string(*param2);
        v8::String::Utf8Value param3(isolate, args[2]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string enc_msg_str = std::string(*param3);
        uint32_t enc_msg_str_len = args[3]->NumberValue(isolate->GetCurrent()->GetCurrentContext()).FromJust();

        //
        std::string plaintext = openssl_x25519_mix_dec(prikey_pem, peer_pubkey_hex, enc_msg_str, enc_msg_str_len);

        if (plaintext.compare(STR_ERROR_)) // SUCCESS
        {
            // Local<String> returnPlaintext = String::NewFromUtf8(isolate, plaintext.c_str()).ToLocalChecked();
            // args.GetReturnValue().Set(returnPlaintext);
            Local<String> returnPlainText;
            v8::MaybeLocal<v8::String> temp = String::NewFromUtf8(isolate, plaintext.c_str());
            if (temp.ToLocal(&returnPlainText))
            {
                args.GetReturnValue().Set(returnPlainText);
            }
            else
            {
                // Error
            }
        }
        else
        {
            args.GetReturnValue().Set(false);
        }
    }
}

//
void aesEncPw(const FunctionCallbackInfo<Value> &args)
{
    if (args.Length() != 4)
    {
        args.GetReturnValue().Set(false);
    }
    else
    {
        //
        v8::Isolate *isolate = args.GetIsolate();

        //
        v8::String::Utf8Value param0(isolate, args[0]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string seed_path = std::string(*param0);
        v8::String::Utf8Value param1(isolate, args[1]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string pw = std::string(*param1);
        uint32_t pw_len = args[2]->NumberValue(isolate->GetCurrent()->GetCurrentContext()).FromJust();
        v8::String::Utf8Value param3(isolate, args[3]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string dst_path = std::string(*param3);

        //
        int32_t ret = openssl_aes_encrypt_pw_proc(seed_path, pw, pw_len, dst_path);

        if (ret == 0) args.GetReturnValue().Set(true);
        else args.GetReturnValue().Set(false);
    }
}

// 
void aesDecPw(const FunctionCallbackInfo<Value> &args)
{
    if (args.Length() != 2)
    {
        args.GetReturnValue().Set(false);
    }
    else
    {
        //
        v8::Isolate *isolate = args.GetIsolate();

        //
        v8::String::Utf8Value param0(isolate, args[0]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string seed_path = std::string(*param0);
        v8::String::Utf8Value param1(isolate, args[1]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string src_path = std::string(*param1);

        //
        uint8_t *p_retPw = openssl_aes_decrypt_pw_proc(seed_path, src_path);

        if (p_retPw)
        {
            // Local<String> pw = String::NewFromUtf8(isolate, ((char *)p_retPw)).ToLocalChecked();
            // args.GetReturnValue().Set(pw);
            Local<String> pw;
            v8::MaybeLocal<v8::String> temp = String::NewFromUtf8(isolate, (char *)p_retPw);
            if (temp.ToLocal(&pw))
            {
                args.GetReturnValue().Set(pw);
            }
            else
            {
                // Error
            }

            FREE_M(p_retPw);
        }
        else
        {
            args.GetReturnValue().Set(false);
        }
    }
}

// 
void aesEncFile(const FunctionCallbackInfo<Value> &args)
{
    if (args.Length() != 4)
    {
        args.GetReturnValue().Set(false);
    }
    else
    {
        //
        v8::Isolate *isolate = args.GetIsolate();

        //
        v8::String::Utf8Value param0(isolate, args[0]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string src_path = std::string(*param0);
        v8::String::Utf8Value param1(isolate, args[1]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string dst_path = std::string(*param1);
        v8::String::Utf8Value param2(isolate, args[2]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string seed = std::string(*param2);
        uint32_t seed_len = args[3]->NumberValue(isolate->GetCurrent()->GetCurrentContext()).FromJust();

        //
        int32_t ret = openssl_aes_encrypt_file_proc(src_path, dst_path, seed, seed_len);

        if (ret == 0) args.GetReturnValue().Set(true);
        else args.GetReturnValue().Set(false);
    }
}

// 
void aesDecFile(const FunctionCallbackInfo<Value> &args)
{
    if (args.Length() != 3)
    {
        args.GetReturnValue().Set(false);
    }
    else
    {
        //
        v8::Isolate *isolate = args.GetIsolate();

        //
        v8::String::Utf8Value param0(isolate, args[0]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string src_path = std::string(*param0);
        v8::String::Utf8Value param1(isolate, args[1]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string seed = std::string(*param1);
		uint32_t seed_len = args[2]->NumberValue(isolate->GetCurrent()->GetCurrentContext()).FromJust();

        //
        uint8_t *p_plane = openssl_aes_decrypt_file_proc(src_path, seed, seed_len);

        if (p_plane)
        {
            // Local<String> p_plane_ = String::NewFromUtf8(isolate, ((char *)p_plane)).ToLocalChecked();
            // args.GetReturnValue().Set(p_plane_);
            Local<String> p_plane_;
            v8::MaybeLocal<v8::String> temp = String::NewFromUtf8(isolate, (char *)p_plane);
            if (temp.ToLocal(&p_plane_))
            {
                args.GetReturnValue().Set(p_plane_);
            }
            else
            {
                // Error
            }

            FREE_M(p_plane);
        }
        else
        {
            args.GetReturnValue().Set(false);
        }
    }
}

// 
void aesDecBinary(const FunctionCallbackInfo<Value> &args)
{
    if (args.Length() != 3)
    {
        args.GetReturnValue().Set(false);
    }
    else
    {
        //
        v8::Isolate *isolate = args.GetIsolate();

        //
        v8::String::Utf8Value param0(isolate, args[0]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string enc_hex_str = std::string(*param0);
        v8::String::Utf8Value param1(isolate, args[1]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string seed = std::string(*param1);
		uint32_t seed_len = args[2]->NumberValue(isolate->GetCurrent()->GetCurrentContext()).FromJust();

        //
        uint8_t *p_plane = openssl_aes_decrypt_binary_proc(enc_hex_str, enc_hex_str.length(), seed, seed_len);

        if (p_plane)
        {
            // Local<String> p_plane_ = String::NewFromUtf8(isolate, ((char *)p_plane)).ToLocalChecked();
            // args.GetReturnValue().Set(p_plane_);
            Local<String> p_plane_;
            v8::MaybeLocal<v8::String> temp = String::NewFromUtf8(isolate, (char *)p_plane);
            if (temp.ToLocal(&p_plane_))
            {
                args.GetReturnValue().Set(p_plane_);
            }
            else
            {
                // Error
            }

            FREE_M(p_plane);
        }
        else
        {
            args.GetReturnValue().Set(false);
        }
    }
}

//
void aes256CbcEnc(const FunctionCallbackInfo<Value> &args)
{
    if (args.Length() != 2)
    {
        args.GetReturnValue().Set(false);
    }
    else
    {
        //
        v8::Isolate *isolate = args.GetIsolate();

        //
        v8::String::Utf8Value param0(isolate, args[0]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string plaintext_str = std::string(*param0);
        v8::String::Utf8Value param1(isolate, args[1]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string seed = std::string(*param1);

        //
        uint32_t ciphertext_len;

        //
        std::string ciphertext = sec_aes_256_cbc_encrypt_proc(plaintext_str, plaintext_str.length(), seed, seed.length(), &ciphertext_len);

        if (ciphertext.compare(STR_ERROR_)) // SUCCESS
        {
            // Local<String> returnCiphertext = String::NewFromUtf8(isolate, ciphertext.c_str()).ToLocalChecked();
            // args.GetReturnValue().Set(returnCiphertext);
            Local<String> returnCiphertext;
            v8::MaybeLocal<v8::String> temp = String::NewFromUtf8(isolate, ciphertext.c_str());
            if (temp.ToLocal(&returnCiphertext))
            {
                args.GetReturnValue().Set(returnCiphertext);
            }
            else
            {
                // Error
            }
        }
        else
        {
            args.GetReturnValue().Set(false);
        }
    }  
}

void aes256CbcDec(const FunctionCallbackInfo<Value> &args)
{
    if (args.Length() != 2)
    {
        args.GetReturnValue().Set(false);
    }
    else
    {
        //
        v8::Isolate *isolate = args.GetIsolate();

        //
        v8::String::Utf8Value param0(isolate, args[0]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string ciphertext_hex_str = std::string(*param0);
        v8::String::Utf8Value param1(isolate, args[1]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string seed = std::string(*param1);

        //
        uint32_t plaintext_len;

        //
        std::string plaintext = sec_aes_256_cbc_decrypt_proc(ciphertext_hex_str, ciphertext_hex_str.length(), seed, seed.length(), &plaintext_len);

        if (plaintext.compare(STR_ERROR_)) // SUCCESS
        {
            // Local<String> returnPlaintext = String::NewFromUtf8(isolate, plaintext.c_str()).ToLocalChecked();
            // args.GetReturnValue().Set(returnPlaintext);
            Local<String> returnPlaintext;
            v8::MaybeLocal<v8::String> temp = String::NewFromUtf8(isolate, plaintext.c_str());
            if (temp.ToLocal(&returnPlaintext))
            {
                args.GetReturnValue().Set(returnPlaintext);
            }
            else
            {
                // Error
            }
        }
        else
        {
            args.GetReturnValue().Set(false);
        }
    }  
}

//
void ariaEnc(const FunctionCallbackInfo<Value> &args)
{
    if (args.Length() != 2)
    {
        args.GetReturnValue().Set(false);
    }
    else
    {
        //
        v8::Isolate *isolate = args.GetIsolate();

        //
        v8::String::Utf8Value param0(isolate, args[0]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string plaintext_str = std::string(*param0);
        v8::String::Utf8Value param1(isolate, args[1]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string seed = std::string(*param1);

        //
        uint32_t ciphertext_len;

        //
        std::string ciphertext = sec_aria_encrypt_proc(plaintext_str, plaintext_str.length(), seed, seed.length(), &ciphertext_len);

        if (ciphertext.compare(STR_ERROR_)) // SUCCESS
        {
            // Local<String> returnCiphertext = String::NewFromUtf8(isolate, ciphertext.c_str()).ToLocalChecked();
            // args.GetReturnValue().Set(returnCiphertext);
            Local<String> returnCiphertext;
            v8::MaybeLocal<v8::String> temp = String::NewFromUtf8(isolate, ciphertext.c_str());
            if (temp.ToLocal(&returnCiphertext))
            {
                args.GetReturnValue().Set(returnCiphertext);
            }
            else
            {
                // Error
            }
        }
        else
        {
            args.GetReturnValue().Set(false);
        }
    }  
}

void ariaDec(const FunctionCallbackInfo<Value> &args)
{
    if (args.Length() != 2)
    {
        args.GetReturnValue().Set(false);
    }
    else
    {
        //
        v8::Isolate *isolate = args.GetIsolate();

        //
        v8::String::Utf8Value param0(isolate, args[0]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string ciphertext_hex_str = std::string(*param0);
        v8::String::Utf8Value param1(isolate, args[1]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string seed = std::string(*param1);

        //
        uint32_t plaintext_len;

        //
        std::string plaintext = sec_aria_decrypt_proc(ciphertext_hex_str, ciphertext_hex_str.length(), seed, seed.length(), &plaintext_len);

        if (plaintext.compare(STR_ERROR_)) // SUCCESS
        {
            // Local<String> returnPlaintext = String::NewFromUtf8(isolate, plaintext.c_str()).ToLocalChecked();
            // args.GetReturnValue().Set(returnPlaintext);
            Local<String> returnPlaintext;
            v8::MaybeLocal<v8::String> temp = String::NewFromUtf8(isolate, plaintext.c_str());
            if (temp.ToLocal(&returnPlaintext))
            {
                args.GetReturnValue().Set(returnPlaintext);
            }
            else
            {
                // Error
            }
        }
        else
        {
            args.GetReturnValue().Set(false);
        }
    }  
}

//
void genSha256Hex(const FunctionCallbackInfo<Value> &args)
{
    if (args.Length() != 1)
    {
        args.GetReturnValue().Set(false);
    }
    else
    {
        //
        v8::Isolate *isolate = args.GetIsolate();

        //
        v8::String::Utf8Value param0(isolate, args[0]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string data_hex = std::string(*param0);

        //
        std::string hashStr = openssl_sha256_hex(data_hex);

        if (hashStr.compare(STR_ERROR_)) // SUCCESS
        {
            // Local<String> retHashStr = String::NewFromUtf8(isolate, hashStr.c_str()).ToLocalChecked();
            // args.GetReturnValue().Set(retHashStr);
            Local<String> retHashStr;
            v8::MaybeLocal<v8::String> temp = String::NewFromUtf8(isolate, hashStr.c_str());
            if (temp.ToLocal(&retHashStr))
            {
                args.GetReturnValue().Set(retHashStr);
            }
            else
            {
                // Error
            }
        }
        else
        {
            args.GetReturnValue().Set(false);
        }
    }
}

void genSha256Str(const FunctionCallbackInfo<Value> &args)
{
    if (args.Length() != 1)
    {
        args.GetReturnValue().Set(false);
    }
    else
    {
        //
        v8::Isolate *isolate = args.GetIsolate();

        //
        v8::String::Utf8Value param0(isolate, args[0]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string data = std::string(*param0);

        //
        std::string hashStr = openssl_sha256_str(data);

        if (hashStr.compare(STR_ERROR_)) // SUCCESS
        {
            // Local<String> retHashStr = String::NewFromUtf8(isolate, hashStr.c_str()).ToLocalChecked();
            // args.GetReturnValue().Set(retHashStr);
            Local<String> retHashStr;
            v8::MaybeLocal<v8::String> temp = String::NewFromUtf8(isolate, hashStr.c_str());
            if (temp.ToLocal(&retHashStr))
            {
                args.GetReturnValue().Set(retHashStr);
            }
            else
            {
                // Error
            }
        }
        else
        {
            args.GetReturnValue().Set(false);
        }
    }
}

//
void eddsaTest(const FunctionCallbackInfo<Value> &args)
{
    ed_verify();
}

void x25519Test(const FunctionCallbackInfo<Value> &args)
{
    x25519_test();
}

void aesTest(const FunctionCallbackInfo<Value> &args)
{
    aes_test();
}

void ariaTest(const FunctionCallbackInfo<Value> &args)
{
    ARIA_test();
}

//
void charToUtf8(const FunctionCallbackInfo<Value> &args)
{
    if (args.Length() != 1)
    {
        args.GetReturnValue().Set(false);
    }
    else
    {
        //
        v8::Isolate *isolate = args.GetIsolate();

        //
        v8::String::Utf8Value param0(isolate, args[0]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string data = std::string(*param0);

        //
        std::string mbsStr = cstombs_str((char *)"C.UTF-8", (char *)data.c_str());

        if (mbsStr.compare(STR_ERROR_)) // SUCCESS
        {
            // Local<String> retMbsStr = String::NewFromUtf8(isolate, mbsStr.c_str()).ToLocalChecked();
            // args.GetReturnValue().Set(retMbsStr);
            Local<String> retMbsStr;
            v8::MaybeLocal<v8::String> temp = String::NewFromUtf8(isolate, mbsStr.c_str());
            if (temp.ToLocal(&retMbsStr))
            {
                args.GetReturnValue().Set(retMbsStr);
            }
            else
            {
                // Error
            }
        }
        else
        {
            args.GetReturnValue().Set(false);
        }
    }
}

//
void utf8Test(const FunctionCallbackInfo<Value> &args)
{
    if (args.Length() != 1)
    {
        args.GetReturnValue().Set(false);
    }
    else
    {
        //
        v8::Isolate *isolate = args.GetIsolate();

        //
        v8::String::Utf8Value param0(isolate, args[0]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string data = std::string(*param0);

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
        // p_mbs = util_wcstombs((char *)"C.UTF-8", (wchar_t *)L"한국이", &mbs_size);
        // FREE_M(p_mbs);

        // 
        p_mbs = util_cstombs((char *)"C.UTF-8", (char *)data.c_str(), &mbs_size);
        FREE_M(p_mbs);

        //
        FREE_M(p_wcs);

        args.GetReturnValue().Set(true);
    }
}

//
void keyCreateMasterChainCode(const FunctionCallbackInfo<Value> &args)
{
    if (args.Length() != 3)
    {
        args.GetReturnValue().Set(false);
    }
    else
    {
        //
        v8::Isolate *isolate = args.GetIsolate();

        //
        v8::String::Utf8Value param0(isolate, args[0]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string pw = std::string(*param0);
        v8::String::Utf8Value param1(isolate, args[1]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string mnemonic1 = std::string(*param1);
        v8::String::Utf8Value param2(isolate, args[2]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string mnemonic2 = std::string(*param2);

        //
        uint32_t rand_num = key_create_master_str(pw, mnemonic1, mnemonic2);

        args.GetReturnValue().Set(rand_num);
    }
    
}

//
void keyRestoreMasterChainCode(const FunctionCallbackInfo<Value> &args)
{
    if (args.Length() != 4)
    {
        args.GetReturnValue().Set(false);
    }
    else
    {
        //
        v8::Isolate *isolate = args.GetIsolate();

        //
        v8::String::Utf8Value param0(isolate, args[0]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string pw = std::string(*param0);
        v8::String::Utf8Value param1(isolate, args[1]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string mnemonic1 = std::string(*param1);
        v8::String::Utf8Value param2(isolate, args[2]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string mnemonic2 = std::string(*param2);
        uint32_t rand_num = args[3]->NumberValue(isolate->GetCurrent()->GetCurrentContext()).FromJust();

        //
        std::string chainCodeStr = key_restore_master_str(pw, mnemonic1, mnemonic2, rand_num);

        if (chainCodeStr.compare(STR_ERROR_)) // SUCCESS
        {
            // Local<String> retChainCodeStrStr = String::NewFromUtf8(isolate, chainCodeStr.c_str()).ToLocalChecked();
            // args.GetReturnValue().Set(retChainCodeStrStr);
            Local<String> retChainCodeStrStr;
            v8::MaybeLocal<v8::String> temp = String::NewFromUtf8(isolate, chainCodeStr.c_str());
            if (temp.ToLocal(&retChainCodeStrStr))
            {
                args.GetReturnValue().Set(retChainCodeStrStr);
            }
            else
            {
                // Error
            }
        }
        else
        {
            args.GetReturnValue().Set(false);
        }
    }
    
}

//
void keyCreateMasterChainCodeOri(const FunctionCallbackInfo<Value> &args)
{
    if (args.Length() != 2)
    {
        args.GetReturnValue().Set(false);
    }
    else
    {
        //
        v8::Isolate *isolate = args.GetIsolate();

        //
        v8::String::Utf8Value param0(isolate, args[0]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string mnemonic1 = std::string(*param0);
        v8::String::Utf8Value param1(isolate, args[1]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string pw = std::string(*param1);

        //
        uint32_t msterChainCodeStrLen = key_create_master_ori_str(mnemonic1, pw);

        args.GetReturnValue().Set(msterChainCodeStrLen);
    }
    
}

//
void keyRestoreMasterChainCodeOri(const FunctionCallbackInfo<Value> &args)
{
    if (args.Length() != 2)
    {
        args.GetReturnValue().Set(false);
    }
    else
    {
        //
        v8::Isolate *isolate = args.GetIsolate();

        //
        v8::String::Utf8Value param0(isolate, args[0]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string mnemonic1 = std::string(*param0);
        v8::String::Utf8Value param1(isolate, args[1]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string pw = std::string(*param1);

        //
        std::string masterChainCodeStr = key_restore_master_ori_str(mnemonic1, pw);

        if (masterChainCodeStr.compare(STR_ERROR_)) // SUCCESS
        {
            // Local<String> retMasterChainCodeStrStr = String::NewFromUtf8(isolate, masterChainCodeStr.c_str()).ToLocalChecked();
            // Local<String> retMasterChainCodeStrStr = String::NewFromUtf8(isolate, masterChainCodeStr.c_str());
            // args.GetReturnValue().Set(retMasterChainCodeStrStr);
            Local<String> retMasterChainCodeStrStr;
            v8::MaybeLocal<v8::String> temp = String::NewFromUtf8(isolate, masterChainCodeStr.c_str());
            if (temp.ToLocal(&retMasterChainCodeStrStr))
            {
                args.GetReturnValue().Set(retMasterChainCodeStrStr);
            }
            else
            {
                // Error
            }
        }
        else
        {
            args.GetReturnValue().Set(false);
        }
    }
    
}

//
void addonTest(const FunctionCallbackInfo<Value> &args)
{
    if (args.Length() != 3)
    {
        args.GetReturnValue().Set(false);
    }
    else
    {
        //
        v8::Isolate *isolate = args.GetIsolate();

        //
        v8::String::Utf8Value param0(isolate, args[0]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string str_1 = std::string(*param0);

        // v8::String::Utf8Value param1(isolate, args[1]->ToString());
        v8::String::Utf8Value param1(isolate, args[1]->ToString(isolate->GetCurrent()->GetCurrentContext()).FromMaybe(v8::Local<v8::String>()));
        std::string str_2 = std::string(*param1);
        
		// uint32_t num_1 = args[2]->NumberValue();
        uint32_t num_1 = args[2]->NumberValue(isolate->GetCurrent()->GetCurrentContext()).FromJust();
        // uint32_t num_1 = args[2]->Int32Value(Nan::GetCurrentContext()).FromJust();
        // uint32_t num_1 = args[2]->Int32Value(isolate->GetCurrent()->GetCurrentContext()).FromJust();

        std::cout << "str_1 : " << str_1 << "\n";
        std::cout << "str_2 : " << str_2 << "\n";
        std::cout << "num_1 : " << num_1 << "\n";

        // double d = NAN;

        // std::cout << "std::isnan(d) : " << std::isnan(d) << '\n';
        // std::cout << "isnan(d) : " << isnan(d) << '\n';
    }
}

//
void Initialize(Local<Object> exports, Local<Object> module)
{
    //
    NODE_SET_METHOD(exports, "utcCurrMS", utcCurrMS);
    NODE_SET_METHOD(exports, "utcCurrUS", utcCurrUS);

    //
    NODE_SET_METHOD(exports, "curlHttpGet", curlHttpGet);
    NODE_SET_METHOD(exports, "curlHttpPost", curlHttpPost);

    //
    NODE_SET_METHOD(exports, "ecR1KeyGenPemWithMnemonic", ecR1KeyGenPemWithMnemonic);
    NODE_SET_METHOD(exports, "ecR1KeyGenPemWithMnemonicOri", ecR1KeyGenPemWithMnemonicOri);
    NODE_SET_METHOD(exports, "ecR1KeyGenPem", ecR1KeyGenPem);
    NODE_SET_METHOD(exports, "ecdsaR1VerifyHex", ecdsaR1VerifyHex);
    NODE_SET_METHOD(exports, "ecdsaR1SignHex", ecdsaR1SignHex);
    NODE_SET_METHOD(exports, "ecdsaR1SignPem", ecdsaR1SignPem);

    //
    NODE_SET_METHOD(exports, "ecK1KeyGenPemWithMnemonic", ecK1KeyGenPemWithMnemonic);
    NODE_SET_METHOD(exports, "ecK1KeyGenPemWithMnemonicOri", ecK1KeyGenPemWithMnemonicOri);
    NODE_SET_METHOD(exports, "ecK1KeyGenPem", ecK1KeyGenPem);
    NODE_SET_METHOD(exports, "ecdsaK1Verify", ecdsaK1Verify);
    NODE_SET_METHOD(exports, "ecdsaK1SignHex", ecdsaK1SignHex);
    NODE_SET_METHOD(exports, "ecdsaK1SignPem", ecdsaK1SignPem);

    //
    NODE_SET_METHOD(exports, "ed25519KeyGenPemWithMnemonic", ed25519KeyGenPemWithMnemonic);
    NODE_SET_METHOD(exports, "ed25519KeyGenPemWithMnemonicOri", ed25519KeyGenPemWithMnemonicOri);
    NODE_SET_METHOD(exports, "ed25519KeyGenPem", ed25519KeyGenPem);
    NODE_SET_METHOD(exports, "ed25519KeyGenPemPubkey", ed25519KeyGenPemPubkey);
    NODE_SET_METHOD(exports, "ed25519KeyGenFinWithMnemonic", ed25519KeyGenFinWithMnemonic);
    NODE_SET_METHOD(exports, "ed25519KeyGenFinWithMnemonicOri", ed25519KeyGenFinWithMnemonicOri);
    NODE_SET_METHOD(exports, "ed25519KeyGenFin", ed25519KeyGenFin);
    NODE_SET_METHOD(exports, "eddsaVerifyHex", eddsaVerifyHex);
    NODE_SET_METHOD(exports, "eddsaSignHex", eddsaSignHex);
    NODE_SET_METHOD(exports, "eddsaSignPem", eddsaSignPem);

    //
    NODE_SET_METHOD(exports, "ecK1GetPrikey", ecK1GetPrikey);
    NODE_SET_METHOD(exports, "ecK1GetPubkey", ecK1GetPubkey);

    //
    NODE_SET_METHOD(exports, "ecR1GetPrikey", ecR1GetPrikey);
    NODE_SET_METHOD(exports, "ecR1GetPubkey", ecR1GetPubkey);

    //
    NODE_SET_METHOD(exports, "ed25519GetPrikeyByPemStr", ed25519GetPrikeyByPemStr);

    //
    NODE_SET_METHOD(exports, "ed25519GetPrikey", ed25519GetPrikey);
    NODE_SET_METHOD(exports, "ed25519GetPubkey", ed25519GetPubkey);

    //
    NODE_SET_METHOD(exports, "x25519KeyGenPemWithMnemonic", x25519KeyGenPemWithMnemonic);
    NODE_SET_METHOD(exports, "x25519KeyGenPemWithMnemonicOri", x25519KeyGenPemWithMnemonicOri);
    NODE_SET_METHOD(exports, "x25519KeyGenPem", x25519KeyGenPem);
    //
    NODE_SET_METHOD(exports, "x25519HexSkey", x25519HexSkey);
    NODE_SET_METHOD(exports, "x25519PemSkey", x25519PemSkey);
    NODE_SET_METHOD(exports, "x25519MixSkey", x25519MixSkey);
    //
    NODE_SET_METHOD(exports, "x25519HexEnc", x25519HexEnc);
    NODE_SET_METHOD(exports, "x25519HexDec", x25519HexDec);
    NODE_SET_METHOD(exports, "x25519PemEnc", x25519PemEnc);
    NODE_SET_METHOD(exports, "x25519PemDec", x25519PemDec);
    NODE_SET_METHOD(exports, "x25519MixEnc", x25519MixEnc);
    NODE_SET_METHOD(exports, "x25519MixDec", x25519MixDec);

    //
    NODE_SET_METHOD(exports, "genSha256Hex", genSha256Hex);
    NODE_SET_METHOD(exports, "genSha256Str", genSha256Str);

    //
    NODE_SET_METHOD(exports, "aesEncPw", aesEncPw);
    NODE_SET_METHOD(exports, "aesDecPw", aesDecPw);
	NODE_SET_METHOD(exports, "aesEncFile", aesEncFile);
    NODE_SET_METHOD(exports, "aesDecFile", aesDecFile);
    NODE_SET_METHOD(exports, "aesDecBinary", aesDecBinary);

    //
    NODE_SET_METHOD(exports, "aes256CbcEnc", aes256CbcEnc);
    NODE_SET_METHOD(exports, "aes256CbcDec", aes256CbcDec);
    NODE_SET_METHOD(exports, "ariaEnc", ariaEnc);
    NODE_SET_METHOD(exports, "ariaDec", ariaDec);

    //
    NODE_SET_METHOD(exports, "eddsaTest", eddsaTest);
    NODE_SET_METHOD(exports, "x25519Test", x25519Test);
    NODE_SET_METHOD(exports, "aesTest", aesTest);
    NODE_SET_METHOD(exports, "ariaTest", ariaTest);

    //
    NODE_SET_METHOD(exports, "addonTest", addonTest);

    //
    NODE_SET_METHOD(exports, "charToUtf8", charToUtf8);
    NODE_SET_METHOD(exports, "utf8Test", utf8Test);
    NODE_SET_METHOD(exports, "keyCreateMasterChainCode", keyCreateMasterChainCode);
    NODE_SET_METHOD(exports, "keyRestoreMasterChainCode", keyRestoreMasterChainCode);
    NODE_SET_METHOD(exports, "keyCreateMasterChainCodeOri", keyCreateMasterChainCodeOri);
    NODE_SET_METHOD(exports, "keyRestoreMasterChainCodeOri", keyRestoreMasterChainCodeOri);
}

NODE_MODULE(addon, Initialize);