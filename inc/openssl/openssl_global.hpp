/**
 * Description : 
 *
 * @date 2021/01/21
 * @author FINL Chain Team
 * @version 1.0
 */

#ifndef __OPENSSL_GLOBAL_HPP__
#define __OPENSSL_GLOBAL_HPP__

#ifdef __cplusplus
extern "C"
{
#endif

// OPENSSL
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/aes.h>

#include <openssl/crypto.h>
#include <openssl/opensslv.h>
#include <openssl/sha.h>

#ifdef __cplusplus
}
#endif

#include "openssl_util.hpp"
#include "openssl_aes.hpp"
#include "openssl_ec.hpp"
#include "openssl_ecdsa.hpp"
#include "openssl_ed.hpp"
#include "openssl_eddsa.hpp"
#include "openssl_x25519.hpp"

#endif	// __OPENSSL_GLOBAL_HPP__
