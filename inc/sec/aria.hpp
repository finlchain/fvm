/**
@file KISA_SHA_256.h
@brief SHA256 암호 알고리즘
@author Copyright (c) 2013 by KISA
@remarks http://seed.kisa.or.kr/
*/

#ifndef _ARIA_H_
#define _ARIA_H_

#ifdef  __cplusplus
extern "C" {
#endif

#ifndef OUT
#define OUT
#endif

#ifndef IN
#define IN
#endif

#ifndef INOUT
#define INOUT
#endif

#undef BIG_ENDIAN
#undef LITTLE_ENDIAN
	//Raspbian Little endian
#define USER_LITTLE_ENDIAN

#if defined(USER_BIG_ENDIAN)
#define BIG_ENDIAN
#elif defined(USER_LITTLE_ENDIAN)
#define LITTLE_ENDIAN
#else
#if 0
#define BIG_ENDIAN
#elif defined(_MSC_VER)
#define LITTLE_ENDIAN
#else
#error
#endif
#endif

typedef unsigned char Byte;
typedef unsigned int  Word;

#define	ARIA_BUFFER_SIZE	16

extern int DecKeySetup(const Byte* mk, Byte* rk, int keyBits);
extern int EncKeySetup(const Byte* mk, Byte* rk, int keyBits);
extern void Crypt(const Byte* i, int Nr, const Byte* rk, Byte* o);

//
extern int32_t aria_enc(uint8_t *p_mk, uint32_t mk_len, uint32_t Nr, uint8_t *p_plaintext, uint32_t plaintext_len, uint8_t *p_ciphertext, uint32_t *p_ciphertext_len);
extern int32_t aria_dec(uint8_t *p_mk, uint32_t mk_len, uint32_t Nr, uint8_t *p_ciphertext, uint32_t ciphertext_len, uint8_t *p_plaintext, uint32_t *p_plaintext_len);

extern void ARIA_test(void);
#ifdef  __cplusplus
}
#endif

#endif // _ARIA_H_