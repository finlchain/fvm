/**
 * Description : 
 *
 * @date 2021/01/21
 * @author FINL Chain Team
 * @version 1.0
 */

#ifndef __UTIL_HPP__
#define __UTIL_HPP__

#ifdef __cplusplus
extern "C"
{
#endif

#define MEMCPY_M memcpy_m
#define MEMCPY_REV reverse_memcpy_m
#define MEMCPY_REV2 reverse_inplace_m
#define STRCMP_M strcmp
#define STRLEN_M strlen_m
#define STRSTR_M strstr
#define STRCPY_M strcpy
#define MEMSET_M memset
#define MEMCMP_M memcmp
#define MALLOC_M malloc_m
#define FREE_M free_m

#define ASSERT_M assert

//
typedef struct {
    char *p_ptr;
    size_t len;
} STRING_T;

//
extern void *malloc_m(uint32_t s);
extern void *free_m(void *p);

extern int strlen_m(const char *in);

//
extern void memcpy_m (void *p_dst, const void *p_src, uint32_t n);
extern void reverse_memcpy_m (void *p_dst, const void *p_src, uint32_t n);
extern void reverse_inplace_m (void *p_data, uint32_t n);

//
extern void xor_m(void *p_dst, const void *p_src_1, const void *p_src_2, uint32_t n);
extern int64_t a2i_64_m(const char *s);

//
extern uint64_t util_curtime_ms (void);
extern uint64_t util_curtime_us (void);

//
extern void hex2str_temp(unsigned char *in, int inlen, char *out, int outlen);

extern int32_t util_str2hex(const char *in, unsigned char *out, int *outlen);
extern int32_t util_str2hex_temp(const char *in, unsigned char *out, int outlen, bool reversed);
extern int32_t util_hex2str(unsigned char *in, int inlen, char *out, int *outlen);
extern int32_t util_hex2str_temp(unsigned char *in, int inlen, char *out, int outlen, bool reversed);
extern void util_hex_dump (void *str, const uint8_t *p_buf, uint32_t len);

extern int32_t util_hex_file_wb(char *p_path, uint8_t *p_buf, uint32_t buf_len);
extern char *util_hex_file_rb(char *p_path, uint32_t *p_buf_len);
extern char *util_file_r(char *p_path, uint32_t *p_buf_len);
extern int32_t util_exists_file(const char *fname);
extern int32_t util_remove_file(const char *fname);

//
extern int util_randinit(int rn);
extern int util_randint(int rn_min, int rn_max);

//
extern char *util_setlocale(char *p_new_locale);
extern void util_restorelocale(char *p_saved_locale);
extern int util_wcs_required_size(char *p_new_locale, char *p_mbs);
extern uint8_t *util_wcstombs(char *p_new_locale, wchar_t *p_wcs, int32_t *p_mbs_size);
extern uint8_t *util_cstombs(char *p_new_locale, char *p_str, int32_t *p_mbs_size);
extern wchar_t *util_mbstowcs(char *p_new_locale, char *p_mbs);

//
extern int32_t init_string(STRING_T *p_str);
extern void free_string(STRING_T *p_str);

#ifdef __cplusplus
}
#endif

//
extern std::string ByteToHexString(void *const data, const size_t dataLength);
extern int32_t chkUndefinedStr(std::string chkStr);

#endif	// __UTIL_HPP__
