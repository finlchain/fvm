/**
 * Description : 
 *
 * @date 2021/01/21
 * @author FINL Chain Team
 * @version 1.0
 */

#include "global.hpp"
#include <unistd.h>

//
void *malloc_m(uint32_t s)
{
    void *p = malloc(s);

    if (p)
    {
        memset(p, 0x00, s);
    }

    return p;
}

void *free_m (void *p) 
{
    if (p) 
    {
        free(p);
        p = NULL;
    }

    return (NULL);
}

int strlen_m(const char *in)
{
    size_t Size = strlen(in);
    return Size;
}

//
void memcpy_m (void *p_dst, const void *p_src, uint32_t n)
{
    uint32_t i;
    uint8_t *dst = (uint8_t *)p_dst, *src = (uint8_t *)p_src;

    for (i=0; i < n; ++i)
        dst[i] = src[i];
}

void reverse_memcpy_m (void *p_dst, const void *p_src, uint32_t n)
{
    uint32_t i;
    uint8_t *dst = (uint8_t *)p_dst, *src = (uint8_t *)p_src;

    for (i=0; i < n; ++i)
        dst[n-1-i] = src[i];
}

void reverse_inplace_m (void *p_data, uint32_t n)
{
    uint32_t i;
    uint8_t *data = (uint8_t *)p_data;
    uint8_t tmp;

    for (i=0; i < n/2; ++i) {
        tmp = data[i];
        data[i] = data[n - 1 - i];
        data[n - 1 - i] = tmp;
    }
}

void xor_m(void *p_dst, const void *p_src_1, const void *p_src_2, uint32_t n)
{
    uint32_t i;
    uint8_t *dst = (uint8_t *)p_dst, *src_1 = (uint8_t *)p_src_1, *src_2 = (uint8_t *)p_src_2;

    for (i=0; i < n; i++)
        dst[i] = src_1[i] ^ src_2[i];
}

int64_t a2i_64_m(const char *s)
{
    int64_t sign = 1;
    int64_t num = 0;
    
    if(*s == '-')
    {
        sign = -1;
        s++;
    }
    
    while(*s)
    {
        num=((*s)-'0')+num*10;
        s++;   
    }
    return num*sign;
}

////////////////////////////////////////////////////////////////
//current time
uint64_t util_curtime_ms (void)
{
    // Refer : https://stackoverflow.com/questions/1952290/how-can-i-get-utctime-in-millisecond-since-january-1-1970-in-c-language
    // Check : https://currentmillis.com/
    struct timeval tv;
    uint64_t msec; // msec_since_epoch

    gettimeofday(&tv, NULL);

    msec =
        (unsigned long long)(tv.tv_sec) * 1000 +
        (unsigned long long)(tv.tv_usec) / 1000;

    DBG_PRINT(DBG_UTIL, DBG_NONE, (void *)"%llu\n", msec);

    return (msec);
}

uint64_t util_curtime_us (void)
{
    // Refer : https://stackoverflow.com/questions/1952290/how-can-i-get-utctime-in-millisecond-since-january-1-1970-in-c-language
    // Check : https://currentmillis.com/
    struct timeval tv;
    uint64_t usec; // usec_since_epoch

    gettimeofday(&tv, NULL);

    usec =
        (unsigned long long)(tv.tv_sec) * 1000000 +
        (unsigned long long)(tv.tv_usec);

    DBG_PRINT(DBG_UTIL, DBG_NONE, (void *)"%llu\n", usec);

    return (usec);
}

////////////////////////////////////////////////////////////////
//
void hex2str_temp(unsigned char *in, int inlen, char *out, int outlen)
{
    int i = 0;
    char *pos = out;
    
    // if(outlen < (2*inlen + 1)) 
    // {
    //     return (ERROR_);
    // }

    for(i = 0; i < inlen; i += 1) 
    {
        pos += sprintf(pos, "%02hhX", in[i]);
    }

    // if(outlen == pos - out + 1)
    //     return (SUCCESS_);
    // else 
    //     return (ERROR_);
}

int32_t util_str2hex(const char *in, unsigned char *out, int *outlen)
{
    int i = 0;
    int j = 0;
    int k = 0;
    int inlen = STRLEN_M(in);
    unsigned char hex[2] = {0};

    if (inlen > 2 && in[0] == '0' && in[1] == 'x')
    {
        k += 2;
    }


    if (outlen == NULL || *outlen < (inlen - k) / 2)
    {
        return (ERROR_);
    }

    for (*outlen = 0, i = (0 + k); i < inlen; *outlen += 1, i += 2)
    {
        for (j = 0; j < 2; j += 1)
        {
            if (in[i + j] >= '0' && in[i + j] <= '9')
                hex[j] = in[i + j] - '0';
            else if (in[i + j] >= 'a' && in[i + j] <= 'f')
                hex[j] = in[i + j] - 'a' + 10;
            else if (in[i + j] >= 'A' && in[i + j] <= 'F')
                hex[j] = in[i + j] - 'A' + 10;
            else
                return -1;
        }
        out[*outlen] = hex[0] << 4 | hex[1];
    }

    return (SUCCESS_);
}

int32_t util_str2hex_temp(const char *in, unsigned char *out, int outlen, bool reversed)
{
    int i = 0;
    int j = 0;
    int k = 0;
    int inlen = STRLEN_M(in);
    unsigned char hex[2] = {0};

    if (inlen >= 2 && in[0] == '0' && in[1] == 'x')
    {
        k += 2;
    }

    DBG_PRINT(DBG_UTIL, DBG_NONE, (void *)"hexR(%d) inlen(%d)\n", STRLEN_M(in), inlen);

    if((outlen < (inlen-k)/2))
    {
        DBG_PRINT(DBG_UTIL, DBG_ERROR, (void *)"outlen(%d) (inlen-k)/2(%d)\n", outlen, (inlen-k)/2);
        return (ERROR_);
    }

    for(outlen = 0, i = (0 + k); i < inlen; outlen += 1, i += 2)
    {
        for(j = 0; j < 2; j += 1)
        {
            if(in[i+j] >= '0' && in[i+j] <= '9')        hex[j] = in[i+j] - '0';
            else if(in[i+j] >= 'a' && in[i+j] <= 'f')   hex[j] = in[i+j] - 'a' + 10;
            else if(in[i+j] >= 'A' && in[i+j] <= 'F')   hex[j] = in[i+j] - 'A' + 10;
            else return -1;
        }
        out[outlen] = hex[0] << 4 | hex[1];

        DBG_PRINT(DBG_UTIL, DBG_NONE, (void *)"out[%d] = 0x%02X\n", outlen, out[outlen]);
    }

    if (reversed)
    {
        MEMCPY_REV2(out, outlen);
    }
    
    return (SUCCESS_);
}

int32_t util_hex2str(unsigned char *in, int inlen, char *out, int *outlen)
{
    int i = 0;
    char *pos = out;

    if(outlen == NULL || *outlen < (2*inlen + 1))
    {
        return (ERROR_);
    }

    for(i = 0; i < inlen; i += 1)
    {
        pos += sprintf(pos, "%02hhX", in[i]);
    }

    *outlen = pos - out + 1;

    return (SUCCESS_);
}

int32_t util_hex2str_temp(unsigned char *in, int inlen, char *out, int outlen, bool reversed)
{
    int i = 0;
    char *pos = out;

    if(outlen < (2*inlen + 1))
    {
        return (ERROR_);
    }

    if (reversed)
    {
        for(i = (inlen-1); i >= 0; i--)
        {
            pos += sprintf(pos, "%02hhX", in[i]);
        }
    }
    else
    {
        for(i = 0; i < inlen; i++)
        {
            pos += sprintf(pos, "%02hhX", in[i]);
        }
    }

    if(outlen == pos - out + 1)
       return (SUCCESS_);
    else
       return (ERROR_);
}

#define DUMP_BUF_SIZE 84
#define DUMP_STR_SIZE 20
#define DUMP_COL_NUM  16
void util_hex_dump (void *str, const uint8_t *p_buf, uint32_t len)
{
    printf("%s, dump size = %d\n", (uint8_t *)str, len);

    do
    {
        uint32_t cnt;
        char print_buf[DUMP_BUF_SIZE] ={0x00,}, str_buf[DUMP_STR_SIZE]={0x00,};

        for(cnt=0; cnt<len; cnt++)
        {
            if (cnt%DUMP_COL_NUM == 0)
            {
                if (cnt != 0)
                {
                    //strcat (print_buf, "\n");
                    printf ("%s\n", print_buf);
                    MEMSET_M(print_buf, 0x00, DUMP_BUF_SIZE);
                }

                sprintf (str_buf, "    %04d : ", cnt);
                strcat (print_buf, str_buf);
            }

            sprintf (str_buf, "%02X ", p_buf[cnt]);
            strcat (print_buf, str_buf);
        }

        printf ("%s\n", print_buf);
        fflush(stdout);
    } while(0);
}

int32_t util_hex_file_wb(char *p_path, uint8_t *p_buf, uint32_t buf_len)
{
    FILE *fp;

    fp = fopen(p_path, "wb");
    fwrite(p_buf, buf_len, 1, fp);
    fclose(fp);

    return (SUCCESS_);
}
char *util_hex_file_rb(char *p_path, uint32_t *p_buf_len)
{
    FILE *fp;
    char *p_buf;

    *p_buf_len = 0;

    if (util_exists_file(p_path) == ERROR_)
    {
        return (NULL);
    }

    fp = fopen(p_path, "rb");
    if (!fp)
    {
        return (NULL);
    }

    fseek(fp, 0, SEEK_END);
    *p_buf_len = ftell(fp);

    if (*p_buf_len == 0)
    {
        fclose(fp);

        return (NULL);
    }

    p_buf = (char *)MALLOC_M(*p_buf_len);
    MEMSET_M(p_buf, 0, *p_buf_len);

    fseek(fp, 0, SEEK_SET);
    size_t cnt = fread(p_buf, *p_buf_len, 1, fp);
    if (cnt) {}

    fclose(fp);

    return (p_buf);
}

char *util_file_r(char *p_path, uint32_t *p_buf_len)
{
    FILE *fp;
    char *p_buf;

    *p_buf_len = 0;

    if (util_exists_file(p_path) == ERROR_)
    {
        return (NULL);
    }

    fp = fopen(p_path, "r");
    if (!fp)
    {
        return (NULL);
    }

    fseek(fp, 0, SEEK_END);
    *p_buf_len = ftell(fp);

    if (*p_buf_len == 0)
    {
        fclose(fp);

        return (NULL);
    }

    p_buf = (char *)MALLOC_M(*p_buf_len);
    MEMSET_M(p_buf, 0, *p_buf_len);

    fseek(fp, 0, SEEK_SET);
    size_t cnt = fread(p_buf, *p_buf_len, 1, fp);
    if (cnt) {}

    fclose(fp);

    return (p_buf);
}

//
int gLastRN = 0;
int util_randinit(int rn)
{
    static int myRN = rn;
    uint32_t cur_seed;
    uint32_t pid =  getpid();
    uint32_t xor_a = (unsigned)time(NULL) + gLastRN + rn + myRN + pid;
    uint32_t xor_b = (getpid() << 16) + myRN;

    myRN = myRN * rn;

    xor_m(&cur_seed, &xor_a, &xor_b, sizeof(uint32_t));

    // DBG_PRINT(DBG_UTIL, DBG_INFO, (void *)"xor_a[%d], xor_b[%d], cur_seed[%d]\n", xor_a, xor_b, cur_seed);

    srand(cur_seed);

    return cur_seed;
}
/* Returns an integer in the range [0, n).
 *
 * Uses rand(), and so is affected-by/affects the same seed.
 */
int util_randint(int rn_min, int rn_max)
{
#if 1
    unsigned long state[16];
    unsigned int index = 0;
    unsigned int s = util_randinit(rn_min ^ rn_max);

    for (int i = 0; i < 16; i++)
    {
        state[i] = s;
        s += s + 100;
    }

    unsigned int a, b, c, d;

    a = state[index];
    c = state[(index + 13) & 15];
    b = a ^ c ^ (a << 16) ^ (c << 15);
    c = state[(index + 9) & 15];
    c ^= (c >> 11);
    a = state[index] = b ^ c;
    d = a ^ ((a << 5) & 0xda442d24U);
    index = (index + 15) & 15;
    a = state[index];
    state[index] = a ^ b ^ d ^ (a << 2) ^ (b << 18) ^ (c << 28);

    gLastRN = state[index];

    return (rn_min + state[index] % (rn_max + 1 - rn_min));
#else
    int rn;

    util_randinit(rn_min ^ rn_max);

    if ((rn_max - rn_min) == RAND_MAX)
    {
        rn = rand();

        gLastRN = rn;

        return rn;
    }
    else
    {
        // Supporting larger values for n would requires an even more
        // elaborate implementation that combines multiple calls to rand()
        assert ((rn_max + 1 - rn_min) <= RAND_MAX);

        // Chop off all of the values that would cause skew...
        int end = RAND_MAX / (rn_max + 1 - rn_min); // truncate skew
        assert (end > 0);
        end *= (rn_max + 1 - rn_min);

        // ... and ignore results from rand() that fall above that limit.
        // (Worst case the loop condition should succeed 50% of the time,
        // so we can expect to bail out of this loop pretty quickly.)
        while ((rn = rand()) >= end) ;

        gLastRN = rn;

        return (rn_min + rn % (rn_max + 1 - rn_min));
    }
#endif
}

int32_t util_exists_file(const char *fname)
{
    if( access( fname, F_OK ) != -1 ) {
        // file exists
        return (SUCCESS_);
    }

    return (ERROR_);
}

int32_t util_remove_file(const char *fname)
{
    int32_t ret = SUCCESS_;
    
    remove(fname);

    return (ret);

}

//
char *util_setlocale(char *p_new_locale)
{
    char *p_old_locale, *p_saved_locale;
    char *p_locale;

    /* Get the name of the current locale.  */
    p_old_locale = setlocale (LC_ALL, NULL);

    /* Copy the name so it won’t be clobbered by setlocale. */
    p_saved_locale = strdup (p_old_locale);
    // if (p_saved_locale == NULL) return NULL;

    /* Now change the locale and do some stuff with it. */
    p_locale = setlocale (LC_ALL, p_new_locale);
    DBG_PRINT(DBG_UTIL, DBG_NONE, (void *)"%s set to %s\n", __FUNCTION__, p_locale);

    return p_saved_locale;
}

void util_restorelocale(char *p_saved_locale)
{
    if (p_saved_locale)
    {
        /* Restore the original locale. */
        setlocale (LC_ALL, p_saved_locale);
        free (p_saved_locale);
    }
}

//
int util_wcs_required_size(char *p_new_locale, char *p_mbs)
{
    //
    char *p_saved_locale;
    p_saved_locale = util_setlocale(p_new_locale);
    
    int required_size;
    required_size = mbstowcs(NULL, (char *)p_mbs, 0); // C4996

    // 
    util_restorelocale(p_saved_locale);

    return (required_size);
}

//
uint8_t *util_wcstombs(char *p_new_locale, wchar_t *p_wcs, int32_t *p_mbs_size)
{
    uint8_t *p_mbs = NULL;

    *p_mbs_size = 0;

    if (!p_wcs)
    {
        return NULL;
    }

    // 
    char *p_saved_locale;
    p_saved_locale = util_setlocale(p_new_locale);

    do
    {
        //
        // wchar_t *p_wcs = (wchar_t *)L"\x3042\x3043";
        // wchar_t *p_wcs = (wchar_t *)L("한국");
        int32_t required_size;
        size_t mbs_size;

        required_size = wcstombs( NULL, p_wcs, 0); // C4996
        // Note: wcstombs is deprecated; consider using wcstombs_s
        DBG_PRINT(DBG_UTIL, DBG_INFO, (void *)"required_size : %d\n", required_size);
        if (required_size == (-1))
        {
            break;
        }

        /* Add one to leave room for the null terminator. */
        p_mbs = (uint8_t *)MALLOC_M(required_size + 1);
        if (!p_mbs)
        {
            break;
        }

        do
        {
            mbs_size = wcstombs( (char *)p_mbs, p_wcs, required_size + 1); // C4996
            // Note: wcstombs is deprecated; consider using wcstombs_s
            DBG_PRINT(DBG_UTIL, DBG_INFO, (void *)"mbs size : %d\n", (int)mbs_size);
            if (mbs_size == (size_t)(-1))
            {
                FREE_M(p_mbs);
                break;
            }

            DBG_DUMP(DBG_UTIL, DBG_INFO, (void *) "p_mbs", (uint8_t *)p_mbs, mbs_size);

            *p_mbs_size = (int32_t)mbs_size;
        } while (0);

        // FREE_M(p_mbs);
    } while (0);

    // 
    util_restorelocale(p_saved_locale);

    return (p_mbs);
}

//
uint8_t *util_cstombs(char *p_new_locale, char *p_str, int32_t *p_mbs_size)
{
    uint8_t *p_mbs = NULL;
    *p_mbs_size = 0;

    int32_t wcs_size = ((STRLEN_M(p_str) / 4) * 4 + 4) * sizeof(wchar_t);
    wchar_t *p_wcs = (wchar_t *)MALLOC_M(wcs_size);

    DBG_PRINT(DBG_UTIL, DBG_INFO, (void *)"wcs_size %d, p_str : %s\n", wcs_size, p_str);
    if (p_wcs)
    {
        int32_t num;

        //
        char *p_saved_locale;
        p_saved_locale = util_setlocale(p_new_locale);

        // num = swprintf(p_wcs, wcs_size, L"%hs", (wchar_t *)p_str);
        num = swprintf(p_wcs, wcs_size, L"%hs", p_str);
        if (num != -1)
        {
            p_mbs = util_wcstombs(p_new_locale, p_wcs, p_mbs_size);
        }

        // 
        util_restorelocale(p_saved_locale);

        //
        FREE_M(p_wcs);

    }
 
    return (p_mbs);
}

wchar_t *util_mbstowcs(char *p_new_locale, char *p_mbs)
{
    if (!p_mbs)
    {
        return NULL;
    }

    //
    wchar_t *p_wcs = NULL;

    // 
    char *p_saved_locale;
    p_saved_locale = util_setlocale(p_new_locale);

    do
    {
        //
        int required_size;
        size_t wcs_size;

        required_size = mbstowcs(NULL, (char *)p_mbs, 0); // C4996
        /* Add one to leave room for the null terminator */
        p_wcs = (wchar_t *)MALLOC_M( (required_size + 1) * sizeof( wchar_t ));
        if (!p_wcs)
        {
            break;
        }

        wcs_size = mbstowcs(p_wcs, (char *)p_mbs, required_size + 1); // C4996
        DBG_PRINT(DBG_UTIL, DBG_INFO, (void *)"wcs size : %d\n", (int)wcs_size);
        if (wcs_size == (size_t) (-1))
        {
            printf("Couldn't convert string--invalid multibyte character.\n");
            FREE_M(p_wcs);
            break;
        }

        printf( " wide characters: %#.4x %#.4x\n\n", p_wcs[0], p_wcs[1] );
        DBG_DUMP(DBG_UTIL, DBG_INFO, (void *) "p_wcs", (uint8_t *)p_wcs, wcs_size);

        // FREE_M(p_wcs);
    } while (0);

    // 
    util_restorelocale(p_saved_locale);

    return (p_wcs);
}


//
std::string ByteToHexString(void *const data, const size_t dataLength)
{
    uint8_t *byteData = reinterpret_cast<unsigned char *>(data);
    std::stringstream hexStringStream;

    hexStringStream << std::hex << std::setfill('0');
    for (size_t index = 0; index < dataLength; ++index)
    {
        hexStringStream << std::setw(2) << static_cast<int>(byteData[index]);
    }
    return (hexStringStream.str());
}

int32_t chkUndefinedStr(std::string chkStr)
{
    std::string undefStr = "undefined";

    return (chkStr.compare(undefStr));
}

//
int32_t init_string(STRING_T *p_str)
{
    p_str->len = 0;
    p_str->p_ptr = (char *)MALLOC_M(p_str->len+1);
    if (p_str->p_ptr == NULL) {
        fprintf(stderr, "MALLOC_M() failed\n");
        return (ERROR_);
    }
    p_str->p_ptr[0] = '\0';

    return (SUCCESS_);
}

//
void free_string(STRING_T *p_str)
{
    p_str->len = 0;

    if (p_str->p_ptr)
    {
        FREE_M(p_str->p_ptr);
    }
}
