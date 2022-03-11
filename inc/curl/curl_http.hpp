/**
 * Description : 
 *
 * @date 2021/01/21
 * @author FINL Chain Team
 * @version 1.0
 */

#ifndef __CURL_HTTP_HPP__
#define __CURL_HTTP_HPP__

#ifdef __cplusplus
extern "C"
{
#endif

extern int32_t curl_http_post (char *p_url, char *p_fields, STRING_T *p_ret_str);
extern int32_t curl_http_get (char *p_url, char *p_fields, STRING_T *p_ret_str);

#ifdef __cplusplus
}
#endif

#endif /* __CURL_HTTP_HPP__ */
