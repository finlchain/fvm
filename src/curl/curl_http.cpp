/**
 * Description : 
 *
 * @date 2021/01/21
 * @author FINL Chain Team
 * @version 1.0
 */

#include "global.hpp"

size_t writefunc(void *p_ptr, size_t size, size_t nmemb, STRING_T *p_str)
{
    size_t new_len = p_str->len + size*nmemb;
    p_str->p_ptr = (char *)realloc(p_str->p_ptr, new_len + 1);
    if (p_str->p_ptr == NULL) {
        fprintf(stderr, "realloc() failed\n");
        exit(EXIT_FAILURE);
    }
    memcpy(p_str->p_ptr + p_str->len, p_ptr, size * nmemb);
    p_str->p_ptr[new_len] = '\0';
    p_str->len = new_len;

    return size*nmemb;
}

//
int32_t curl_http_post (char *p_url, char *p_fields, STRING_T *p_ret_str)
{
    CURL *curl;
    CURLcode res;

    /* In windows, this will init the winsock stuff */
    curl_global_init(CURL_GLOBAL_ALL);

    /* get a curl handle */
    curl = curl_easy_init();
    if(curl)
    {
        /* First set the URL that is about to receive our POST. This URL can
        just as well be a https:// URL if that is what should receive the
        data. */
        // curl_easy_setopt(curl, CURLOPT_URL, "http://postit.example.com/moo.cgi");
        curl_easy_setopt(curl, CURLOPT_URL, p_url);
        /* Now specify the POST data */
        curl_easy_setopt(curl, CURLOPT_POST, 1);
        // curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "name=daniel&project=curl");
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, p_fields);

        //
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L); //only for https
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L); //only for https, default = 2

        //
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, p_ret_str);

        /* Perform the request, res will get the return code */
        res = curl_easy_perform(curl);
        /* Check for errors */
        if(res != CURLE_OK)
        {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        }

        /* always cleanup */
        curl_easy_cleanup(curl);
    }

    curl_global_cleanup();

    return (SUCCESS_);   
}

//
int32_t curl_http_get (char *p_url, char *p_fields, STRING_T *p_ret_str)
{
    CURL *curl;
    CURLcode res;

    curl = curl_easy_init();
    if(curl)
    {
        //
        // curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");
        curl_easy_setopt(curl, CURLOPT_URL, p_url);

        /* example.com is redirected, so we tell libcurl to follow redirection */
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

        //
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L); //only for https
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L); //only for https, default = 2

        //
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, p_ret_str);

        /* Perform the request, res will get the return code */
        res = curl_easy_perform(curl);
        /* Check for errors */
        if(res != CURLE_OK)
        {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        }
        // else
        // {
        //     printf("%s\n", p_ret_str->p_ptr);
        // }

        /* always cleanup */
        curl_easy_cleanup(curl);
    }

    return (SUCCESS_);  
}
