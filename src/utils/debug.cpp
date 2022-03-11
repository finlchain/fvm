/**
 * Description : 
 *
 * @date 2021/01/21
 * @author FINL Chain Team
 * @version 1.0
 */

#include "global.hpp"

//
#define COLOR_CLEAR "\x1b[0m"
#define COLOR_ERROR "\x1b[31m"  /* Red */
#define COLOR_WARN  "\x1b[32m"  /* Green */
#define COLOR_TRACE "\x1b[34m"  /* Blue */
#define COLOR_INFO  "\x1b[35m"  /* Magenta */
#define COLOR_NONE  "\x1b[36m"  /* Cyan */
#define COLOR_RESET "\x1b[0m"   /* All attributes off(color at startup) */

//
#define DBG_BUF_SIZE      4096
#define DBG_COLOR_SIZE    10

//
#define DUMP_BUF_SIZE 84
#define DUMP_STR_SIZE 20
#define DUMP_COL_NUM  16

//
static uint32_t debug_module = 0;

//
static DBG_LEVEL_E debug_level = DBG_WARN;

//
static char debug_str_buf[DBG_BUF_SIZE];
// static char debug_fd_str_buf[DBG_BUF_SIZE];
static char debug_color[DBG_END][DBG_COLOR_SIZE] 
                    = { COLOR_RESET, COLOR_ERROR, COLOR_WARN, COLOR_TRACE, COLOR_INFO, COLOR_NONE };

//
static const char dbg_lvl_char[DBG_END]  = {'C', 'E', 'W', 'T', 'I', 'N'};

//
static bool dbg_time_display = false;

pthread_mutex_t dbg_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t dump_mutex = PTHREAD_MUTEX_INITIALIZER;

//
void debug_init(bool b_time_display)
{
    dbg_time_display = b_time_display;
}

int32_t debug_get_module(void)
{
    return (debug_module);
}

int32_t debug_get_level(void)
{
    return (debug_level);
}

void debug_printf (uint32_t module, DBG_LEVEL_E level, void *fmt, ...)
{
    if (debug_level >= level)
    {
        pthread_mutex_lock (&dbg_mutex);
        
        do
        {
            struct timeval curTime;
            char *p_buf;
            uint32_t len;

            len = 0;
            p_buf = debug_str_buf;
            MEMSET_M (p_buf, 0x00, DBG_BUF_SIZE);

            if (dbg_time_display)
            {
                gettimeofday (&curTime, NULL);
                
                sprintf (&p_buf[len], (char *)"[%ld:%06ld] ", curTime.tv_sec, curTime.tv_usec);
                len += STRLEN_M (p_buf);
            }
            p_buf[len++] = '[';
            p_buf[len++] = 'A';
            p_buf[len++] = ']';
            
            sprintf (&p_buf[len], "%s", debug_color[level]);
            len += STRLEN_M (debug_color[level]);
            
            p_buf[len++] = '[';
            p_buf[len++] = dbg_lvl_char[level];
            p_buf[len++] = ']';
            p_buf[len++] = ' ';

            sprintf (&p_buf[len], "%s", debug_color[DBG_CLEAR]);
            len += STRLEN_M (debug_color[DBG_CLEAR]);

            do
            {
                va_list ap;
                
                va_start (ap, fmt);
                vsprintf (&p_buf[len], (char *)fmt, ap);
                va_end (ap);
                
            } while(0);

            printf ("%s", p_buf);
            //fprintf(stdout, "%s", p_buf);
            fflush(stdout);
        } while(0);

        pthread_mutex_unlock (&dbg_mutex);
    }
}

void debug_dump (uint32_t module, DBG_LEVEL_E level, void *str, const uint8_t *p_buf, uint32_t len)
{
    if (debug_level >= level)
    {
        DBG_PRINT (module, level, (void *)"%s, dump size = %d\n", (uint8_t *)str, len);
        
        pthread_mutex_lock(&dump_mutex);

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
        
        pthread_mutex_unlock(&dump_mutex);
    } 
}

#if (DBG_CHK_DELAY_TIME == ENABLED)
void debug_delay_time(uint8_t *str, struct timespec *pt_start, struct timespec *pt_end, DBG_LEVEL_E level)
{
    DBG_PRINT(DBG_UTIL, level, (void *)"INFO: (%s) Diff time: %.5f sec \n", str, ((double)pt_end->tv_sec+1.0e-9*pt_end->tv_nsec)-((double)pt_start->tv_sec+1.0e-9*pt_start->tv_nsec));
}
#endif // DBG_CHK_DELAY_TIME
