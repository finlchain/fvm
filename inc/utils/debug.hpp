/**
 * Description : 
 *
 * @date 2021/01/21
 * @author FINL Chain Team
 * @version 1.0
 */

#ifndef __DEBUG_HPP__
#define __DEBUG_HPP__

#ifdef __cplusplus
extern "C"
{
#endif

//
#define DBG_CHK_DELAY_TIME ENABLED // ENABLED DISABLED

//
/* Definition of debug modules */
#define DBG_UTIL        (1 << 0)

//
#define DBG_INIT  debug_init
#define DBG_PRINT debug_printf
#define DBG_DUMP  debug_dump

//
typedef enum {
    DBG_CLEAR = 0,
    DBG_ERROR,
    DBG_WARN,
    DBG_TRACE,
    DBG_INFO,
    DBG_NONE,
    DBG_END
} DBG_LEVEL_E;

//
extern void debug_init(bool b_time_display);
extern int32_t debug_get_module(void);
extern int32_t debug_get_level(void);
extern void debug_printf (uint32_t module, DBG_LEVEL_E level, void *fmt, ...);
extern void debug_dump (uint32_t module, DBG_LEVEL_E level, void *str, const uint8_t *p_buf, uint32_t len);

//
#if (DBG_CHK_DELAY_TIME == ENABLED)
extern void debug_delay_time(uint8_t *str, struct timespec *pt_start, struct timespec *pt_end, DBG_LEVEL_E level);
#endif // DBG_CHK_DELAY_TIME

#ifdef __cplusplus
}
#endif

#endif /* __DEBUG_HPP__ */
