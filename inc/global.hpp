/**
 * Description : 
 *
 * @date 2021/01/21
 * @author FINL Chain Team
 * @version 1.0
 */

//Compilation flags used to enable/disable features
#define ENABLED  1
#define DISABLED 0

#define SUCCESS_ 0
#define ERROR_ -1

#ifdef __GNUC__
// #define PACK( __Declaration__ ) __Declaration__ __attribute__((__packed__))
#define __PACK__ __attribute__((__packed__))
#endif

#ifdef _MSC_VER
// #define PACK( __Declaration__ ) __pragma( pack(push, 1) ) __Declaration__ __pragma( pack(pop))
#define __PACK__ 
#endif

#include <assert.h>
#include <cstring>
#include <string>
#include <cstdlib>
#include <stdint.h>

// #include <time.h>
// #include <stdlib.h>

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <locale.h>

#if (defined (__GNUC__))
#include <sys/time.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>
#if (defined (__MINGW32__) || defined (__MINGW64__))
#
#include <winsock2.h> // Only for libcurl windows
#endif
#endif

#if (defined (_WIN32) || defined (_WIN64))
#include <Windows.h>
#endif

#include "utf8proc.h"

// C++
#include <sstream>
#include <iostream>
#include <iomanip>
#include <fstream>
// #include <cmath>
// #include <math.h>

#include "debug.hpp"
#include "util.hpp"

#include "aes.hpp"
#include "aria.hpp"
#include "sec_proc.hpp"

#include "curl_global.hpp"

#include "openssl_global.hpp"

#include "key.hpp"

#include "lua_global.hpp"
