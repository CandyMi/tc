#ifndef __TINY_CRYPTO__
#define __TINY_CRYPTO__

#ifdef _WIN32
  #ifndef TC_EXPORT
    #define TC_EXPORT __declspec(dllexport)
  #endif
#else
  #ifndef TC_EXPORT
    #define TC_EXPORT extern
  #endif
#endif

#ifdef _WIN32
  #include <windows.h>
#endif

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#define tc_version          (0x00000001)
#define tc_version_string   ("TinyCrypto-0.0.1")

#ifdef __cplusplus
  #ifndef NULL
    #define NULL nullptr
  #endif
  extern "C" {
#endif

#ifndef tc_xmalloc 
  #define tc_xmalloc(sz) malloc((sz))
#endif

#ifndef tc_xfree 
  #define tc_xfree(ptr) free((ptr))
#endif

#include "sha.h"
#include "rc4.h"
#include "utils.h"

#ifdef __cplusplus
  }
#endif

#endif // __TINY_CRYPTO__