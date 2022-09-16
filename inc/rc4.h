/*
** RC4 **
*/
#ifndef __TC_RC4__
#define __TC_RC4__

#define RC4_set_key(key, len, data)             tc_rc4_set_key((key), (len), (data))
#define RC4(key, len, indata, outdata)          tc_rc4((key), (indata), (len), (outdata))
#define RC4_encrypt(key, len, indata, outdata)  RC4(key, len, indata, outdata)
#define RC4_decrypt(key, len, indata, outdata)  RC4(key, len, indata, outdata)

typedef struct tc_rc4_ctx {
  unsigned int x, y;
  unsigned int data[256];
} RC4_KEY;

TC_EXPORT int tc_rc4_set_key(RC4_KEY *key, const void *text, unsigned int tsize);
TC_EXPORT void* tc_rc4(RC4_KEY *key, const void *text, unsigned int tsize, unsigned char *md);

#endif