/*
** SHA-MD5 **
*/
#ifndef __TC_MD5__
#define __TC_MD5__

#define MD5_DIGEST_LENGTH (16)
#define MD5_BLOCK_SIZE    (64)

#define MD5_Init(md5_ptr)                    tc_md5_init((md5_ptr))
#define MD5_Update(md5_ptr,text,tsize)       tc_md5_update((md5_ptr),(text),(tsize))
#define MD5_Final(md,md5_ptr)                tc_md5_final((md5_ptr),(md))
#define MD5(text,tsize,md)                   tc_md5((text),(tsize),(md))
#define HMAC_MD5(key,ksize, text,tsize,md)   tc_hmac_md5((key),(ksize),(text),(tsize),(md))

typedef struct tc_md5_ctx {
  unsigned int count[2];
  unsigned int state[4];
  unsigned char buffer[MD5_BLOCK_SIZE];
} MD5_CTX;

TC_EXPORT int   tc_md5_init(MD5_CTX *);
TC_EXPORT void  tc_md5_update(MD5_CTX *context, const void* text, unsigned int tsize);
TC_EXPORT int   tc_md5_final(MD5_CTX *context, unsigned char md[MD5_DIGEST_LENGTH]);
TC_EXPORT void* tc_md5(const void* text, unsigned int tsize, unsigned char md[MD5_DIGEST_LENGTH]);
TC_EXPORT void* tc_hmac_md5(const void* key, unsigned int ksize, const void* text, unsigned int tsize, unsigned char md[MD5_DIGEST_LENGTH]);

#endif