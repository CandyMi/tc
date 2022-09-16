/*
** Secure Hash Algorithm **
*/
#ifndef __TC_SHA__
#define __TC_SHA__

/* SHA128 */
#define SHA_DIGEST_LENGTH       (20)
#define SHA_BLOCK_SIZE          (64)

#define SHA1_Init(sha_ptr)                   tc_sha1_init((sha_ptr))
#define SHA1_Update(sha_ptr,text,tsize)      tc_sha1_update((sha_ptr),(text),(tsize))
#define SHA1_Final(md,sha_ptr)               tc_sha1_final((sha_ptr),(md))
#define SHA1(text,tsize,md)                  tc_sha1((text),(tsize),(md))
#define HMAC_SHA1(key,ksize, text,tsize,md)  tc_hmac_sha1((key),(ksize),(text),(tsize),(md))

typedef struct tc_sha1_ctx {
  unsigned int count[2];
  unsigned int state[5];
  unsigned char buffer[SHA_BLOCK_SIZE];
} SHA_CTX;

TC_EXPORT int   tc_sha1_init(SHA_CTX* context);
TC_EXPORT void  tc_sha1_update(SHA_CTX* context, const void* text, unsigned int tsize);
TC_EXPORT void  tc_sha1_final(SHA_CTX* context, unsigned char md[SHA_DIGEST_LENGTH]);
TC_EXPORT void* tc_sha1(const void* text, unsigned int tsize, unsigned char md[SHA_DIGEST_LENGTH]);
TC_EXPORT void* tc_hmac_sha1(const void* key, unsigned int ksize, const void* text, unsigned int tsize, unsigned char md[SHA_DIGEST_LENGTH]);

#endif