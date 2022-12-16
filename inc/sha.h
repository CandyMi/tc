/*
** Secure Hash Algorithm **
*/
#ifndef __TC_SHA__
#define __TC_SHA__

/* SHA-128 */
#define SHA_DIGEST_LENGTH       (20)
#define SHA_BLOCK_SIZE          (64)

#define SHA1_Init(sha_ptr)                   tc_sha1_init((sha_ptr))
#define SHA1_Update(sha_ptr,text,tsize)      tc_sha1_update((sha_ptr),(text),(tsize))
#define SHA1_Final(md,sha_ptr)               tc_sha1_final((sha_ptr),(md))
#define SHA1(text,tsize,md)                  tc_sha1((text),(tsize),(md))
#define HMAC_SHA1(key,ksize,text,tsize,md)   tc_hmac_sha1((key),(ksize),(text),(tsize),(md))

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

/* SHA-256 */
#define SHA256_DIGEST_LENGTH       (32)
#define SHA256_BLOCK_SIZE          (64)

#define SHA256_Init(sha_ptr)                   tc_sha256_init((sha_ptr))
#define SHA256_Update(sha_ptr,text,tsize)      tc_sha256_update((sha_ptr),(text),(tsize))
#define SHA256_Final(md,sha_ptr)               tc_sha256_final((sha_ptr),(md))
#define SHA256(text,tsize,md)                  tc_sha256((text),(tsize),(md))
#define HMAC_SHA256(key,ksize,text,tsize,md)   tc_hmac_sha256((key),(ksize),(text),(tsize),(md))

typedef struct tc_sha256_ctx {
  unsigned int state[8];
  unsigned long long count;
  unsigned char buffer[SHA256_BLOCK_SIZE];
} SHA256_CTX;

TC_EXPORT int   tc_sha256_init(SHA256_CTX* context);
TC_EXPORT void  tc_sha256_update(SHA256_CTX* context, const void* text, unsigned int tsize);
TC_EXPORT void  tc_sha256_final(SHA256_CTX* context, unsigned char md[SHA256_DIGEST_LENGTH]);
TC_EXPORT void* tc_sha256(const void* text, unsigned int tsize, unsigned char md[SHA256_DIGEST_LENGTH]);
TC_EXPORT void* tc_hmac_sha256(const void* key, unsigned int ksize, const void* text, unsigned int tsize, unsigned char md[SHA256_DIGEST_LENGTH]);

#endif