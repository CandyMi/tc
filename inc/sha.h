/*
** Secure Hash Algorithm **
*/
#ifndef __TC_SHA__
#define __TC_SHA__

/* MD5 */
#define MD5_DIGEST_LENGTH (16)
#define MD5_BLOCK_SIZE    (64)

#define MD5_Init(md5_ptr)                    tc_md5_init((md5_ptr))
#define MD5_Update(md5_ptr,text,tsize)       tc_md5_update((md5_ptr),(text),(tsize))
#define MD5_Final(md,md5_ptr)                tc_md5_final((md5_ptr),(md))
#define MD5(text,tsize,md)                   tc_md5((text),(tsize),(md))
#define HMAC_MD5(key,ksize,text,tsize,md)    tc_hmac_md5((key),(ksize),(text),(tsize),(md))

typedef struct tc_md5_ctx {
  unsigned int count[2];
  unsigned int state[4];
  unsigned char buffer[MD5_BLOCK_SIZE];
} MD5_CTX;

TC_EXPORT int   tc_md5_init(MD5_CTX *context);
TC_EXPORT void  tc_md5_update(MD5_CTX *context, const void* text, unsigned int tsize);
TC_EXPORT int   tc_md5_final(MD5_CTX *context, unsigned char md[MD5_DIGEST_LENGTH]);
TC_EXPORT void* tc_md5(const void* text, unsigned int tsize, unsigned char md[MD5_DIGEST_LENGTH]);
TC_EXPORT void* tc_hmac_md5(const void* key, unsigned int ksize, const void* text, unsigned int tsize, unsigned char md[MD5_DIGEST_LENGTH]);

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

/* PBKDF2 */
typedef enum tc_sign_t{
  TC_MD5 = 0,
  TC_SHA128,
  TC_SHA256,
} tc_sign_t;

TC_EXPORT int tc_pbkdf2(tc_sign_t mode, const void* password, unsigned int plen, const void* salt, unsigned int slen, unsigned int count, char* out);

#endif