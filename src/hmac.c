/*
**  LICENSE: BSD
**  Author: CandyMi[https://github.com/candymi]
*/
#include <tc.h>

#define hmac_init(ctx, process, key, klen, size, block) \
  unsigned char mkey[size];                             \
  if (klen > block) {                                   \
    process(key, klen, mkey);                           \
    key = mkey; klen = size;                            \
  }                                                     \
  memset(ctx->ipad, 0x36, block);                       \
  memset(ctx->opad, 0x5c, block);                       \
  unsigned int i;                                       \
  for (i = 0; i < klen; i++) {                          \
    ctx->ipad[i] ^= ((uint8_t*)key)[i];                 \
    ctx->opad[i] ^= ((uint8_t*)key)[i];                 \
  }

/*  =========================== HMAC-MD5 ===========================  */

int tc_hmac_md5_init(MD5_CTX *context, const void* key, unsigned int klen) {

  hmac_init(context, tc_md5, key, klen, MD5_DIGEST_LENGTH, MD5_BLOCK_SIZE);

  tc_md5_init(context);
  tc_md5_update(context, context->ipad, MD5_BLOCK_SIZE);

  return 1;
}

void tc_hmac_md5_update(MD5_CTX *context, const void* text, unsigned int tsize) {
  tc_md5_update(context, text, tsize);
}

void tc_hmac_md5_final(MD5_CTX *context, unsigned char md[MD5_DIGEST_LENGTH]) {
  tc_md5_final(context, md);

  tc_md5_init(context);

  tc_md5_update(context, context->opad, MD5_BLOCK_SIZE);
  tc_md5_update(context, md, MD5_DIGEST_LENGTH);

  tc_md5_final(context, md);
}

void* tc_hmac_md5(const void* key, unsigned int ksize, const void* text, unsigned int tsize, unsigned char md[MD5_DIGEST_LENGTH]) {
  if (ksize == 0 || tsize == 0)
    return NULL;

  if (!md)
    md = tc_xmalloc(MD5_DIGEST_LENGTH);

  MD5_CTX context;
  tc_hmac_md5_init(&context, key, ksize);
  tc_hmac_md5_update(&context, text, tsize);
  tc_hmac_md5_final(&context, md);

  return md;
}

/*  =========================== HMAC-SHA-128 ===========================  */

int tc_hmac_sha1_init(SHA_CTX *context, const void* key, unsigned int klen) {

  hmac_init(context, tc_sha1, key, klen, SHA_DIGEST_LENGTH, SHA_BLOCK_SIZE);

  tc_sha1_init(context);
  tc_sha1_update(context, context->ipad, SHA_BLOCK_SIZE);

  return 1;
}

void tc_hmac_sha1_update(SHA_CTX *context, const void* text, unsigned int tsize) {
  tc_sha1_update(context, text, tsize);
}

void tc_hmac_sha1_final(SHA_CTX *context, unsigned char md[SHA_DIGEST_LENGTH]) {
  tc_sha1_final(context, md);

  tc_sha1_init(context);

  tc_sha1_update(context, context->opad, SHA_BLOCK_SIZE);
  tc_sha1_update(context, md, SHA_DIGEST_LENGTH);

  tc_sha1_final(context, md);
}

void* tc_hmac_sha1(const void* key, unsigned int ksize, const void* text, unsigned int tsize, unsigned char md[SHA_DIGEST_LENGTH]) {
  if (ksize == 0 || tsize == 0)
    return NULL;

  if (!md)
    md = tc_xmalloc(SHA_DIGEST_LENGTH);

  SHA_CTX context;
  tc_hmac_sha1_init(&context, key, ksize);
  tc_hmac_sha1_update(&context, text, tsize);
  tc_hmac_sha1_final(&context, md);

  return md;
}

/*  =========================== HMAC-SHA-256 =========================== */

int tc_hmac_sha256_init(SHA256_CTX *context, const void* key, unsigned int klen) {

  hmac_init(context, tc_sha256, key, klen, SHA256_DIGEST_LENGTH, SHA256_BLOCK_SIZE);

  tc_sha256_init(context);
  tc_sha256_update(context, context->ipad, SHA256_BLOCK_SIZE);

  return 1;
}

void tc_hmac_sha256_update(SHA256_CTX *context, const void* text, unsigned int tsize) {
  tc_sha256_update(context, text, tsize);
}

void tc_hmac_sha256_final(SHA256_CTX *context, unsigned char md[SHA256_DIGEST_LENGTH]) {
  tc_sha256_final(context, md);

  tc_sha256_init(context);

  tc_sha256_update(context, context->opad, SHA256_BLOCK_SIZE);
  tc_sha256_update(context, md, SHA256_DIGEST_LENGTH);

  tc_sha256_final(context, md);
}

void* tc_hmac_sha256(const void* key, unsigned int ksize, const void* text, unsigned int tsize, unsigned char md[SHA256_DIGEST_LENGTH]) {
  if (ksize == 0 || tsize == 0)
    return NULL;

  if (!md)
    md = tc_xmalloc(SHA256_DIGEST_LENGTH);

  SHA256_CTX context;
  tc_hmac_sha256_init(&context, key, ksize);
  tc_hmac_sha256_update(&context, text, tsize);
  tc_hmac_sha256_final(&context, md);

  return md;
}
