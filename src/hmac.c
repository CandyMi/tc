/*
**  LICENSE: BSD
**  Author: CandyMi[https://github.com/candymi]
*/
#include <tc.h>


/*  =========================== HMAC-MD5 ===========================  */

int tc_hmac_md5_init(MD5_CTX *context, const void* key, unsigned int klen) {
  char mkey[MD5_DIGEST_LENGTH];
  if (klen > MD5_BLOCK_SIZE) {
    tc_md5(key, klen, mkey);
    key = mkey;
    klen = MD5_DIGEST_LENGTH;
  }

  memset(context->ipad, 0x36, MD5_BLOCK_SIZE);
  memset(context->opad, 0x5c, MD5_BLOCK_SIZE);

  for (unsigned int i = 0; i < klen; i++) {
    context->ipad[i] ^= ((uint8_t*)key)[i];
    context->opad[i] ^= ((uint8_t*)key)[i];
  }

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
  if (text == NULL || tsize == 0)
    return NULL;

  if (!md)
    md = tc_xmalloc(SHA_DIGEST_LENGTH);

  MD5_CTX context;
  tc_hmac_md5_init(&context, key, ksize);
  tc_hmac_md5_update(&context, text, tsize);
  tc_hmac_md5_final(&context, md);

  return md;
}

/*  =========================== HMAC-SHA-128 ===========================  */

int tc_hmac_sha1_init(SHA_CTX *context, const void* key, unsigned int klen) {
  char mkey[SHA_DIGEST_LENGTH];
  if (klen > SHA_BLOCK_SIZE) {
    tc_sha1(key, klen, mkey);
    key = mkey;
    klen = SHA_DIGEST_LENGTH;
  }

  memset(context->ipad, 0x36, SHA_BLOCK_SIZE);
  memset(context->opad, 0x5c, SHA_BLOCK_SIZE);

  for (unsigned int i = 0; i < klen; i++) {
    context->ipad[i] ^= ((uint8_t*)key)[i];
    context->opad[i] ^= ((uint8_t*)key)[i];
  }

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
  if (text == NULL || tsize == 0)
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
  char mkey[SHA256_DIGEST_LENGTH];
  if (klen > SHA256_BLOCK_SIZE) {
    tc_sha256(key, klen, mkey);
    key = mkey;
    klen = SHA256_DIGEST_LENGTH;
  }

  memset(context->ipad, 0x36, SHA256_BLOCK_SIZE);
  memset(context->opad, 0x5c, SHA256_BLOCK_SIZE);

  for (unsigned int i = 0; i < klen; i++) {
    context->ipad[i] ^= ((uint8_t*)key)[i];
    context->opad[i] ^= ((uint8_t*)key)[i];
  }

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
  if (text == NULL || tsize == 0)
    return NULL;

  if (!md)
    md = tc_xmalloc(SHA256_DIGEST_LENGTH);

  SHA256_CTX context;
  tc_hmac_sha256_init(&context, key, ksize);
  tc_hmac_sha256_update(&context, text, tsize);
  tc_hmac_sha256_final(&context, md);

  return md;
}