/*
**  LICENSE: BSD
**  Author: CandyMi[https://github.com/candymi]
*/
#include <tc.h>

#define pbkdf2_check_error(p, plen, s, slen, c) \
  if (!(p) || (plen) == 0)                      \
    return -2;                                  \
  if (!(s) || (slen) == 0)                      \
    return -3;                                  \
  if ((c) == 0)                                 \
    return -4

static inline int tc_pbkdf2_md5(const void* password, unsigned int plen, const void* salt, unsigned int slen, unsigned int count, unsigned char out[MD5_DIGEST_LENGTH]) {
  pbkdf2_check_error(password, plen, salt, slen, count);
  
  MD5_CTX context;
  tc_md5_init(&context);

  tc_hmac_md5_init(&context, password, plen);
  tc_hmac_md5_update(&context, salt, slen);
  tc_hmac_md5_update(&context, "\x00\x00\x00\x01", 4);
  tc_hmac_md5_final(&context, out);

  if (count > 1) {
    char tmp[MD5_DIGEST_LENGTH];
    memcpy(tmp, out, MD5_DIGEST_LENGTH);
    for (unsigned int i = 1; i < count; i++) {

      tc_hmac_md5_init(&context, password, plen);
      tc_hmac_md5_update(&context, out, MD5_DIGEST_LENGTH);
      tc_hmac_md5_final(&context, out);

      for (unsigned int j = 0; j < MD5_DIGEST_LENGTH; j++)
        tmp[j] ^= out[j];
    }
    memcpy(out, tmp, MD5_DIGEST_LENGTH);
  }
  return MD5_DIGEST_LENGTH;
}

static inline int tc_pbkdf2_sha128(const void* password, unsigned int plen, const void* salt, unsigned int slen, unsigned int count, unsigned char out[SHA_DIGEST_LENGTH]) {
  pbkdf2_check_error(password, plen, salt, slen, count);

  SHA_CTX context;
  tc_sha1_init(&context);

  tc_hmac_sha1_init(&context, password, plen);
  tc_hmac_sha1_update(&context, salt, slen);
  tc_hmac_sha1_update(&context, "\x00\x00\x00\x01", 4);
  tc_hmac_sha1_final(&context, out);

  if (count > 1) {
    char tmp[SHA_DIGEST_LENGTH];
    memcpy(tmp, out, SHA_DIGEST_LENGTH);
    for (unsigned int i = 1; i < count; i++) {

      tc_hmac_sha1_init(&context, password, plen);
      tc_hmac_sha1_update(&context, out, SHA_DIGEST_LENGTH);
      tc_hmac_sha1_final(&context, out);

      for (unsigned int j = 0; j < SHA_DIGEST_LENGTH; j++)
        tmp[j] ^= out[j];
    }
    memcpy(out, tmp, SHA_DIGEST_LENGTH);
  }
  return SHA_DIGEST_LENGTH;
}

static inline int tc_pbkdf2_sha256(const void* password, unsigned int plen, const void* salt, unsigned int slen, unsigned int count, unsigned char out[SHA256_DIGEST_LENGTH]) {
  pbkdf2_check_error(password, plen, salt, slen, count);

  SHA256_CTX context;
  tc_sha256_init(&context);

  tc_hmac_sha256_init(&context, password, plen);
  tc_hmac_sha256_update(&context, salt, slen);
  tc_hmac_sha256_update(&context, "\x00\x00\x00\x01", 4);
  tc_hmac_sha256_final(&context, out);

  if (count > 1) {
    char tmp[SHA256_DIGEST_LENGTH];
    memcpy(tmp, out, SHA256_DIGEST_LENGTH);
    for (unsigned int i = 1; i < count; i++) {

      tc_hmac_sha256_init(&context, password, plen);
      tc_hmac_sha256_update(&context, out, SHA256_DIGEST_LENGTH);
      tc_hmac_sha256_final(&context, out);

      for (unsigned int j = 0; j < SHA256_DIGEST_LENGTH; j++)
        tmp[j] ^= out[j];
    }
    memcpy(out, tmp, SHA256_DIGEST_LENGTH);
  }
  return SHA256_DIGEST_LENGTH;
}

int tc_pbkdf2(tc_sign_method_t mode, const void* password, unsigned int plen, const void* salt, unsigned int slen, unsigned int count, unsigned char* out) {
  switch (mode)
  {
    case TC_MD5:
      return tc_pbkdf2_md5(password, plen, salt, slen, count, out);
    case TC_SHA128:
      return tc_pbkdf2_sha128(password, plen, salt, slen, count, out);
    case TC_SHA256:
      return tc_pbkdf2_sha256(password, plen, salt, slen, count, out);
  }
  return -1;
}