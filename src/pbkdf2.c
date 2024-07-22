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
    return -4;

#define pbkdf2_init_tmp(val, data, len) char val[len]; memcpy(tmp, out, len);

#define pbkdf2_xor_step(a, b, len) { int n; for (n = 0; n < len; n++) a[n] ^= b[n]; }

#define pbkdf2_init_process(name, ctx, pw, plen, salt, slen, out)  \
  tc_hmac_##name##_init(ctx, pw, plen);                            \
  tc_hmac_##name##_update(ctx, salt, slen);                        \
  tc_hmac_##name##_update(ctx, "\x00\x00\x00\x01", 4);             \
  tc_hmac_##name##_final(ctx, out);

#define pbkdf2_one_step(name, ctx, pw, plen, in, isize)    \
  tc_hmac_##name##_init(ctx, pw, plen);                    \
  tc_hmac_##name##_update(ctx, in, isize);                 \
  tc_hmac_##name##_final(ctx, in);

static inline int tc_pbkdf2_md5(const void* password, unsigned int plen, const void* salt, unsigned int slen, unsigned int count, unsigned char out[MD5_DIGEST_LENGTH]) {
  pbkdf2_check_error(password, plen, salt, slen, count);
  
  MD5_CTX context;
  pbkdf2_init_process(md5, &context, password, plen, salt, slen, out);

  if (count > 1) {
    uint32_t i; pbkdf2_init_tmp(tmp, out, MD5_DIGEST_LENGTH);
    for (i = 1; i < count; i++) {
      pbkdf2_one_step(md5, &context, password, plen, out, MD5_DIGEST_LENGTH);
      pbkdf2_xor_step(tmp, out, MD5_DIGEST_LENGTH);
    }
    memcpy(out, tmp, MD5_DIGEST_LENGTH);
  }
  return MD5_DIGEST_LENGTH;
}

static inline int tc_pbkdf2_sha128(const void* password, unsigned int plen, const void* salt, unsigned int slen, unsigned int count, unsigned char out[SHA_DIGEST_LENGTH]) {
  pbkdf2_check_error(password, plen, salt, slen, count);

  SHA_CTX context;
  pbkdf2_init_process(sha1, &context, password, plen, salt, slen, out);

  if (count > 1) {
    uint32_t i; pbkdf2_init_tmp(tmp, out, SHA_DIGEST_LENGTH);
    for (i = 1; i < count; i++) {
      pbkdf2_one_step(sha1, &context, password, plen, out, SHA_DIGEST_LENGTH);
      pbkdf2_xor_step(tmp, out, SHA_DIGEST_LENGTH);
    }
    memcpy(out, tmp, SHA_DIGEST_LENGTH);
  }
  return SHA_DIGEST_LENGTH;
}

static inline int tc_pbkdf2_sha256(const void* password, unsigned int plen, const void* salt, unsigned int slen, unsigned int count, unsigned char out[SHA256_DIGEST_LENGTH]) {
  pbkdf2_check_error(password, plen, salt, slen, count);

  SHA256_CTX context;
  pbkdf2_init_process(sha256, &context, password, plen, salt, slen, out);

  if (count > 1) {
    uint32_t i; pbkdf2_init_tmp(tmp, out, SHA256_DIGEST_LENGTH);
    for (i = 1; i < count; i++) {
      pbkdf2_one_step(sha256, &context, password, plen, out, SHA256_DIGEST_LENGTH);
      pbkdf2_xor_step(tmp, out, SHA256_DIGEST_LENGTH);
    }
    memcpy(out, tmp, SHA256_DIGEST_LENGTH);
  }
  return SHA256_DIGEST_LENGTH;
}

int tc_pbkdf2(tc_sign_method_t mode, const void* password, unsigned int plen, const void* salt, unsigned int slen, unsigned int count, unsigned char* out) {
  switch (mode)
  {
    case tc_sign_md5:
      return tc_pbkdf2_md5(password, plen, salt, slen, count, out);
    case tc_sign_sha128:
      return tc_pbkdf2_sha128(password, plen, salt, slen, count, out);
    case tc_sign_sha256:
      return tc_pbkdf2_sha256(password, plen, salt, slen, count, out);
  }
  return -1;
}