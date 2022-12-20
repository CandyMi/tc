/*
**  LICENSE: BSD
**  Author: CandyMi[https://github.com/candymi]
*/
#include <tc.h>

static inline void tc_init_counter(char c[4], unsigned long counter) {
  c[0] = (counter >> 24) & 0xff;
  c[1] = (counter >> 16) & 0xff;
  c[2] = (counter >> 8)  & 0xff;
  c[3] = (counter >> 0)  & 0xff;
}


static inline int tc_pbkdf2_md5(const void* password, unsigned int plen, const void* salt, unsigned int slen, unsigned int count, char out[MD5_DIGEST_LENGTH]) {
  if (!password || plen == 0)
    return -2;
  if (!salt || slen == 0)
    return -3;
  if (count == 0)
    return -4;

  return MD5_DIGEST_LENGTH;
}

static inline int tc_pbkdf2_sha128(const void* password, unsigned int plen, const void* salt, unsigned int slen, unsigned int count, char out[SHA_DIGEST_LENGTH]) {
  if (!password || plen == 0)
    return -2;
  if (!salt || slen == 0)
    return -3;
  if (count == 0)
    return -4;

  return SHA_DIGEST_LENGTH;
}

static inline int tc_pbkdf2_sha256(const void* password, unsigned int plen, const void* salt, unsigned int slen, unsigned int count, char out[SHA256_DIGEST_LENGTH]) {
  if (!password || plen == 0)
    return -2;
  if (!salt || slen == 0)
    return -3;
  if (count == 0)
    return -4;

  return SHA256_DIGEST_LENGTH;
}

int tc_pbkdf2(tc_sign_t mode, const void* password, unsigned int plen, const void* salt, unsigned int slen, unsigned int count, char* out) {
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