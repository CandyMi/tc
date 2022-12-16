/*
**  LICENSE: BSD
**  Author: CandyMi[https://github.com/candymi]
*/
#include <tc.h>

static inline int tc_pbkdf2_md5(const void* password, unsigned int plen, const void* salt, unsigned int slen, unsigned int count, char* out) {
  return MD5_DIGEST_LENGTH;
}

static inline int tc_pbkdf2_sha128(const void* password, unsigned int plen, const void* salt, unsigned int slen, unsigned int count, char* out) {
  return SHA_DIGEST_LENGTH;  
}

static inline int tc_pbkdf2_sha256(const void* password, unsigned int plen, const void* salt, unsigned int slen, unsigned int count, char* out) {
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