/*
**  LICENSE: BSD
**  Author: CandyMi[https://github.com/candymi]
*/
#include <tc.h>

#define FNV32_PRIME   (0x01000193)
#define FNV32_OFFSET  (0x811c9dc5)

#define FNV64_PRIME   (0x00000100000001B3LL)
#define FNV64_OFFSET  (0xcbf29ce484222325LL)

int tc_hashxor(const void* key, unsigned int ksize, const void* text, unsigned int tsize, unsigned char* md) {
  if (text == NULL || tsize == 0 || key == NULL || ksize == 0 || md == NULL)
    return 0;
  
  unsigned int i;
  for (i = 0; i < tsize; i++)
    md[i] = ((const char*)text)[i] ^ ((const char*)key)[i % ksize];
  
  return tsize;
}

#define fnv_hash(FNV_OFFSET, FNV_PRIME, BUFFER, BSIZE, HASH1, HASH1A) {  \
  *HASH1 = FNV_OFFSET; *HASH1A = FNV_OFFSET;                             \
  while (BSIZE--)                                                        \
  {                                                                      \
    (*HASH1)  *= FNV_PRIME; (*HASH1)  ^= *BUFFER;                        \
    (*HASH1A) ^= *BUFFER;   (*HASH1A) *= FNV_PRIME;                      \
    BUFFER++;                                                            \
  }}

int tc_hashkey(const void* text, unsigned int tsize, unsigned char md[HASHKEY_LENGTH]) {
  if (text == NULL || tsize == 0 || md == NULL)
    return 0;

  const char *data = text;

  uint32_t hash1; uint32_t hash2;
  fnv_hash(FNV32_OFFSET, FNV32_PRIME, data, tsize, &hash1, &hash2);

  md[0] = (uint8_t)(hash1 >> 24) & 0xff;  md[1] = (uint8_t)(hash2 >> 24) & 0xff;
  md[2] = (uint8_t)(hash1 >> 16) & 0xff;  md[3] = (uint8_t)(hash2 >> 16) & 0xff;
  md[4] = (uint8_t)(hash1 >>  8) & 0xff;  md[5] = (uint8_t)(hash2 >>  8) & 0xff;
  md[6] = (uint8_t)hash1 & 0xff;          md[7] = (uint8_t)hash2 & 0xff;

  return 1;
}

int tc_hashkey64(const void* text, unsigned int tsize, unsigned char md[HASHKEY64_LENGTH]) {
  if (text == NULL || tsize == 0 || md == NULL)
    return 0;

  const char *data = text;

  uint64_t hash1; uint64_t hash2;
  fnv_hash(FNV64_OFFSET, FNV64_PRIME, data, tsize, &hash1, &hash2);

  md[0]  = (uint8_t)(hash1 >> 56) & 0xff;  md[1]  = (uint8_t)(hash2 >> 56) & 0xff;
  md[2]  = (uint8_t)(hash1 >> 48) & 0xff;  md[3]  = (uint8_t)(hash2 >> 48) & 0xff;
  md[4]  = (uint8_t)(hash1 >> 40) & 0xff;  md[5]  = (uint8_t)(hash2 >> 40) & 0xff;
  md[6]  = (uint8_t)(hash1 >> 32) & 0xff;  md[7]  = (uint8_t)(hash2 >> 32) & 0xff;
  md[8]  = (uint8_t)(hash1 >> 24) & 0xff;  md[9]  = (uint8_t)(hash2 >> 24) & 0xff;
  md[10] = (uint8_t)(hash1 >> 16) & 0xff;  md[11] = (uint8_t)(hash2 >> 16) & 0xff;
  md[12] = (uint8_t)(hash1 >>  8) & 0xff;  md[13] = (uint8_t)(hash2 >>  8) & 0xff;
  md[14] = (uint8_t)hash1 & 0xff;          md[15] = (uint8_t)hash2 & 0xff;

  return 1;
}