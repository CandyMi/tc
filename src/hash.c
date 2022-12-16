/*
**  LICENSE: BSD
**  Author: CandyMi[https://github.com/candymi]
*/
#include <tc.h>

#define prime   (0x01000193)
#define ivalue  (0x811c9dc5)


int tc_hashxor(const void* key, unsigned int ksize, const void* text, unsigned int tsize, unsigned char* md) {
  if (text == NULL || tsize == 0 || key == NULL || ksize == 0 || md == NULL)
    return 0;
  
  unsigned int i;
  for (i = 0; i < tsize; i++)
    md[i] = ((const char*)text)[i] ^ ((const char*)key)[i % ksize];
  
  return tsize;
}

int tc_hashkey(const void* text, unsigned int tsize, unsigned char md[HASHKEY_LENGTH]) {
  if (text == NULL || tsize == 0 || md == NULL)
    return 0;

  uint8_t code;
  const char *data = text;

  uint32_t hash1  = ivalue;
  uint32_t hash2  = ivalue;

  while (tsize--)
  {
    code = *data++;

    hash1 ^= code;
    hash1 *= prime;

    hash2 *= prime;
    hash2 ^= code;
  }

  md[0] = hash1 >> 24;  md[1] = hash2 >> 24;
  md[2] = hash1 >> 16;  md[3] = hash2 >> 16;
  md[4] = hash1 >>  8;  md[5] = hash2 >>  8;
  md[6] = hash1 & 0xff; md[7] = hash2 & 0xff;

  return 1;
}