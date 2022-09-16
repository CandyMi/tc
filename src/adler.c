/*
**  LICENSE: BSD
**  Author: CandyMi[https://github.com/candymi]
*/
#include <tc.h>

unsigned int adler32(const void *text, unsigned int tsize) {
  if (!text || tsize == 0)
    return 0;
  uint32_t sum = 0;
  uint32_t adler = 1;
  size_t index;
  for (index = 0; index < tsize; index++) {
    adler = (adler + ((uint8_t*)text)[index]) % 65521;
    sum = (sum + adler) % 65521;
  }
  return adler | (sum << 16);
}