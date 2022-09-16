/*
**  LICENSE: BSD
**  Author: CandyMi[https://github.com/candymi]
*/
#include <tc.h>

static char lencode[] = "0123456789abcdef";

static char hencode[] = "0123456789ABCDEF";

static const char deindex[256] = {
  -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
  -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
  -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
  -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
  -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
  -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
   0,      1,      2,      3,      4,      5,      6,      7,
   8,      9,     -1,     -1,     -1,     -1,     -1,     -1,
  -1,     10,     11,     12,     13,     14,     15,     -1,
  -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
  -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
  -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
  -1,     10,     11,     12,     13,     14,     15,     -1,
  -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
  -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
  -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
  -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
  -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
  -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
  -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
  -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
  -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
  -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
  -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
  -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
  -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
  -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
  -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
  -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
  -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
  -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
  -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
};

int hexencode(const void* text, unsigned int tsize, unsigned char *md, int mode) {
  if (text == NULL || tsize == 0 || md == NULL)
    return 0;

  uint8_t *buffer = md;
  const char *etable = lencode;
  if (mode == tc_hex_upper)
    etable = hencode;

  uint8_t code;
  unsigned int idx = 0;
  while (idx < tsize)
  {
    code = ((uint8_t*)text)[idx++];
    *buffer++ = etable[code >> 4];
    *buffer++ = etable[code & 0xF];
  }

  *buffer = '\x00';
  return tsize << 1;
}

int hexdecode(const void* text, unsigned int tsize, unsigned char *md) {
  if (text == NULL || tsize == 0 || md == NULL)
    return 0;

  uint8_t *buffer = md;
  uint32_t idx = 0; int8_t hi; int8_t lo;
  while (idx < tsize)
  {
    hi = deindex[((uint8_t*)text)[idx++]];
    lo = deindex[((uint8_t*)text)[idx++]];
    if (hi == -1 || lo == -1)
      return 0;
    *buffer++ = hi << 4 | lo;
  }

  *buffer = '\x00';
  return idx;
}