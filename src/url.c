/*
**  LICENSE: BSD
**  Author: CandyMi[https://github.com/candymi]
*/
#include <tc.h>

#define TOHEX(ch) tohex[ch]

static const char tohex[] = "0123456789ABCDEF";

static const char *reserved = "~_-.!(*)";

static const char deindex[] = {
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

int tc_urlencode(const void *text, unsigned int tsize, unsigned char *md) {
  if (text == NULL || tsize == 0 || md == NULL)
    return 0;

  uint8_t ch;
  const uint8_t *idx = text;
  uint8_t *data = md;
  while (tsize--)
  {
    ch = *idx++;
    if(isalnum(ch) || strchr(reserved, ch)) {
      *data++ = ch;
      continue;
    }
    *data++ = '%';
    *data++ = TOHEX(((uint8_t)ch) >> 4);
    *data++ = TOHEX(((uint8_t)ch) & 0xF);
  }
  return (unsigned int)(data - md);
}

int tc_urldecode(const void *text, unsigned int tsize, unsigned char *md) {
  if (text == NULL || tsize == 0 || md == NULL)
    return 0;

  uint8_t *data = md;
  int hi, lo; size_t index;
  for (index = 0; index < tsize;) {
    uint8_t ch = ((uint8_t*)text)[index++];
    if (ch != '%') {
      if (ch == '+')
        *data++ = ' ';
      else
        *data++ = ch;
      continue;
    }
    hi = deindex[((uint8_t*)text)[index++]];
    if (index == tsize || -1 == hi)
      return 0;
    lo = deindex[((uint8_t*)text)[index++]];
    if (index == tsize || -1 == lo)
      return 0;
    *data++ = hi << 4 | lo;
  }

  return (unsigned int)index;
}
