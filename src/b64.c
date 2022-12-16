/*
**  LICENSE: BSD
**  Author: CandyMi[https://github.com/candymi]
*/
#include <tc.h>

#define BASE64_URLSAFE(safe, ch, a, b, c, d) \
  if (urlsafe) {            \
    if (ch == a)            \
      ch = b;               \
    else if (ch == c)       \
      ch = d;               \
  }

static inline void encoder(uint8_t *buffer, uint32_t idx, uint8_t code, int32_t urlsafe) {
  static const char b64code[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  uint8_t ch = b64code[code];
  BASE64_URLSAFE(urlsafe, ch, '+', '-', '/', '_');
  /* check encoder */
  buffer[idx] = ch;
}

static inline uint8_t decoder(uint8_t ch, int32_t urlsafe) {
  static const int8_t b64code_idx[] = {
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  62,  -1,  -1,  -1,  63,
    52,  53,  54,  55,  56,  57,  58,  59,  60,  61,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,   0,   1,   2,   3,   4,   5,   6,   7,   8,   9,  10,  11,  12,  13,  14,
    15,  16,  17,  18,  19,  20,  21,  22,  23,  24,  25,  -1,  -1,  -1,  -1,  -1,
    -1,  26,  27,  28,  29,  30,  31,  32,  33,  34,  35,  36,  37,  38,  39,  40,
    41,  42,  43,  44,  45,  46,  47,  48,  49,  50,  51,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
  };
  BASE64_URLSAFE(urlsafe, ch, '-', '+', '_', '/');
  return b64code_idx[ch];
}

int tc_base64encode(const void* text, unsigned int tsize, unsigned char *md, int mode) {
  if (text == NULL || tsize == 0 || md == NULL)
    return 0;

  int urlsafe = mode & tc_b64_url ? 1 : 0;
  int nopadding = mode & tc_b64_nopadding ? 1 : 0;

  uint8_t code;
  uint8_t* buffer = md;
  size_t nsize = tsize;
  size_t idx, set;
  uint32_t index = 0;

  /* normal encoder */
  for (idx = 0; idx < nsize - 2; idx += 3) {
    set = (((uint8_t*)text)[idx] << 16) | (((uint8_t*)text)[idx + 1] << 8) | (((uint8_t*)text)[idx + 2]);
    encoder((uint8_t*)buffer, index++, set >> 18 & 0x3f, urlsafe);
    encoder((uint8_t*)buffer, index++, set >> 12 & 0x3f, urlsafe);
    encoder((uint8_t*)buffer, index++, set >> 6  & 0x3f, urlsafe);
    encoder((uint8_t*)buffer, index++, set & 0x3f, urlsafe);
  }

  /* checked padding. */
  switch (tsize - idx) {
    case 1: /* only 1 char */
      code = ((uint8_t*)text)[idx];
      encoder((uint8_t*)buffer, index++, code >> 2, urlsafe);
      encoder((uint8_t*)buffer, index++, (code << 4) & 0x3f, urlsafe);
      if (!nopadding) {
        buffer[index++] = '=';
        buffer[index++] = '=';
      }
      break;
    case 2: /* having 2 char */
      set = ((uint8_t*)text)[idx] << 8 | ((uint8_t*)text)[idx + 1];
      encoder((uint8_t*)buffer, index++, (set >> 10) & 0x3f, urlsafe);
      encoder((uint8_t*)buffer, index++, (set >>  4) & 0x3f, urlsafe);
      encoder((uint8_t*)buffer, index++, (set <<  2) & 0x3f, urlsafe);
      if (!nopadding)
        buffer[index++] = '=';
      break;
  }

  buffer[index] = '\x00';
  return index;
}

int tc_base64decode(const void* text, unsigned int tsize, unsigned char *md, int mode) {
  if (text == NULL || tsize == 0 || md == NULL)
    return 0;

  int urlsafe = mode & tc_b64_url ? 1 : 0;

  uint8_t* buffer = md;
  uint32_t index = 0, idx = 0;
  uint32_t offsets, i, pos;

  for (idx = 0; idx < tsize;)
  {
    i = 0, pos = 0;
    uint8_t set[] = {0, 0, 0, 0};
    while (idx + pos < tsize && i < 4) {
      uint8_t ch = ((uint8_t*)text)[idx + (pos++)];
      if (ch == '=') {
        if (idx + pos < tsize - 2)
          return -1;
        break;
      }
      if (ch == '\n')
        continue;
      ch = decoder(ch, urlsafe);
      if ((int8_t)ch == -1)
        return -1;
      set[i++] = ch;
    }

    offsets = (set[0] << 18) | (set[1] << 12) | (set[2] << 6) | set[3];
    switch (4 - i){
      case 0:
        /* decode normal character. */
        buffer[index++] = (offsets >> 16);
        buffer[index++] = (offsets >>  8) & 0xFF;;
        buffer[index++] = offsets & 0xFF;
        break;
      case 1:
        /* padding 1 character. */
        buffer[index++] = (offsets >> 16);
        buffer[index++] = (offsets >>  8) & 0xFF;;
        break;
      case 2:
        /* padding 2 character. */
        buffer[index++] = offsets >> 16;
        break;
    }
    idx += pos; 
  }
  buffer[index] = '\x00';
  return index;
}