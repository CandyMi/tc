/*
**  LICENSE: BSD
**  Author: CandyMi[https://github.com/candymi]
*/
#include <tc.h>

int tc_rc4_set_key(RC4_KEY *key, const void *text, unsigned int tsize) {
  if (!key || !text || text == 0)
    return 0;
  memset(key, 0x0, sizeof(RC4_KEY));

  register uint32_t tmp;
  register uint32_t *d;
  register size_t id1, id2, i;

  id1 = id2 = 0;
  d = &(key->data[0]);
  for (i = 0; i < 256; i++)
    d[i] = i;
  
#define SK_LOOP(d,n)                                  \
  {                                                   \
    tmp = d[(n)];                                     \
    id2 = (((uint8_t*)text)[id1] + tmp + id2) & 0xff; \
    if (++id1 == tsize) id1=0;                        \
    d[(n)]=d[id2];                                    \
    d[id2]=tmp;                                       \
  }

  for (i = 0; i < 256; i += 4) {
    SK_LOOP(d, i + 0);
    SK_LOOP(d, i + 1);
    SK_LOOP(d, i + 2);
    SK_LOOP(d, i + 3);
  }
  return 1;
}

void* tc_rc4(RC4_KEY *key, const void *text, unsigned int tsize, unsigned char *md) {
  if (key == NULL || text == NULL || tsize == 0)
    return NULL;

  int eof = 0;
  if (!md){
    md = tc_xmalloc(tsize + 1);
    eof = 1;
  }

  uint32_t *d; size_t i;
  uint32_t x, y, tx, ty;

  const unsigned char *indata  = text;
  unsigned char *outdata = md;

  x = key->x; y = key->y; d = key->data;

#define LOOP(in,out)                 \
    x=((x+1)&0xff);                  \
    tx=d[x];                         \
    y=(tx+y)&0xff;                   \
    d[x]=ty=d[y];                    \
    d[y]=tx;                         \
    (out) = d[(tx+ty)&0xff] ^ (in);

  i = tsize >> 3;
  if (i) {
      for (;;) {
        LOOP(indata[0], outdata[0]);
        LOOP(indata[1], outdata[1]);
        LOOP(indata[2], outdata[2]);
        LOOP(indata[3], outdata[3]);
        LOOP(indata[4], outdata[4]);
        LOOP(indata[5], outdata[5]);
        LOOP(indata[6], outdata[6]);
        LOOP(indata[7], outdata[7]);
        indata += 8; outdata += 8;
        if (--i == 0)
            break;
      }
  }
  i = tsize & 0x07;
  if (i) {
      for (;;) {
          LOOP(indata[0], outdata[0]);
          if (--i == 0)
              break;
          LOOP(indata[1], outdata[1]);
          if (--i == 0)
              break;
          LOOP(indata[2], outdata[2]);
          if (--i == 0)
              break;
          LOOP(indata[3], outdata[3]);
          if (--i == 0)
              break;
          LOOP(indata[4], outdata[4]);
          if (--i == 0)
              break;
          LOOP(indata[5], outdata[5]);
          if (--i == 0)
              break;
          LOOP(indata[6], outdata[6]);
          if (--i == 0)
              break;
      }
  }
  key->x = x; key->y = y;
  if (eof)
    md[tsize] = '\x00';
  return md;
}
