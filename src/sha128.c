/*
**  LICENSE: BSD
**  Author: CandyMi[https://github.com/candymi]
*/
#include <tc.h>

#define H1 (0x67452301)
#define H2 (0xEFCDAB89)
#define H3 (0x98BADCFE)
#define H4 (0x10325476)
#define H5 (0xC3D2E1F0)

#define rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

#define blk0(i) (block->l[i] = (rol(block->l[i],24)&0xff00ff00) |(rol(block->l[i],8)&0x00ff00ff))
#define blk(i) (block->l[i&15] = rol(block->l[(i+13)&15]^block->l[(i+8)&15] ^ block->l[(i+2)&15]^block->l[i&15],1))

/* (R0+R1), R2, R3, R4 are the different operations used in SHA1 */
#define R0(v, w, x, y, z, i) z+=((w&(x^y))^y)+blk0(i)+0x5a827999+rol(v,5);w=rol(w,30);
#define R1(v, w, x, y, z, i) z+=((w&(x^y))^y)+blk(i)+0x5a827999+rol(v,5);w=rol(w,30);
#define R2(v, w, x, y, z, i) z+=(w^x^y)+blk(i)+0x6ed9eba1+rol(v,5);w=rol(w,30);
#define R3(v, w, x, y, z, i) z+=(((w|x)&y)|(w&x))+blk(i)+0x8f1bbcdc+rol(v,5);w=rol(w,30);
#define R4(v, w, x, y, z, i) z+=(w^x^y)+blk(i)+0xca62c1d6+rol(v,5);w=rol(w,30);

static inline void tc_sha1_transform(unsigned int state[5], const unsigned char text[64]) {
  typedef union {
    uint8_t c[64];
    uint32_t l[16];
  } CHAR64LONG16;
  CHAR64LONG16 v;
  CHAR64LONG16* block = &v;
  memcpy(block->c, text, 64);
  

  uint32_t a = state[0];
  uint32_t b = state[1];
  uint32_t c = state[2];
  uint32_t d = state[3];
  uint32_t e = state[4];

  /* 4 rounds of 20 operations each. Loop unrolled. */
  R0(a, b, c, d, e, 0);
  R0(e, a, b, c, d, 1);
  R0(d, e, a, b, c, 2);
  R0(c, d, e, a, b, 3);
  R0(b, c, d, e, a, 4);
  R0(a, b, c, d, e, 5);
  R0(e, a, b, c, d, 6);
  R0(d, e, a, b, c, 7);
  R0(c, d, e, a, b, 8);
  R0(b, c, d, e, a, 9);
  R0(a, b, c, d, e, 10);
  R0(e, a, b, c, d, 11);
  R0(d, e, a, b, c, 12);
  R0(c, d, e, a, b, 13);
  R0(b, c, d, e, a, 14);
  R0(a, b, c, d, e, 15);
  R1(e, a, b, c, d, 16);
  R1(d, e, a, b, c, 17);
  R1(c, d, e, a, b, 18);
  R1(b, c, d, e, a, 19);
  R2(a, b, c, d, e, 20);
  R2(e, a, b, c, d, 21);
  R2(d, e, a, b, c, 22);
  R2(c, d, e, a, b, 23);
  R2(b, c, d, e, a, 24);
  R2(a, b, c, d, e, 25);
  R2(e, a, b, c, d, 26);
  R2(d, e, a, b, c, 27);
  R2(c, d, e, a, b, 28);
  R2(b, c, d, e, a, 29);
  R2(a, b, c, d, e, 30);
  R2(e, a, b, c, d, 31);
  R2(d, e, a, b, c, 32);
  R2(c, d, e, a, b, 33);
  R2(b, c, d, e, a, 34);
  R2(a, b, c, d, e, 35);
  R2(e, a, b, c, d, 36);
  R2(d, e, a, b, c, 37);
  R2(c, d, e, a, b, 38);
  R2(b, c, d, e, a, 39);
  R3(a, b, c, d, e, 40);
  R3(e, a, b, c, d, 41);
  R3(d, e, a, b, c, 42);
  R3(c, d, e, a, b, 43);
  R3(b, c, d, e, a, 44);
  R3(a, b, c, d, e, 45);
  R3(e, a, b, c, d, 46);
  R3(d, e, a, b, c, 47);
  R3(c, d, e, a, b, 48);
  R3(b, c, d, e, a, 49);
  R3(a, b, c, d, e, 50);
  R3(e, a, b, c, d, 51);
  R3(d, e, a, b, c, 52);
  R3(c, d, e, a, b, 53);
  R3(b, c, d, e, a, 54);
  R3(a, b, c, d, e, 55);
  R3(e, a, b, c, d, 56);
  R3(d, e, a, b, c, 57);
  R3(c, d, e, a, b, 58);
  R3(b, c, d, e, a, 59);
  R4(a, b, c, d, e, 60);
  R4(e, a, b, c, d, 61);
  R4(d, e, a, b, c, 62);
  R4(c, d, e, a, b, 63);
  R4(b, c, d, e, a, 64);
  R4(a, b, c, d, e, 65);
  R4(e, a, b, c, d, 66);
  R4(d, e, a, b, c, 67);
  R4(c, d, e, a, b, 68);
  R4(b, c, d, e, a, 69);
  R4(a, b, c, d, e, 70);
  R4(e, a, b, c, d, 71);
  R4(d, e, a, b, c, 72);
  R4(c, d, e, a, b, 73);
  R4(b, c, d, e, a, 74);
  R4(a, b, c, d, e, 75);
  R4(e, a, b, c, d, 76);
  R4(d, e, a, b, c, 77);
  R4(c, d, e, a, b, 78);
  R4(b, c, d, e, a, 79);

  /* Add the working vars back into context.state[] */
  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
  state[4] += e;

  /* Wipe variables */
  a = b = c = d = e = 0;
}

int tc_sha1_init(SHA_CTX *context) {
  if (context == NULL)
    return 0;

  context->count[0] = 0;
  context->count[1] = 0;
  context->state[0] = H1;
  context->state[1] = H2;
  context->state[2] = H3;
  context->state[3] = H4;
  context->state[4] = H5;
  return 1;
}

int tc_sha1_update(SHA_CTX* context, const void* text, unsigned int tsize) {
  if (context == NULL || text == NULL || tsize == 0)
    return 0;

  const uint8_t *data = text;
  size_t i, j;

  j = (context->count[0] >> 3) & 63;
  if ((context->count[0] += (uint32_t) (tsize << 3)) < (tsize << 3))
    context->count[1]++;

  context->count[1] += (uint32_t) (tsize >> 29);
  if ((j + tsize) > 63) {
      memcpy(&context->buffer[j], data, (i = 64 - j));
      tc_sha1_transform(context->state, context->buffer);
      for (; i + 63 < tsize; i += 64) {
          tc_sha1_transform(context->state, data + i);
      }
      j = 0;
  } else {
    i = 0;
  }
  memcpy(&context->buffer[j], &data[i], tsize - i);
  return 1;
}

int tc_sha1_final(SHA_CTX *context, unsigned char md[SHA_DIGEST_LENGTH]) {
  if (context == NULL || md == NULL)
    return 0;

  uint32_t i; uint8_t finalcount[8];

  for (i = 0; i < 8; i++)
    finalcount[i] = (uint8_t) ((context->count[(i >= 4 ? 0 : 1)] >> ((3 - (i & 3)) * 8)) & 255);

  tc_sha1_update(context, (uint8_t *) "\200", 1);

  while ((context->count[0] & 504) != 448)
    tc_sha1_update(context, (uint8_t *) "\0", 1);

  tc_sha1_update(context, finalcount, 8); /* Should cause SHA1_Transform */

  for (i = 0; i < SHA_DIGEST_LENGTH; i++)
    md[i] = (uint8_t) ((context->state[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);

  return 1;
}

static char digest[] = "\xda\x39\xa3\xee\x5e\x6b\x4b\x0d\x32\x55\xbf\xef\x95\x60\x18\x90\xaf\xd8\x07\x09";

void* tc_sha1(const void* text, unsigned int tsize, unsigned char md[SHA_DIGEST_LENGTH]) {
  if (!md)
    md = tc_xmalloc(SHA_DIGEST_LENGTH);

  if (text == NULL || tsize == 0)
    return memcpy(md, digest, SHA_DIGEST_LENGTH);

  SHA_CTX context;
  tc_sha1_init(&context);
  tc_sha1_update(&context, text, tsize);
  tc_sha1_final(&context, md);

  return md;
}