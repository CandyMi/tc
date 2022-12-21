/*
**  LICENSE: BSD
**  Author: CandyMi[https://github.com/candymi]
*/
#include <tc.h>

#define H1 (0x67452301)
#define H2 (0xEFCDAB89)
#define H3 (0x98BADCFE)
#define H4 (0x10325476)

#define F(b,c,d)   ((((c) ^ (d)) & (b)) ^ (d))
#define G(b,c,d)   ((((b) ^ (c)) & (d)) ^ (c))
#define H(b,c,d)   ((b) ^ (c) ^ (d))
#define I(b,c,d)   (((~(d)) | (b)) ^ (c))

#define ROTATE(x,n) ((x << n) | (x >> (32-n)))

#define R0(a,b,c,d,k,s,t) {          \
        a+=((k)+(t)+F((b),(c),(d))); \
        a=ROTATE(a,s);               \
        a+=b; };

#define R1(a,b,c,d,k,s,t) {          \
        a+=((k)+(t)+G((b),(c),(d))); \
        a=ROTATE(a,s);               \
        a+=b; };

#define R2(a,b,c,d,k,s,t) {          \
        a+=((k)+(t)+H((b),(c),(d))); \
        a=ROTATE(a,s);               \
        a+=b; };

#define R3(a,b,c,d,k,s,t) {          \
        a+=((k)+(t)+I((b),(c),(d))); \
        a=ROTATE(a,s);               \
        a+=b; };

static const uint8_t padding[] = {
  0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static inline void tc_encode(uint8_t *output, uint32_t *input, size_t len) {
  unsigned int i = 0,j = 0;
  while(j < len) {
    output[j+0] = (input[i] & 0xFF);
    output[j+1] = (input[i] >> 8)  & 0xFF;
    output[j+2] = (input[i] >> 16) & 0xFF;
    output[j+3] = (input[i] >> 24) & 0xFF;
    i++; j+=4;
  }
}

static inline void tc_decode(uint32_t *output, const uint8_t *input, size_t len) {
  unsigned int i = 0,j = 0;
  while(j < len) {
    output[i] = (input[j]) | (input[j+1] << 8) | (input[j+2] << 16) | (input[j+3] << 24);
    i++; j+=4;
  }
}

static inline void tc_md5_transform(unsigned int state[4], const unsigned char block[64]) {
  uint32_t a = state[0];
  uint32_t b = state[1];
  uint32_t c = state[2];
  uint32_t d = state[3];
  uint32_t x[64];

  tc_decode(x, block, 64);

  R0(a, b, c, d, x[ 0],  7, 0xd76aa478);
  R0(d, a, b, c, x[ 1], 12, 0xe8c7b756);
  R0(c, d, a, b, x[ 2], 17, 0x242070db);
  R0(b, c, d, a, x[ 3], 22, 0xc1bdceee);
  R0(a, b, c, d, x[ 4],  7, 0xf57c0faf);
  R0(d, a, b, c, x[ 5], 12, 0x4787c62a);
  R0(c, d, a, b, x[ 6], 17, 0xa8304613);
  R0(b, c, d, a, x[ 7], 22, 0xfd469501);
  R0(a, b, c, d, x[ 8],  7, 0x698098d8);
  R0(d, a, b, c, x[ 9], 12, 0x8b44f7af);
  R0(c, d, a, b, x[10], 17, 0xffff5bb1);
  R0(b, c, d, a, x[11], 22, 0x895cd7be);
  R0(a, b, c, d, x[12],  7, 0x6b901122);
  R0(d, a, b, c, x[13], 12, 0xfd987193);
  R0(c, d, a, b, x[14], 17, 0xa679438e);
  R0(b, c, d, a, x[15], 22, 0x49b40821);

  R1(a, b, c, d, x[ 1],  5, 0xf61e2562);
  R1(d, a, b, c, x[ 6],  9, 0xc040b340);
  R1(c, d, a, b, x[11], 14, 0x265e5a51);
  R1(b, c, d, a, x[ 0], 20, 0xe9b6c7aa);
  R1(a, b, c, d, x[ 5],  5, 0xd62f105d);
  R1(d, a, b, c, x[10],  9,  0x2441453);
  R1(c, d, a, b, x[15], 14, 0xd8a1e681);
  R1(b, c, d, a, x[ 4], 20, 0xe7d3fbc8);
  R1(a, b, c, d, x[ 9],  5, 0x21e1cde6);
  R1(d, a, b, c, x[14],  9, 0xc33707d6);
  R1(c, d, a, b, x[ 3], 14, 0xf4d50d87);
  R1(b, c, d, a, x[ 8], 20, 0x455a14ed);
  R1(a, b, c, d, x[13],  5, 0xa9e3e905);
  R1(d, a, b, c, x[ 2],  9, 0xfcefa3f8);
  R1(c, d, a, b, x[ 7], 14, 0x676f02d9);
  R1(b, c, d, a, x[12], 20, 0x8d2a4c8a);


  R2(a, b, c, d, x[ 5],  4, 0xfffa3942);
  R2(d, a, b, c, x[ 8], 11, 0x8771f681);
  R2(c, d, a, b, x[11], 16, 0x6d9d6122);
  R2(b, c, d, a, x[14], 23, 0xfde5380c);
  R2(a, b, c, d, x[ 1],  4, 0xa4beea44);
  R2(d, a, b, c, x[ 4], 11, 0x4bdecfa9);
  R2(c, d, a, b, x[ 7], 16, 0xf6bb4b60);
  R2(b, c, d, a, x[10], 23, 0xbebfbc70);
  R2(a, b, c, d, x[13],  4, 0x289b7ec6);
  R2(d, a, b, c, x[ 0], 11, 0xeaa127fa);
  R2(c, d, a, b, x[ 3], 16, 0xd4ef3085);
  R2(b, c, d, a, x[ 6], 23,  0x4881d05);
  R2(a, b, c, d, x[ 9],  4, 0xd9d4d039);
  R2(d, a, b, c, x[12], 11, 0xe6db99e5);
  R2(c, d, a, b, x[15], 16, 0x1fa27cf8);
  R2(b, c, d, a, x[ 2], 23, 0xc4ac5665);


  R3(a, b, c, d, x[ 0],  6, 0xf4292244);
  R3(d, a, b, c, x[ 7], 10, 0x432aff97);
  R3(c, d, a, b, x[14], 15, 0xab9423a7);
  R3(b, c, d, a, x[ 5], 21, 0xfc93a039);
  R3(a, b, c, d, x[12],  6, 0x655b59c3);
  R3(d, a, b, c, x[ 3], 10, 0x8f0ccc92);
  R3(c, d, a, b, x[10], 15, 0xffeff47d);
  R3(b, c, d, a, x[ 1], 21, 0x85845dd1);
  R3(a, b, c, d, x[ 8],  6, 0x6fa87e4f);
  R3(d, a, b, c, x[15], 10, 0xfe2ce6e0);
  R3(c, d, a, b, x[ 6], 15, 0xa3014314);
  R3(b, c, d, a, x[13], 21, 0x4e0811a1);
  R3(a, b, c, d, x[ 4],  6, 0xf7537e82);
  R3(d, a, b, c, x[11], 10, 0xbd3af235);
  R3(c, d, a, b, x[ 2], 15, 0x2ad7d2bb);
  R3(b, c, d, a, x[ 9], 21, 0xeb86d391);

  state[0] += a; state[1] += b;
  state[2] += c; state[3] += d;
}

int tc_md5_init(MD5_CTX *context) {
  if (context == NULL)
    return 0;

  context->count[0] = 0;
  context->count[1] = 0;
  context->state[0] = H1;
  context->state[1] = H2;
  context->state[2] = H3;
  context->state[3] = H4;
  return 1;
}

int tc_md5_update(MD5_CTX *context, const void* text, unsigned int tsize) {
  if (context == NULL || text == NULL || tsize == 0)
    return 0;

  uint32_t i = 0, index = 0, partlen = 0;
  index = (context->count[0] >> 3) & 0x3F;
  partlen = 64 - index;
  context->count[0] += tsize << 3;
  if(context->count[0] < (tsize << 3))
    context->count[1]++;

  context->count[1] += tsize >> 29;

  if(tsize >= partlen) {
    memcpy(&context->buffer[index], text, partlen);
    tc_md5_transform(context->state, context->buffer);
    for(i = partlen; i + 64 <= tsize; i += 64)
      tc_md5_transform(context->state, ((uint8_t*)text) + i);

    index = 0;
  } else {
    i = 0;
  }

  memcpy(&context->buffer[index], ((uint8_t*)text) + i, tsize - i);
  return 1;
}

int tc_md5_final(MD5_CTX *context, unsigned char md[MD5_DIGEST_LENGTH]) {
  if (context == NULL || md == NULL)
    return 0;
  uint32_t index = 0, padlen = 0;
  uint8_t bits[8];
  index = (context->count[0] >> 3) & 0x3F;
  padlen = (index < 56) ? (56-index) : (120-index);
  tc_encode(bits,context->count, 8);
  tc_md5_update(context, padding, padlen);
  tc_md5_update(context, bits, 8);
  tc_encode(md, context->state, 16);
  return 1;
}

static char digest[] = "\xd4\x1d\x8c\xd9\x8f\x00\xb2\x04\xe9\x80\x09\x98\xec\xf8\x42\x7e";

void* tc_md5(const void* text, unsigned int tsize, unsigned char md[MD5_DIGEST_LENGTH]) {
  if (!md)
    md = tc_xmalloc(MD5_DIGEST_LENGTH);

  if (text == NULL || tsize == 0)
    return memcpy(md, digest, MD5_DIGEST_LENGTH);

  MD5_CTX context;
  tc_md5_init(&context);
  tc_md5_update(&context, text, tsize);
  tc_md5_final(&context, md);

  return md;
}