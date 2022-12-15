/*
**  LICENSE: BSD
**  Author: CandyMi[https://github.com/candymi]
*/
#include <tc.h>

/* define it for speed optimization */
#define _SHA256_UNROLL
#define _SHA256_UNROLL2

#define U32V(v) ((uint32_t)(v) & 0xFFFFFFFFU)

#define ROTL32(v, n) (U32V((uint32_t)(v) << (n)) | ((uint32_t)(v) >> (32 - (n))))

#define ROTR32(v, n) ROTL32(v, 32 - (n))

#define S0(x) (ROTR32(x, 2) ^ ROTR32(x,13) ^ ROTR32(x, 22))
#define S1(x) (ROTR32(x, 6) ^ ROTR32(x,11) ^ ROTR32(x, 25))
#define s0(x) (ROTR32(x, 7) ^ ROTR32(x,18) ^ (x >> 3))
#define s1(x) (ROTR32(x,17) ^ ROTR32(x,19) ^ (x >> 10))

#define blk0(i) (W[i] = data[i])
#define blk2(i) (W[i&15] += s1(W[(i-2)&15]) + W[(i-7)&15] + s0(W[(i-15)&15]))

#define Ch(x,y,z) (z^(x&(y^z)))
#define Maj(x,y,z) ((x&y)|(z&(x|y)))

#define a(i) T[(0-(i))&7]
#define b(i) T[(1-(i))&7]
#define c(i) T[(2-(i))&7]
#define d(i) T[(3-(i))&7]
#define e(i) T[(4-(i))&7]
#define f(i) T[(5-(i))&7]
#define g(i) T[(6-(i))&7]
#define h(i) T[(7-(i))&7]


#if defined(_SHA256_UNROLL2)

  #define R(a,b,c,d,e,f,g,h, i) h += S1(e) + Ch(e,f,g) + K[i+j] + (j?blk2(i):blk0(i));\
    d += h; h += S0(a) + Maj(a, b, c)

  #define RX_8(i) \
    R(a,b,c,d,e,f,g,h, i); \
    R(h,a,b,c,d,e,f,g, (i+1)); \
    R(g,h,a,b,c,d,e,f, (i+2)); \
    R(f,g,h,a,b,c,d,e, (i+3)); \
    R(e,f,g,h,a,b,c,d, (i+4)); \
    R(d,e,f,g,h,a,b,c, (i+5)); \
    R(c,d,e,f,g,h,a,b, (i+6)); \
    R(b,c,d,e,f,g,h,a, (i+7))

#else

  #define R(i) h(i) += S1(e(i)) + Ch(e(i),f(i),g(i)) + K[i+j] + (j?blk2(i):blk0(i));\
    d(i) += h(i); h(i) += S0(a(i)) + Maj(a(i), b(i), c(i))

  #ifdef _SHA256_UNROLL

    #define RX_8(i) R(i+0); R(i+1); R(i+2); R(i+3); R(i+4); R(i+5); R(i+6); R(i+7);

  #endif

#endif

static const uint32_t K[64] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static inline void tc_sha256_transform(uint32_t state[8], const uint32_t *data)
{
  uint32_t W[16];
  unsigned j;
  #ifdef _SHA256_UNROLL2
    uint32_t a,b,c,d,e,f,g,h;
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    f = state[5];
    g = state[6];
    h = state[7];
  #else
    uint32_t T[8];
    for (j = 0; j < 8; j++)
      T[j] = state[j];
  #endif

  for (j = 0; j < 64; j += 16)
  {
    #if defined(_SHA256_UNROLL) || defined(_SHA256_UNROLL2)
      RX_8(0); RX_8(8);
    #else
      unsigned i;
      for (i = 0; i < 16; i++)
        {R(i);}
    #endif
  }

  #ifdef _SHA256_UNROLL2
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
  #else
    for (j = 0; j < 8; j++)
      state[j] += T[j];
  #endif
}

static inline void tc_sha256_write_byte_block(SHA256_CTX *context)
{
  uint32_t data32[16];
  unsigned i;
  for (i = 0; i < 16; i++)
    data32[i] =
      ((uint32_t)(context->buffer[i * 4    ]) << 24) +
      ((uint32_t)(context->buffer[i * 4 + 1]) << 16) +
      ((uint32_t)(context->buffer[i * 4 + 2]) <<  8) +
      ((uint32_t)(context->buffer[i * 4 + 3]));
  tc_sha256_transform(context->state, data32);
}

int tc_sha256_init(SHA256_CTX *context) {
  if (context == NULL)
    return 0;
  memset(context, 0, sizeof(SHA256_CTX));
  context->count = 0;
  context->state[0] = 0x6a09e667;
  context->state[1] = 0xbb67ae85;
  context->state[2] = 0x3c6ef372;
  context->state[3] = 0xa54ff53a;
  context->state[4] = 0x510e527f;
  context->state[5] = 0x9b05688c;
  context->state[6] = 0x1f83d9ab;
  context->state[7] = 0x5be0cd19;
  return 1;
}

void tc_sha256_update(SHA256_CTX* context, const void* text, unsigned int tsize) {
  uint32_t pos = (uint32_t)context->count & 0x3F;
  const char* data = (const char*)text;
  while (tsize)
  {
    context->buffer[pos++] = *data++;
    context->count++;
    tsize--;
    if (pos == 64)
    {
      pos = 0;
      tc_sha256_write_byte_block(context);
    }
  }
}

void tc_sha256_final(SHA256_CTX* context, unsigned char md[SHA256_DIGEST_LENGTH]) {
  uint64_t lenInBits = (context->count << 3);
  uint32_t pos = (uint32_t)context->count & 0x3F;
  unsigned i;
  context->buffer[pos++] = 0x80;
  while (pos != (64 - 8))
  {
    pos &= 0x3F;
    if (pos == 0)
      tc_sha256_write_byte_block(context);
    context->buffer[pos++] = 0;
  }

  for (i = 0; i < 8; i++)
  {
    context->buffer[pos++] = (unsigned char)(lenInBits >> 56);
    lenInBits <<= 8;
  }

  tc_sha256_write_byte_block(context);

  for (i = 0; i < 8; i++)
  {
    *md++ = (unsigned char)(context->state[i] >> 24);
    *md++ = (unsigned char)(context->state[i] >> 16);
    *md++ = (unsigned char)(context->state[i] >> 8);
    *md++ = (unsigned char)(context->state[i]);
  }
  tc_sha256_init(context);
}

void* tc_sha256(const void* text, unsigned int tsize, unsigned char md[SHA256_DIGEST_LENGTH]) {
  if (text == NULL || tsize == 0)
    return NULL;

  int eof = 0;
  if (!md){
    md = tc_xmalloc(SHA256_DIGEST_LENGTH + 1);
    eof = 1;
  }

  SHA256_CTX context;
  tc_sha256_init(&context);
  tc_sha256_update(&context, text, tsize);
  tc_sha256_final(&context, md);

  if (eof)
    md[SHA256_DIGEST_LENGTH] = '\x00';
  return md;
}

static inline void xor_key(uint8_t key[SHA256_BLOCK_SIZE], uint32_t xor) {
  int i;
  for (i=0; i < SHA256_BLOCK_SIZE; i += sizeof(uint32_t)) {
    uint32_t * k = (uint32_t *)&key[i];
    *k ^= xor;
  }
}

void* tc_hmac_sha256(const void* key, unsigned int ksize, const void* text, unsigned int tsize, unsigned char md[SHA256_DIGEST_LENGTH]) {
  if (text == NULL || tsize == 0)
    return NULL; 

  int eof = 0;
  if (!md){
    md = tc_xmalloc(SHA256_DIGEST_LENGTH + 1);
    eof = 1;
  }

  uint8_t buf[SHA256_BLOCK_SIZE];
  memset(buf, 0x0, SHA256_BLOCK_SIZE);

  if (ksize > SHA256_BLOCK_SIZE) {
    tc_sha1(key, ksize, buf);
    ksize = SHA256_DIGEST_LENGTH;
  } else {
    memcpy(buf, key, ksize);
  }

  xor_key(buf, 0x5c5c5c5c);

  SHA256_CTX ctx1;
  tc_sha256_init(&ctx1);
  tc_sha256_update(&ctx1, buf, SHA256_BLOCK_SIZE);

  xor_key(buf, 0x5c5c5c5c ^ 0x36363636);

  SHA256_CTX ctx2;
  tc_sha256_init(&ctx2);
  tc_sha256_update(&ctx2, buf, SHA256_BLOCK_SIZE);
  tc_sha256_update(&ctx2, text, tsize);
  tc_sha256_final(&ctx2, md);

  tc_sha256_update(&ctx1, md, SHA256_DIGEST_LENGTH);
  tc_sha256_final(&ctx1, md);

  if (eof)
    md[SHA256_DIGEST_LENGTH] = '\x00';
  return md;
}