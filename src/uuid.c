/*
**  LICENSE: BSD
**  Author: CandyMi[https://github.com/candymi]
*/
#include <tc.h>
#include <stdio.h>
#include <time.h>

#ifdef _WIN32
  #include <process.h>
  #define getpid    _getpid
#else
  #include <unistd.h>
#endif

/* Cuban prime */
#define prime1 (0xf9cd)
#define prime2 (0xec4d)

static int rand_init = 0;

void rinit () {
  rand_init = 1;
  srand(getpid() ^ ((uint32_t)time(NULL) << 16) ^ (rand() << 8));
}

int tc_randomkey(unsigned char *rbuf, unsigned int rsize) {
  if (rbuf == NULL || rsize < RKEY_MIN_LENGTH)
    return 0;
  if (!rand_init)
    rinit();
  unsigned int i, j;
  char tmp1[RKEY_MIN_LENGTH]; char tmp2[RKEY_MIN_LENGTH];
  for (j = 0; j < RKEY_MIN_LENGTH; j++) {
    tmp1[j] = (rand() ^ prime1) & 0xff;
    tmp2[j] = (rand() ^ prime2) & 0xff;
  }
  for (i = 0; i < rsize; i++)
    rbuf[i] = (tmp1[i % RKEY_MIN_LENGTH] ^ tmp2[i % RKEY_MIN_LENGTH]) & 0xff;
  return 1;
}

int tc_uuid_v4(unsigned char *ubuf) {
  if (ubuf == NULL)
    return 0;
  if (!rand_init)
    rinit();
  union {
    struct {
      uint32_t time_low;
      uint16_t time_mid;
      uint16_t time_hi_and_version;
      uint8_t  clk_seq_hi_res;
      uint8_t  clk_seq_low;
      uint8_t  node[6];
    };
    uint8_t __rnd[16];
  } uuid;

  int i = 0;
  for (i = 0; i < 16; i++)
    uuid.__rnd[i] = (rand() ^ i) & 0xff;

  uuid.clk_seq_hi_res = (uint8_t) ((uuid.clk_seq_hi_res & 0x3f) | 0x80);
  uuid.time_hi_and_version = (uint16_t) ((uuid.time_hi_and_version & 0x0fff) | 0x4000);

  snprintf((char *)ubuf, UUID_V4_LENGTH, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
    uuid.time_low, uuid.time_mid, uuid.time_hi_and_version,
    uuid.clk_seq_hi_res, uuid.clk_seq_low,
    uuid.node[0], uuid.node[1], uuid.node[2],
    uuid.node[3], uuid.node[4], uuid.node[5]
  );

  ubuf[UUID_V4_LENGTH] = '\x00';
  return 1;
}