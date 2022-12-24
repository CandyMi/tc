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

  uint8_t uuid[16];
  unsigned int i;
  for (i = 0; i < 16; i++)
    uuid[i] = (rand() ^ (i % 16 + 1)) & 0xff;
  
  uuid[6] = (unsigned char)(0x40 | (uuid[6] & 0x0F));
  uuid[8] = (unsigned char)(0x80 | (uuid[8] & 0x3F));

  snprintf((char *)ubuf, UUID_V4_LENGTH + 1, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
    uuid[0], uuid[1],  uuid[2],  uuid[3],  uuid[4],  uuid[5],  uuid[6],  uuid[7],
    uuid[8], uuid[9], uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]
  );

  ubuf[UUID_V4_LENGTH] = '\x00';
  return 1;
}
