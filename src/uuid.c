/*
**  LICENSE: BSD
**  Author: CandyMi[https://github.com/candymi]
*/
#include <tc.h>
#include <stdio.h>
#include <stdbool.h>

int tc_uuid_v4(unsigned char *ubuf) {
  if (ubuf == NULL)
    return 0;

  uint8_t uuid[16];
  unsigned int i;
  for (i = 0; i < 16; i++)
    uuid[i] = (tc_random_next() ^ (i % 16 + 1)) & 0xff;
  
  uuid[6] = (unsigned char)(0x40 | (uuid[6] & 0x0F));
  uuid[8] = (unsigned char)(0x80 | (uuid[8] & 0x3F));

  snprintf((char *)ubuf, UUID_V4_LENGTH + 1, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
    uuid[0], uuid[1],  uuid[2],  uuid[3],  uuid[4],  uuid[5],  uuid[6],  uuid[7],
    uuid[8], uuid[9], uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]
  );

  return 1;
}

static const char nanoid_alphabet[] = "_-0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

int tc_nanoid(const char *alphabet, unsigned char *rbuf, unsigned int *rsize) {
  if (!rbuf || !rsize || !*rbuf)
    return 0;

  if (alphabet == NULL)
    alphabet = nanoid_alphabet;
  size_t tsize = strlen(alphabet);

  for (size_t i = 0; i < *rsize; i++)
    rbuf[i] = alphabet[tc_random_next() % tsize];

  return 1;
}

static const char B32_INDEX[] = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

int tc_ulid(unsigned char ulid_buf[26]) {
  if (!ulid_buf)
    return 0;

  char ulid_tmp[16];

  uint64_t nt; tc_time_millisecond(&nt);

  ulid_tmp[0] = nt >> 40 & 0xff; ulid_tmp[1] = nt >> 32 & 0xff;
  ulid_tmp[2] = nt >> 24 & 0xff; ulid_tmp[3] = nt >> 16 & 0xff;
  ulid_tmp[4] = nt >>  8 & 0xff; ulid_tmp[5] = nt >>  0 & 0xff;

  /* 80 bit random bit */
  ulid_tmp[6]  = tc_random_next() & 0xff;  ulid_tmp[7]  = tc_random_next() & 0xff;
  ulid_tmp[8]  = tc_random_next() & 0xff;  ulid_tmp[9]  = tc_random_next() & 0xff;
  ulid_tmp[10] = tc_random_next() & 0xff;  ulid_tmp[11] = tc_random_next() & 0xff;
  ulid_tmp[12] = tc_random_next() & 0xff;  ulid_tmp[13] = tc_random_next() & 0xff;
  ulid_tmp[14] = tc_random_next() & 0xff;  ulid_tmp[15] = tc_random_next() & 0xff;

  /* base32 encode */
  ulid_buf[0] = B32_INDEX[(ulid_tmp[0] & 224) >> 5];
  ulid_buf[1] = B32_INDEX[ulid_tmp[0] & 31];
  ulid_buf[2] = B32_INDEX[(ulid_tmp[1] & 248) >> 3];
  ulid_buf[3] = B32_INDEX[((ulid_tmp[1] & 7) << 2) | ((ulid_tmp[2] & 192) >> 6)];
  ulid_buf[4] = B32_INDEX[(ulid_tmp[2] & 62) >> 1];
  ulid_buf[5] = B32_INDEX[((ulid_tmp[2] & 1) << 4) | ((ulid_tmp[3] & 240) >> 4)];
  ulid_buf[6] = B32_INDEX[((ulid_tmp[3] & 15) << 1) | ((ulid_tmp[4] & 128) >> 7)];
  ulid_buf[7] = B32_INDEX[(ulid_tmp[4] & 124) >> 2];
  ulid_buf[8] = B32_INDEX[((ulid_tmp[4] & 3) << 3) | ((ulid_tmp[5] & 224) >> 5)];
  ulid_buf[9] = B32_INDEX[ulid_tmp[5] & 31];

  ulid_buf[10] = B32_INDEX[(ulid_tmp[6] & 248) >> 3];
  ulid_buf[11] = B32_INDEX[((ulid_tmp[6] & 7) << 2) | ((ulid_tmp[7] & 192) >> 6)];
  ulid_buf[12] = B32_INDEX[(ulid_tmp[7] & 62) >> 1];
  ulid_buf[13] = B32_INDEX[((ulid_tmp[7] & 1) << 4) | ((ulid_tmp[8] & 240) >> 4)];
  ulid_buf[14] = B32_INDEX[((ulid_tmp[8] & 15) << 1) | ((ulid_tmp[9] & 128) >> 7)];
  ulid_buf[15] = B32_INDEX[(ulid_tmp[9] & 124) >> 2];
  ulid_buf[16] = B32_INDEX[((ulid_tmp[9] & 3) << 3) | ((ulid_tmp[10] & 224) >> 5)];
  ulid_buf[17] = B32_INDEX[ulid_tmp[10] & 31];
  ulid_buf[18] = B32_INDEX[(ulid_tmp[11] & 248) >> 3];
  ulid_buf[19] = B32_INDEX[((ulid_tmp[11] & 7) << 2) | ((ulid_tmp[12] & 192) >> 6)];
  ulid_buf[20] = B32_INDEX[(ulid_tmp[12] & 62) >> 1];
  ulid_buf[21] = B32_INDEX[((ulid_tmp[12] & 1) << 4) | ((ulid_tmp[13] & 240) >> 4)];
  ulid_buf[22] = B32_INDEX[((ulid_tmp[13] & 15) << 1) | ((ulid_tmp[14] & 128) >> 7)];
  ulid_buf[23] = B32_INDEX[(ulid_tmp[14] & 124) >> 2];
  ulid_buf[24] = B32_INDEX[((ulid_tmp[14] & 3) << 3) | ((ulid_tmp[15] & 224) >> 5)];
  ulid_buf[25] = B32_INDEX[ulid_tmp[15] & 31];

  return 1;
}
