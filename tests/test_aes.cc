#include <tc.h>
#include <iostream>

int main(int argc, char const *argv[])
{
  uint8_t out[16]; memset(out, 0, 16);
  const uint8_t userKey_128[] = "0123456789abcdef";
  const uint8_t userKey_192[] = "0123456789abcdef01234567";

  AES_KEY key;
  AES_set_encrypt_key(userKey_192, AES_192, &key);
  AES_encrypt((const uint8_t *)"abcdef0123456789", out, &key);

  unsigned char aeshex[HEX_ENC_LENGTH(16)];
  hexencode(out, HEX_ENC_LENGTH(16), aeshex, tc_hex_lower);
  return 0;
}