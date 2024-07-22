#include <tc.h>
#include <iostream>

int main(int argc, char const *argv[])
{

  uint8_t out[16]; memset(out, 0, 16);
  RC4_KEY KEY;
  RC4(&KEY, 16, "abcdef0123456789", out);

  unsigned char aeshex[HEX_ENC_LENGTH(16)];
  hexencode(out, HEX_ENC_LENGTH(16), aeshex, tc_hex_lower);
  return 0;
}