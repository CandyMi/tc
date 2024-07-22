#include "tc.h"
#include <iostream>


int main(int argc, char const *argv[])
{
  if (argc < 2) {
    std::cout << __FILE__ << ": need cipher name" << std::endl;
    exit(EXIT_FAILURE);
  }

  if (!strcmp("hmac_md5", argv[1]) && argv[2] && argv[3]) {
    // calc hmac_md5
    unsigned char hmac_md5_buf[MD5_DIGEST_LENGTH];
    HMAC_MD5(argv[2], strlen(argv[2]), argv[3], strlen(argv[3]), hmac_md5_buf);
    // to hexencode
    unsigned char md5hex[HEX_ENC_LENGTH(MD5_DIGEST_LENGTH)];
    hexencode(hmac_md5_buf, MD5_DIGEST_LENGTH, md5hex, tc_hex_lower);
    std::cout << "hmac_md5: " << md5hex << std::endl;
    return 0;
  }

  if (!strcmp("md5", argv[1]) && argv[2]) {
    // calc md5
    unsigned char md5_buf[MD5_DIGEST_LENGTH];
    MD5(argv[2], strlen(argv[2]), md5_buf);
    // to hexencode
    unsigned char md5hex[HEX_ENC_LENGTH(MD5_DIGEST_LENGTH)];
    hexencode(md5_buf, MD5_DIGEST_LENGTH, md5hex, tc_hex_lower);
    std::cout << "md5: " << md5hex << std::endl;
    return 0;
  }

  std::cout << __FILE__ << ": Invalid args." << std::endl;
  exit(EXIT_FAILURE);
}
