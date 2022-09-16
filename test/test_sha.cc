#include "tc.h"
#include <iostream>


int main(int argc, char const *argv[])
{
  if (argc < 2) {
    std::cout << __FILE__ << "need cipher name" << std::endl;
    exit(EXIT_FAILURE);
  }

  if (!strcmp("hmac_sha", argv[1]) && argv[2] && argv[3]) {
    // calc hmac_sha1
    unsigned char hmac_sha1_buf[SHA_DIGEST_LENGTH];
    HMAC_SHA1(argv[2], strlen(argv[2]), argv[3], strlen(argv[3]), hmac_sha1_buf);
    // to hexencode
    unsigned char sha1hex[HEX_ENC_LENGTH(SHA_DIGEST_LENGTH)];
    hexencode(hmac_sha1_buf, SHA_DIGEST_LENGTH, sha1hex, 0);
    std::cout << "hmac_sha1: " << sha1hex << std::endl;
    return 0;
  }

  if (!strcmp("sha", argv[1]) && argv[2]) {
    // calc sha1
    unsigned char sha1_buf[SHA_DIGEST_LENGTH];
    SHA1(argv[2], strlen(argv[2]), sha1_buf);
    // to hexencode
    unsigned char sha1hex[HEX_ENC_LENGTH(SHA_DIGEST_LENGTH)];
    hexencode(sha1_buf, SHA_DIGEST_LENGTH, sha1hex, 0);
    std::cout << "sha1: " << sha1hex << std::endl;
    return 0;
  }

  std::cout << __FILE__ << ": Invalid args." << std::endl;
  exit(EXIT_FAILURE);
}
