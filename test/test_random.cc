#include "tc.h"
#include <iostream>


int main(int argc, char const *argv[])
{
  if (argc < 2) {
    std::cout << __FILE__ << ": need cipher name" << std::endl;
    exit(EXIT_FAILURE);
  }

  if (!strcmp("uuid", argv[1])) {
    unsigned char id[UUID_V4_LENGTH + 1];
    uuid_v4(id);
    std::cout << "uuid: " << id << std::endl;
    return 0;
  }

  if (!strcmp("randomkey", argv[1])) {
    unsigned char rkey[RKEY_MIN_LENGTH];
    randomkey(rkey, RKEY_MIN_LENGTH);

    unsigned char rkey_hex[HEX_ENC_LENGTH(MD5_DIGEST_LENGTH)];
    hexencode(rkey, RKEY_MIN_LENGTH, rkey_hex, 0);
    std::cout << "randomkey: " << rkey_hex << std::endl;
    return 0;
  }

  std::cout << __FILE__ << ": Invalid args." << std::endl;
  exit(EXIT_FAILURE);
}
