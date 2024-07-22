#include "tc.h"
#include <iostream>


int main(int argc, char const *argv[])
{
  if (argc < 2) {
    std::cout << __FILE__ << ": need cipher name" << std::endl;
    exit(EXIT_FAILURE);
  }

  if (!strcmp("crc32", argv[1]) && argv[2]) {
    std::cout << "crc32: " << crc32(argv[2], strlen(argv[2])) << std::endl;
    return 0;
  }

  if (!strcmp("adler32", argv[1]) && argv[2]) {
    std::cout << "adler32: " << adler32(argv[2], strlen(argv[2])) << std::endl;
    return 0;
  }

  std::cout << __FILE__ << "Invalid args." << std::endl;
  exit(EXIT_FAILURE);
}
