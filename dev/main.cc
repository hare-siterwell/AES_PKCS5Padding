/**
 * @file main.cc
 * @brief Main program body
 */
#include "aes.h"

#define KEY "NULL"
#define PLAIN R"({})"

/**
 * @brief Example program
 * @return int
 */
auto main() -> int {
  std::string key(KEY);
  std::string plain(PLAIN);

  cipher::AesEcbCipher aes(key);
  auto cipher = aes.encode(plain);

  std::cout << cipher << std::endl;
  std::cout << aes.decode(cipher) << std::endl;
}
