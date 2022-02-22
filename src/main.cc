/**
 * @file main.cc
 * @brief Main program body
 */
#include "aes.h"
#include <iostream>

#define KEY "Tt5CPXUAUZ2kxn9S"
#define PLAIN R"({"productId": "TEST", "deviceName": "1000000001"})"

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
