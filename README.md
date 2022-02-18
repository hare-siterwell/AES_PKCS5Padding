# AES
C++ AES128 ECB PKCS5Padding implementation  

# Usage
```c++
...
std::string key(KEY);
std::string plain(PLAIN);

cipher::AesEcbCipher aes(key);
auto cipher = aes.encode(plain);
...
```
