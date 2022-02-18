#ifndef AES_H_
#define AES_H_

#include <algorithm>
#include <cstring>
#include <iostream>

#define MAX_BUF_LEN 1024

namespace cipher {

class AesEcbCipher {
public:
  explicit AesEcbCipher(const std::string &key, bool use_cbc = false)
      : key_(reinterpret_cast<uint8_t *>(const_cast<char *>(key.c_str()))),
        state_(nullptr), use_cbc(use_cbc){};

  auto encode(const std::string &plain) -> std::string;
  auto decode(const std::string &cipher) -> std::string;

private:
  using state_t = uint8_t[4][4];
  uint8_t round_key_[240];
  const uint8_t *key_;
  state_t *state_;
  bool use_cbc;
  static const uint8_t kSbox[256];
  static const uint8_t kRsbox[256];
  static const uint8_t kRcon[255];
  static const char *kBase64Table[2];
  static const uint32_t kKeyLen;
  static const uint32_t kNr;
  static const uint32_t kNb;
  static const uint32_t kNk;

  static inline auto get_sbox_value(uint8_t num) -> uint8_t;
  static inline auto get_sbox_invert(uint8_t num) -> uint8_t;
  static inline auto xtime(uint8_t x) -> uint8_t;
  static inline auto multiply(uint8_t x, uint8_t y) -> uint8_t;

  auto AddRoundKey(uint8_t round) -> void;
  auto InvAddRoundKey(uint8_t round) -> void;
  auto KeyExpansion() -> void;

  auto MixColumns() -> void;
  auto SubBytes() -> void;
  auto ShiftRows() -> void;
  auto Cipher() -> void;
  auto Aes128EcbEncrypt(const uint8_t *input, uint8_t *out) -> void;

  auto InvMixColumns() -> void;
  auto InvSubBytes() -> void;
  auto InvShiftRows() -> void;
  auto InvCipher() -> void;
  auto Aes128EcbDecrypt(const uint8_t *input, uint8_t *out) -> void;

  auto pos_of_char(const uint8_t &chr) -> uint32_t;
  auto Base64Encrypt(const uint8_t *in, uint32_t in_len, bool url = false)
      -> std::string;
  auto Base64Decrypt(std::string encoded_string) -> std::string;
};

} // namespace cipher

#endif
