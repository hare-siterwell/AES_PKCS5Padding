#include "aes.h"

namespace cipher {

const uint8_t AesEcbCipher::kSbox[] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16};

const uint8_t AesEcbCipher::kRsbox[] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e,
    0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32,
    0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49,
    0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50,
    0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05,
    0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41,
    0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8,
    0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b,
    0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59,
    0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d,
    0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63,
    0x55, 0x21, 0x0c, 0x7d};

const uint8_t AesEcbCipher::kRcon[] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c,
    0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a,
    0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
    0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
    0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
    0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6,
    0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72,
    0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
    0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10,
    0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e,
    0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5,
    0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
    0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02,
    0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d,
    0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d,
    0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
    0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb,
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c,
    0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a,
    0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
    0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
    0x74, 0xe8, 0xcb};

const char *AesEcbCipher::kBase64Table[2] = {"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                             "abcdefghijklmnopqrstuvwxyz"
                                             "0123456789"
                                             "+/",
                                             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                             "abcdefghijklmnopqrstuvwxyz"
                                             "0123456789"
                                             "-_"};

const uint32_t AesEcbCipher::kNr = 10;
const uint32_t AesEcbCipher::kNb = 4;
const uint32_t AesEcbCipher::kNk = 4;
const uint32_t AesEcbCipher::kKeyLen = 16;

auto AesEcbCipher::get_sbox_value(uint8_t num) -> uint8_t { return kSbox[num]; }

auto AesEcbCipher::get_sbox_invert(uint8_t num) -> uint8_t {
  return kRsbox[num];
}

auto AesEcbCipher::xtime(uint8_t x) -> uint8_t {
  return ((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

auto AesEcbCipher::multiply(uint8_t x, uint8_t y) -> uint8_t {
  return (((y & 1) * x) ^ ((y >> 1 & 1) * xtime(x)) ^
          ((y >> 2 & 1) * xtime(xtime(x))) ^
          ((y >> 3 & 1) * xtime(xtime(xtime(x)))) ^
          ((y >> 4 & 1) * xtime(xtime(xtime(xtime(x))))));
}

auto AesEcbCipher::AddRoundKey(uint8_t round) -> void {
  for (auto i = 0; i < 4; ++i) {
    for (auto j = 0; j < 4; ++j) {
      (*state_)[j][i] ^= round_key_[round * kNb * 4 + i * kNb + j];
    }
  }
}

auto AesEcbCipher::InvAddRoundKey(uint8_t round) -> void {
  for (auto i = 0; i < 4; ++i) {
    for (auto j = 0; j < 4; ++j) {
      (*state_)[i][j] ^= round_key_[round * kNb * 4 + i * kNb + j];
    }
  }
}

auto AesEcbCipher::KeyExpansion() -> void {
  auto i = 0;
  uint8_t temp[4];

  memset(round_key_, 0, sizeof(round_key_));

  // The first round key is the key itself.
  for (i = 0; i < kNk; ++i) {
    round_key_[i * 4 + 0] = key_[i * 4 + 0];
    round_key_[i * 4 + 1] = key_[i * 4 + 1];
    round_key_[i * 4 + 2] = key_[i * 4 + 2];
    round_key_[i * 4 + 3] = key_[i * 4 + 3];
  }

  // All other round keys are found from the previous round keys.
  while (i < (kNb * (kNr + 1))) {
    for (auto j = 0; j < 4; ++j) {
      temp[j] = round_key_[(i - 1) * 4 + j];
    }
    if (i % kNk == 0) {
      // This function rotates the 4 bytes in a word to the left once.
      // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]

      // Function RotWord()
      {
        auto k = temp[0];
        temp[0] = temp[1];
        temp[1] = temp[2];
        temp[2] = temp[3];
        temp[3] = k;
      }

      // SubWord() is a function that takes a four-byte input word and
      // applies the S-box to each of the four bytes to produce an output word.

      // Function Subword()
      {
        temp[0] = get_sbox_value(temp[0]);
        temp[1] = get_sbox_value(temp[1]);
        temp[2] = get_sbox_value(temp[2]);
        temp[3] = get_sbox_value(temp[3]);
      }

      temp[0] = temp[0] ^ kRcon[i / kNk];
    } else if (kNk > 6 && i % kNk == 4) {
      // Function Subword()
      {
        temp[0] = get_sbox_value(temp[0]);
        temp[1] = get_sbox_value(temp[1]);
        temp[2] = get_sbox_value(temp[2]);
        temp[3] = get_sbox_value(temp[3]);
      }
    }
    round_key_[i * 4 + 0] = round_key_[(i - kNk) * 4 + 0] ^ temp[0];
    round_key_[i * 4 + 1] = round_key_[(i - kNk) * 4 + 1] ^ temp[1];
    round_key_[i * 4 + 2] = round_key_[(i - kNk) * 4 + 2] ^ temp[2];
    round_key_[i * 4 + 3] = round_key_[(i - kNk) * 4 + 3] ^ temp[3];
    ++i;
  }
}

auto AesEcbCipher::encode(const std::string &plain) -> std::string {
  if (plain.empty()) {
    return {};
  }

  uint32_t encode_buf_size = plain.length();
  uint8_t encode_buf[encode_buf_size];
  memcpy(encode_buf,
         reinterpret_cast<uint8_t *>(const_cast<char *>(plain.c_str())),
         encode_buf_size);

  // input been padded well with pkcs5padding
  auto pading_size =
      AesEcbCipher::kKeyLen - encode_buf_size % AesEcbCipher::kKeyLen;
  // PKCS5Padding rules: ²¹(16-len)¸ö(16-len)
  for (auto pading = 0; pading < pading_size; ++pading) {
    encode_buf[encode_buf_size + pading] = pading_size;
  }
  encode_buf_size += pading_size;
  uint8_t dest[encode_buf_size];

  const auto *iv = key_;
  for (auto i = 0; i < encode_buf_size / AesEcbCipher::kKeyLen; ++i) {
    Aes128EcbEncrypt(encode_buf +
                         static_cast<size_t>(i * AesEcbCipher::kKeyLen),
                     dest + static_cast<size_t>(i * AesEcbCipher::kKeyLen));
    if (use_cbc) {
      for (auto j = 0; j < AesEcbCipher::kKeyLen; ++j) {
        (dest + static_cast<size_t>(i * AesEcbCipher::kKeyLen))[j] ^= iv[j];
      }
      iv = encode_buf + static_cast<size_t>(i * AesEcbCipher::kKeyLen);
    }
  }
  dest[encode_buf_size] = 0;

  auto ret = Base64Encrypt(dest, encode_buf_size);
  return ret;
}

auto AesEcbCipher::decode(const std::string &cipher) -> std::string {
  if (cipher.empty()) {
    return {};
  }

  auto original = Base64Decrypt(cipher, true);

  uint32_t decode_buf_size = original.length();
  // assume input has been padded well with pkcs5padding
  if (decode_buf_size % AesEcbCipher::kKeyLen != 0) {
    std::cout << "AesEcbCipher::decode, src len has to be divided by 16!"
              << std::endl;
    return {};
  }

  uint8_t dest[decode_buf_size];
  uint8_t decode_buf[decode_buf_size];
  memcpy(decode_buf,
         reinterpret_cast<uint8_t *>(const_cast<char *>(original.c_str())),
         decode_buf_size);

  const auto *iv = key_;
  for (auto i = 0; i < decode_buf_size / AesEcbCipher::kKeyLen; ++i) {
    Aes128EcbDecrypt(decode_buf +
                         static_cast<size_t>(i * AesEcbCipher::kKeyLen),
                     dest + static_cast<size_t>(i * AesEcbCipher::kKeyLen));
    if (use_cbc) {
      for (auto j = 0; j < AesEcbCipher::kKeyLen; ++j) {
        (dest + static_cast<size_t>(i * AesEcbCipher::kKeyLen))[j] ^= iv[j];
      }
      iv = decode_buf + static_cast<size_t>(i * AesEcbCipher::kKeyLen);
    }
  }

  // unpad with pkcs5, remove unused charactors
  auto lastASIIC = static_cast<uint8_t>(dest[decode_buf_size - 1]);
  dest[decode_buf_size - lastASIIC] = 0;

  auto ret = std::string(reinterpret_cast<char *>(dest));
  return ret;
}

auto AesEcbCipher::MixColumns() -> void {
  for (auto i = 0; i < 4; ++i) {
    auto t = (*state_)[0][i];
    auto Tmp =
        (*state_)[0][i] ^ (*state_)[1][i] ^ (*state_)[2][i] ^ (*state_)[3][i];
    auto Tm = (*state_)[0][i] ^ (*state_)[1][i];
    Tm = xtime(Tm);
    (*state_)[0][i] ^= Tm ^ Tmp;
    Tm = (*state_)[1][i] ^ (*state_)[2][i];
    Tm = xtime(Tm);
    (*state_)[1][i] ^= Tm ^ Tmp;
    Tm = (*state_)[2][i] ^ (*state_)[3][i];
    Tm = xtime(Tm);
    (*state_)[2][i] ^= Tm ^ Tmp;
    Tm = (*state_)[3][i] ^ t;
    Tm = xtime(Tm);
    (*state_)[3][i] ^= Tm ^ Tmp;
  }
}

auto AesEcbCipher::SubBytes() -> void {
  for (auto i = 0; i < 4; ++i) {
    for (auto j = 0; j < 4; ++j) {
      (*state_)[i][j] = get_sbox_value((*state_)[i][j]);
    }
  }
}

auto AesEcbCipher::ShiftRows() -> void {
  // Rotate first row 1 columns to left
  auto temp = (*state_)[1][0];
  (*state_)[1][0] = (*state_)[1][1];
  (*state_)[1][1] = (*state_)[1][2];
  (*state_)[1][2] = (*state_)[1][3];
  (*state_)[1][3] = temp;

  // Rotate second row 2 columns to left
  temp = (*state_)[2][0];
  (*state_)[2][0] = (*state_)[2][2];
  (*state_)[2][2] = temp;
  temp = (*state_)[2][1];
  (*state_)[2][1] = (*state_)[2][3];
  (*state_)[2][3] = temp;

  // Rotate third row 3 columns to left
  temp = (*state_)[3][0];
  (*state_)[3][0] = (*state_)[3][3];
  (*state_)[3][3] = (*state_)[3][2];
  (*state_)[3][2] = (*state_)[3][1];
  (*state_)[3][1] = temp;
}

auto AesEcbCipher::Cipher() -> void {
  // Add the First round key to the state before starting the rounds.
  AddRoundKey(0);

  // There will be kNr rounds.
  // The first kNr-1 rounds are identical.
  // These kNr-1 rounds are executed in the loop below.
  for (auto round = 1; round < kNr; round++) {
    SubBytes();
    ShiftRows();
    MixColumns();
    AddRoundKey(round);
  }

  // The last round is given below.
  // The MixColumns function is not here in the last round.
  SubBytes();
  ShiftRows();
  AddRoundKey(kNr);
}

auto AesEcbCipher::Aes128EcbEncrypt(const uint8_t *input, uint8_t *output)
    -> void {
  memcpy(output, input, AesEcbCipher::kKeyLen);
  state_ = reinterpret_cast<state_t *>(output);

  state_t state;
  state_ = &state;

  for (auto i = 0; i < 4; ++i) {
    for (auto j = 0; j < 4; ++j) {
      (*state_)[j][i] = input[i * 4 + j];
    }
  }

  KeyExpansion();
  Cipher();

  for (auto i = 0; i < 4; ++i) {
    for (auto j = 0; j < 4; ++j) {
      output[i * 4 + j] = (*state_)[j][i];
    }
  }
}

auto AesEcbCipher::InvMixColumns() -> void {
  for (uint32_t i = 0; i < 4; ++i) {
    auto a = (*state_)[i][0];
    auto b = (*state_)[i][1];
    auto c = (*state_)[i][2];
    auto d = (*state_)[i][3];

    (*state_)[i][0] = multiply(a, 0x0e) ^ multiply(b, 0x0b) ^
                      multiply(c, 0x0d) ^ multiply(d, 0x09);
    (*state_)[i][1] = multiply(a, 0x09) ^ multiply(b, 0x0e) ^
                      multiply(c, 0x0b) ^ multiply(d, 0x0d);
    (*state_)[i][2] = multiply(a, 0x0d) ^ multiply(b, 0x09) ^
                      multiply(c, 0x0e) ^ multiply(d, 0x0b);
    (*state_)[i][3] = multiply(a, 0x0b) ^ multiply(b, 0x0d) ^
                      multiply(c, 0x09) ^ multiply(d, 0x0e);
  }
}

auto AesEcbCipher::InvSubBytes() -> void {
  for (auto i = 0; i < 4; ++i) {
    for (auto j = 0; j < 4; ++j) {
      (*state_)[j][i] = get_sbox_invert((*state_)[j][i]);
    }
  }
}

auto AesEcbCipher::InvShiftRows() -> void {
  // Rotate first row 1 columns to right
  auto temp = (*state_)[3][1];
  (*state_)[3][1] = (*state_)[2][1];
  (*state_)[2][1] = (*state_)[1][1];
  (*state_)[1][1] = (*state_)[0][1];
  (*state_)[0][1] = temp;

  // Rotate second row 2 columns to right
  temp = (*state_)[0][2];
  (*state_)[0][2] = (*state_)[2][2];
  (*state_)[2][2] = temp;

  temp = (*state_)[1][2];
  (*state_)[1][2] = (*state_)[3][2];
  (*state_)[3][2] = temp;

  // Rotate third row 3 columns to right
  temp = (*state_)[0][3];
  (*state_)[0][3] = (*state_)[1][3];
  (*state_)[1][3] = (*state_)[2][3];
  (*state_)[2][3] = (*state_)[3][3];
  (*state_)[3][3] = temp;
}

auto AesEcbCipher::InvCipher() -> void {
  InvAddRoundKey(kNr);

  for (auto round = kNr - 1; round > 0; round--) {
    InvShiftRows();
    InvSubBytes();
    InvAddRoundKey(round);
    InvMixColumns();
  }

  InvShiftRows();
  InvSubBytes();
  InvAddRoundKey(0);
}

auto AesEcbCipher::Aes128EcbDecrypt(const uint8_t *input, uint8_t *output)
    -> void {
  memcpy(output, input, AesEcbCipher::kKeyLen);
  state_ = reinterpret_cast<state_t *>(output);

  KeyExpansion();
  InvCipher();
}

auto AesEcbCipher::Base64Encrypt(const uint8_t *in, uint32_t in_len, bool url)
    -> std::string {
  auto trailing_char = url ? '.' : '=';
  const auto *base64_chars_ = kBase64Table[url];
  std::string ret{};

  for (auto pos = 0; pos < in_len; pos += 3) {
    ret.push_back(base64_chars_[(in[pos + 0] & 0xfc) >> 2]);

    if (pos + 1 < in_len) {
      ret.push_back(base64_chars_[((in[pos + 0] & 0x03) << 4) +
                                  ((in[pos + 1] & 0xf0) >> 4)]);
      if (pos + 2 < in_len) {
        ret.push_back(base64_chars_[((in[pos + 1] & 0x0f) << 2) +
                                    ((in[pos + 2] & 0xc0) >> 6)]);
        ret.push_back(base64_chars_[in[pos + 2] & 0x3f]);
      } else {
        ret.push_back(base64_chars_[(in[pos + 1] & 0x0f) << 2]);
        ret.push_back(static_cast<char>(trailing_char));
      }
    } else {
      ret.push_back(base64_chars_[(in[pos + 0] & 0x03) << 4]);
      ret.push_back(static_cast<char>(trailing_char));
      ret.push_back(static_cast<char>(trailing_char));
    }
  }

  // Line length is 76 characters
  for (auto pos = 76; pos < ret.size(); pos += 78) {
    ret.insert(pos, "\r\n");
  }

  return ret;
}

auto AesEcbCipher::pos_of_char(const uint8_t &chr) -> uint32_t {
  auto ret = 0;

  if (chr >= 'A' && chr <= 'Z') {
    ret = chr - 'A';
  } else if (chr >= 'a' && chr <= 'z') {
    ret = chr - 'a' + ('Z' - 'A') + 1;
  } else if (chr >= '0' && chr <= '9') {
    ret = chr - '0' + ('Z' - 'A') + ('z' - 'a') + 2;
  } else if (chr == '+' || chr == '-') {
    ret = 62;
  } else if (chr == '/' || chr == '_') {
    ret = 63;
  } else {
    throw std::runtime_error("Input is not valid base64-encoded data.");
  }

  return ret;
}

auto AesEcbCipher::Base64Decrypt(std::string encoded_string,
                                 bool remove_linebreaks) -> std::string {
  if (remove_linebreaks) {
    encoded_string.erase(
        std::remove(encoded_string.begin(), encoded_string.end(), '\r'),
        encoded_string.end());
    encoded_string.erase(
        std::remove(encoded_string.begin(), encoded_string.end(), '\n'),
        encoded_string.end());
  }

  auto length_of_string = encoded_string.length();
  std::string ret{};

  for (auto pos = 0; pos < length_of_string; pos += 4) {
    auto pos_of_char_1 = pos_of_char(encoded_string[pos + 1]);

    ret.push_back(static_cast<std::string::value_type>(
        ((pos_of_char(encoded_string[pos + 0])) << 2) +
        ((pos_of_char_1 & 0x30) >> 4)));

    if ((pos + 2 < length_of_string) && encoded_string[pos + 2] != '=' &&
        encoded_string[pos + 2] != '.') {

      auto pos_of_char_2 = pos_of_char(encoded_string[pos + 2]);
      ret.push_back(static_cast<std::string::value_type>(
          ((pos_of_char_1 & 0x0f) << 4) + ((pos_of_char_2 & 0x3c) >> 2)));

      if ((pos + 3 < length_of_string) && encoded_string[pos + 3] != '=' &&
          encoded_string[pos + 3] != '.') {

        ret.push_back(static_cast<std::string::value_type>(
            ((pos_of_char_2 & 0x03) << 6) +
            pos_of_char(encoded_string[pos + 3])));
      }
    }
  }

  return ret;
}

} // namespace cipher
