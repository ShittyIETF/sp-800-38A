#include "AES/Global"
#include "ModeCBC"

#include "Galileo/Galileo"

#include <cstring>
using namespace std;

struct ModeCBCTest {
  // Test Data
  template <int KeySize>
  struct TestData {
    static Byte AES_key[];
    static Byte initializationVector[];
    static Byte AES_plaintext[];
    static Byte AES_ciphertext[];
  };

  template <int KeySize>
  static void AESEncryptionTest() {
    typename Cipher<KeySize>::CipherKey key;
    key.read(TestData<KeySize>::AES_key);

    Block iv;
    iv.read(TestData<KeySize>::initializationVector);
    ModeCBC<KeySize> m(key, iv);

    std::vector<Block> in;
    for (int i = 0; i < 4 ; ++i) {
      Block b;
      b.read(&TestData<KeySize>::AES_plaintext[i * 4 * Cipher<KeySize>::block_size]);
      in.push_back(b);
    }

    std::vector<Block> out(4);
    m.encrypt(in.begin(), in.end(), out.begin());

    Byte actualCiphertext[4 * 4 * Cipher<KeySize>::block_size];
    for (int i = 0; i < 4 ; ++i) {
      out[i].write(&actualCiphertext[i * 4 * Cipher<KeySize>::block_size]);
    }

    Galileo::assert("Expected Ciphertext == Actual Ciphertext",
                    memcmp(TestData<KeySize>::AES_ciphertext, actualCiphertext, 4 * 4 * Cipher<KeySize>::block_size) == 0);
  }

  template <int KeySize>
  static void AESDecryptionTest() {
    typename Cipher<KeySize>::CipherKey key;
    key.read(TestData<KeySize>::AES_key);

    Block iv;
    iv.read(TestData<KeySize>::initializationVector);
    ModeCBC<KeySize> m(key, iv);

    std::vector<Block> in;
    for (int i = 0; i < 4 ; ++i) {
      Block b;
      b.read(&TestData<KeySize>::AES_ciphertext[i * 4 * Cipher<KeySize>::block_size]);
      in.push_back(b);
    }

    std::vector<Block> out(4);
    m.decrypt(in.begin(), in.end(), out.begin());

    Byte actualPlaintext[4 * 4 * Cipher<KeySize>::block_size];
    for (int i = 0; i < 4 ; ++i) {
      out[i].write(&actualPlaintext[i * 4 * Cipher<KeySize>::block_size]);
    }

    Galileo::assert("Expected Plaintext == Actual Plaintext",
                    memcmp(TestData<KeySize>::AES_plaintext, actualPlaintext, 4 * 4 * Cipher<KeySize>::block_size) == 0);
  }
};

template<>
Byte ModeCBCTest::TestData<128>::AES_key[] = {
  0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7,
  0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
};

template<>
Byte ModeCBCTest::TestData<128>::initializationVector[] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
  0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};

template<>
Byte ModeCBCTest::TestData<128>::AES_plaintext[] = {
  0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d,
  0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57,
  0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf,
  0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
  0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f,
  0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b,
  0xe6, 0x6c, 0x37, 0x10,
};

template<>
Byte ModeCBCTest::TestData<128>::AES_ciphertext[] = {
  0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9,
  0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d, 0x50, 0x86, 0xcb, 0x9b,
  0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76,
  0x78, 0xb2, 0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b,
  0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16, 0x3f, 0xf1,
  0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09, 0x12, 0x0e, 0xca, 0x30,
  0x75, 0x86, 0xe1, 0xa7,
};

int main() {
  Galileo::test("AES128EncryptionTest", ModeCBCTest::AESEncryptionTest<128>);
  Galileo::test("AES128DecryptionTest", ModeCBCTest::AESDecryptionTest<128>);

  return Galileo::run("ModeCBC");
}