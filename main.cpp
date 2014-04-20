#include <vector>

#include "AES/Global"

#include "ModeECB"

void print(Block a) {
  for (int r = 0; r < 4; ++r) {
    for (int c = 0; c < 4; ++c) {
      printf("%02x%c", a[c][r], c == 3 ? '\n' : ' ');
    }
  }
}

Byte ECB_AES128_key[] = {
  0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7,
  0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
};

int main() {

  Cipher<128>::CipherKey key;
  key.read(ECB_AES128_key);

  ModeECB m(key);

  std::vector<Block> a(10), b(10);
  a[0][0][0] = 5;
  print(a[0]);
  print(b[0]);
  m.encrypt(a.begin(), a.end(), b.begin());
  print(a[0]);
  print(b[0]);

  return 0;
}
