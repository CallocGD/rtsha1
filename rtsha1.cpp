#include "rtsha1.h"


/* Im using an abreviation (for now) since I don't feel like writing this shit out everytime... - Calloc */
typedef unsigned int u32;

void _transform_(u32 *digest, u32 *hash)

{
  u32 _f;
  u32 _digest;
  u32 *block;
  u32 _b;
  u32 _c;
  u32 _e;
  u32 _g;
  u32 _c;
  u32 _a;
  u32 _d;
  
  _a = digest[1];
  block = hash + -1;
  _b = digest[2];
  _digest = *digest;
  _c = digest[3];
  _d = digest[4];
  do {
    _c = _c;
    _g = _digest;
    _c = _b;
    block++;
    _b = _a >> 2 | _a << 0x1e;
    _digest = (_c & ~_a | _c & _a) + *block + 0x5a827999 + (_g >> 0x1b | _g << 5) + _d;
    _a = _g;
    _d = _c;
  } while (block != hash + 0xf);
  block = hash + -1;
  do {
    _e = _c;
    _c = _b;
    _d = _digest;
    block++;
    _b = block[9] ^ block[0xe] ^ block[3] ^ *block;
    _a = _b >> 0x1f | _b << 1;
    _b = _g >> 2 | _g << 0x1e;
    _digest = (_e & ~_g | _c & _g) + (_d >> 0x1b | _d << 5) + 0x5a827999 + _a + _e;
    block[0x11] = _a;
    _g = _d;
    block = block;
    _c = _e;
  } while (block != hash + 3);
  block = hash + 3;
  while (_g = _c, _a = _digest, block != hash + 0x17) {
    _digest = block[9] ^ block[0xe] ^ block[3] ^ block[1];
    _digest = _digest >> 0x1f | _digest << 1;
    block[0x11] = _digest;
    _c = _d >> 2;
    _f = _d << 0x1e;
    _digest = _e + 0x6ed9eba1 + (_a >> 0x1b | _a << 5) + (_b ^ _d ^ _g) + _digest;
    _d = _a;
    _c = _b;
    _e = _g;
    block = block + 1;
    _b = _c | _f;
  }
  block = hash + 0x17;
  while (_c = _g, _digest = _a, block != hash + 0x2b) {
    _a = block[9] ^ block[0xe] ^ block[3] ^ block[1];
    _a = _a >> 0x1f | _a << 1;
    block[0x11] = _a;
    _c = _d >> 2;
    _f = _d << 0x1e;
    _a = _e + 0x8f1bbcdc + (_digest >> 0x1b | _digest << 5) +
          ((_c | _b) & _d | _c & _b) + _a;
    _d = _digest;
    _g = _b;
    _e = _c;
    block = block + 1;
    _b = _c | _f;
  }
  block = hash + 0x2b;
  while (_g = _c, _a = _digest, block != hash + 0x3f) {
    _digest = block[9] ^ block[0xe] ^ block[3] ^ block[1];
    _digest = _digest >> 0x1f | _digest << 1;
    block[0x11] = _digest;
    _c = _d >> 2;
    _f = _d << 0x1e;
    _digest = _e + 0xca62c1d6 + (_a >> 0x1b | _a << 5) + (_b ^ _d ^ _g) + _digest;
    _d = _a;
    _c = _b;
    _e = _g;
    block = block + 1;
    _b = _c | _f;
  }
  *digest = _a + *digest;
  digest[1] = _d + digest[1];
  digest[2] = digest[2] + _b;
  digest[3] = digest[3] + _g;
  digest[4] = digest[4] + _e;
  return;
}






void rtsha1::calc(void const* password, int password_size, unsigned char* hash){
  int i, j, l, m;
  u32 k;
  unsigned int _hash[80];
  int digest[5];
  digest[0] = 0x67452301;
  digest[1] = 0xefcdab89;
  digest[2] = 0x98badcfe;
  digest[3] = 0x10325476;
  digest[4] = 0xc3d2e1f0;

  unsigned int* b;
        
  for (i = 0; i <= password_size - 0x40; i += 0x40){
      b = (unsigned int*)(password + i);
      for (j = 0; j != 0x10; j++){
          _hash[j] = b[3] | b[1] << 0x10 | b[2] << 8 | *b << 0x18;
          b += 4;
      }
      _transform_(_hash, digest);
  }

  k = password_size - i;

  /* clears the first 16 blocks apparently... */
  j = 0x10;
  while (j != 0) {
    _hash[j] = 0;
    j--;
  }

  for (m = 0; m < k; m++) {
    _hash[m >> 2] = ((i + password + m) << ((~m & 3) << 3) | _hash[m >> 2]);
  }
  m = k & ~((int)k >> 0x1f);
  i = m >> 2;
  _hash[i] = _hash[i] | 0x80 << ((~m & 3) << 3);
  if (0x37 < k) {
    _transform_(digest,_hash);
    i = 0x10;
    while (i != 0) {
      _hash[i] = 0;
      i--;
    }
  }
  _hash[15] = password_size << 3;
  _transform_(digest,_hash);
  i = 0x14;
  while (i != 0) {
      (hash + i) = (unsigned char)(digest[i >> 2] >> ((3U - i & 3) << 3));
      i--;
  }
}

void rtsha1::toHexString(const char unsigned *_in, char *out){
  const char* hex_numbers = "0123456789abcdef";
  unsigned char* a, *b, *c;
  int i = 0x14;
  unsigned char* x = _in + 0x13;
  while (i != 0) {
    out[i * 2] = ((int)hex_numbers + (u32)(*x >> 4));
    out[i * 2 + 1] = ((int)hex_numbers + (*x & 15));
    i--;
  }
  out[0x28] = '\0';
}

