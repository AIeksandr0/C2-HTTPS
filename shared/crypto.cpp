#include "crypto.h"

#include <cstdio>
#include <cstring>
#include <stdexcept>

#if defined(_WIN32)
#include <bcrypt.h>
#include <windows.h>

#pragma comment(lib, "bcrypt.lib")
#endif

namespace crypto {
namespace {

using u8 = uint8_t;
using u32 = uint32_t;
using u64 = uint64_t;

void random_bytes(u8 *out, size_t n) {
#if defined(_WIN32)
  if (BCryptGenRandom(nullptr, out, static_cast<ULONG>(n),
                      BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
    throw std::runtime_error("rand");
#else
  FILE *f = fopen("/dev/urandom", "rb");
  if (!f || fread(out, 1, n, f) != n) {
    if (f)
      fclose(f);
    throw std::runtime_error("rand");
  }
  fclose(f);
#endif
}

// ---------------------------------------------------------------- SHA-256
struct Sha256 {
  u32 h[8];
  u64 len;
  u8 buf[64];
  size_t fill;

  static u32 ror(u32 x, int n) { return (x >> n) | (x << (32 - n)); }

  void init() {
    static const u32 iv[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                              0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    std::memcpy(h, iv, sizeof(iv));
    len = 0;
    fill = 0;
  }

  void block(const u8 *p) {
    static const u32 k[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
        0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
        0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
        0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
        0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
    u32 w[64];
    for (int i = 0; i < 16; ++i)
      w[i] = (u32(p[i * 4]) << 24) | (u32(p[i * 4 + 1]) << 16) |
             (u32(p[i * 4 + 2]) << 8) | u32(p[i * 4 + 3]);
    for (int i = 16; i < 64; ++i) {
      u32 s0 = ror(w[i - 15], 7) ^ ror(w[i - 15], 18) ^ (w[i - 15] >> 3);
      u32 s1 = ror(w[i - 2], 17) ^ ror(w[i - 2], 19) ^ (w[i - 2] >> 10);
      w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    u32 a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6],
        hh = h[7];
    for (int i = 0; i < 64; ++i) {
      u32 S1 = ror(e, 6) ^ ror(e, 11) ^ ror(e, 25);
      u32 ch = (e & f) ^ (~e & g);
      u32 t1 = hh + S1 + ch + k[i] + w[i];
      u32 S0 = ror(a, 2) ^ ror(a, 13) ^ ror(a, 22);
      u32 mj = (a & b) ^ (a & c) ^ (b & c);
      u32 t2 = S0 + mj;
      hh = g;
      g = f;
      f = e;
      e = d + t1;
      d = c;
      c = b;
      b = a;
      a = t1 + t2;
    }
    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
    h[5] += f;
    h[6] += g;
    h[7] += hh;
  }

  void update(const u8 *p, size_t n) {
    len += n;
    while (n > 0) {
      size_t take = 64 - fill;
      if (take > n)
        take = n;
      std::memcpy(buf + fill, p, take);
      fill += take;
      p += take;
      n -= take;
      if (fill == 64) {
        block(buf);
        fill = 0;
      }
    }
  }

  void final(u8 out[32]) {
    u64 bits = len * 8;
    u8 pad = 0x80;
    update(&pad, 1);
    u8 zero = 0;
    while (fill != 56)
      update(&zero, 1);
    u8 lb[8];
    for (int i = 0; i < 8; ++i)
      lb[i] = u8(bits >> (56 - 8 * i));
    update(lb, 8);
    for (int i = 0; i < 8; ++i) {
      out[i * 4] = u8(h[i] >> 24);
      out[i * 4 + 1] = u8(h[i] >> 16);
      out[i * 4 + 2] = u8(h[i] >> 8);
      out[i * 4 + 3] = u8(h[i]);
    }
  }
};

void sha256(const u8 *data, size_t n, u8 out[32]) {
  Sha256 s;
  s.init();
  s.update(data, n);
  s.final(out);
}

// ---------------------------------------------------------------- HMAC-SHA256
void hmac_sha256(const u8 *key, size_t klen, const u8 *msg, size_t mlen,
                 u8 out[32]) {
  u8 k[64];
  std::memset(k, 0, sizeof(k));
  if (klen > 64)
    sha256(key, klen, k);
  else
    std::memcpy(k, key, klen);

  u8 inner[128];
  for (int i = 0; i < 64; ++i)
    inner[i] = k[i] ^ 0x36;
  if (mlen > 64) {
    Sha256 s;
    s.init();
    s.update(inner, 64);
    s.update(msg, mlen);
    u8 ih[32];
    s.final(ih);
    u8 outer[96];
    for (int i = 0; i < 64; ++i)
      outer[i] = k[i] ^ 0x5c;
    std::memcpy(outer + 64, ih, 32);
    sha256(outer, 96, out);
    return;
  }
  std::memcpy(inner + 64, msg, mlen);
  u8 ih[32];
  sha256(inner, 64 + mlen, ih);

  u8 outer[96];
  for (int i = 0; i < 64; ++i)
    outer[i] = k[i] ^ 0x5c;
  std::memcpy(outer + 64, ih, 32);
  sha256(outer, 96, out);
}

// ---------------------------------------------------------------- HKDF-SHA256
void hkdf(const u8 *salt, size_t saltlen, const u8 *ikm, size_t ikmlen,
          const u8 *info, size_t infolen, u8 *out, size_t outlen) {
  u8 prk[32];
  hmac_sha256(salt, saltlen, ikm, ikmlen, prk);

  u8 t[32];
  size_t tlen = 0, done = 0;
  u8 counter = 1;
  while (done < outlen) {
    u8 msg[32 + 512 + 1];
    if (infolen > 512)
      throw std::runtime_error("hkdf info");
    size_t ml = 0;
    std::memcpy(msg, t, tlen);
    ml += tlen;
    std::memcpy(msg + ml, info, infolen);
    ml += infolen;
    msg[ml++] = counter++;
    hmac_sha256(prk, 32, msg, ml, t);
    tlen = 32;
    size_t take = outlen - done < 32 ? outlen - done : 32;
    std::memcpy(out + done, t, take);
    done += take;
  }
}

// ---------------------------------------------------------------- ChaCha20
inline u32 rotl32(u32 x, int n) { return (x << n) | (x >> (32 - n)); }
inline u32 load32(const u8 *p) {
  return u32(p[0]) | (u32(p[1]) << 8) | (u32(p[2]) << 16) | (u32(p[3]) << 24);
}
inline void store32(u8 *p, u32 v) {
  p[0] = u8(v);
  p[1] = u8(v >> 8);
  p[2] = u8(v >> 16);
  p[3] = u8(v >> 24);
}

inline void chacha_qr(u32 &a, u32 &b, u32 &c, u32 &d) {
  a += b;
  d ^= a;
  d = rotl32(d, 16);
  c += d;
  b ^= c;
  b = rotl32(b, 12);
  a += b;
  d ^= a;
  d = rotl32(d, 8);
  c += d;
  b ^= c;
  b = rotl32(b, 7);
}

void chacha20_block(const u8 key[32], u32 counter, const u8 nonce[12],
                    u8 out[64]) {
  u32 st[16];
  st[0] = 0x61707865;
  st[1] = 0x3320646e;
  st[2] = 0x79622d32;
  st[3] = 0x6b206574;
  for (int i = 0; i < 8; ++i)
    st[4 + i] = load32(key + i * 4);
  st[12] = counter;
  st[13] = load32(nonce);
  st[14] = load32(nonce + 4);
  st[15] = load32(nonce + 8);

  u32 x[16];
  std::memcpy(x, st, sizeof(x));
  for (int i = 0; i < 10; ++i) {
    chacha_qr(x[0], x[4], x[8], x[12]);
    chacha_qr(x[1], x[5], x[9], x[13]);
    chacha_qr(x[2], x[6], x[10], x[14]);
    chacha_qr(x[3], x[7], x[11], x[15]);
    chacha_qr(x[0], x[5], x[10], x[15]);
    chacha_qr(x[1], x[6], x[11], x[12]);
    chacha_qr(x[2], x[7], x[8], x[13]);
    chacha_qr(x[3], x[4], x[9], x[14]);
  }
  for (int i = 0; i < 16; ++i)
    store32(out + i * 4, x[i] + st[i]);
}

void chacha20_xor(const u8 key[32], u32 counter, const u8 nonce[12],
                  const u8 *in, u8 *out, size_t n) {
  u8 ks[64];
  while (n > 0) {
    chacha20_block(key, counter++, nonce, ks);
    size_t take = n < 64 ? n : 64;
    for (size_t i = 0; i < take; ++i)
      out[i] = in[i] ^ ks[i];
    in += take;
    out += take;
    n -= take;
  }
}

// ---------------------------------------------------------------- Poly1305
struct Poly1305 {
  u32 r[5];
  u32 h[5];
  u32 pad[4];
  u8 buf[16];
  size_t fill;

  void init(const u8 key[32]) {
    // clamp r
    r[0] = (load32(key + 0)) & 0x3ffffff;
    r[1] = (load32(key + 3) >> 2) & 0x3ffff03;
    r[2] = (load32(key + 6) >> 4) & 0x3ffc0ff;
    r[3] = (load32(key + 9) >> 6) & 0x3f03fff;
    r[4] = (load32(key + 12) >> 8) & 0x00fffff;
    h[0] = h[1] = h[2] = h[3] = h[4] = 0;
    for (int i = 0; i < 4; ++i)
      pad[i] = load32(key + 16 + i * 4);
    fill = 0;
  }

  void block(const u8 *m, u32 hibit) {
    const u32 r0 = r[0], r1 = r[1], r2 = r[2], r3 = r[3], r4 = r[4];
    const u32 s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;

    u32 h0 = h[0] + (load32(m + 0) & 0x3ffffff);
    u32 h1 = h[1] + ((load32(m + 3) >> 2) & 0x3ffffff) + (h0 >> 26);
    h0 &= 0x3ffffff;
    u32 h2 = h[2] + ((load32(m + 6) >> 4) & 0x3ffffff) + (h1 >> 26);
    h1 &= 0x3ffffff;
    u32 h3 = h[3] + ((load32(m + 9) >> 6) & 0x3ffffff) + (h2 >> 26);
    h2 &= 0x3ffffff;
    u32 h4 = h[4] + ((load32(m + 12) >> 8) | hibit) + (h3 >> 26);
    h3 &= 0x3ffffff;

    u64 d0 = u64(h0) * r0 + u64(h1) * s4 + u64(h2) * s3 + u64(h3) * s2 +
             u64(h4) * s1;
    u64 d1 = u64(h0) * r1 + u64(h1) * r0 + u64(h2) * s4 + u64(h3) * s3 +
             u64(h4) * s2;
    u64 d2 = u64(h0) * r2 + u64(h1) * r1 + u64(h2) * r0 + u64(h3) * s4 +
             u64(h4) * s3;
    u64 d3 = u64(h0) * r3 + u64(h1) * r2 + u64(h2) * r1 + u64(h3) * r0 +
             u64(h4) * s4;
    u64 d4 = u64(h0) * r4 + u64(h1) * r3 + u64(h2) * r2 + u64(h3) * r1 +
             u64(h4) * r0;

    u32 c = u32(d0 >> 26);
    h0 = u32(d0) & 0x3ffffff;
    d1 += c;
    c = u32(d1 >> 26);
    h1 = u32(d1) & 0x3ffffff;
    d2 += c;
    c = u32(d2 >> 26);
    h2 = u32(d2) & 0x3ffffff;
    d3 += c;
    c = u32(d3 >> 26);
    h3 = u32(d3) & 0x3ffffff;
    d4 += c;
    c = u32(d4 >> 26);
    h4 = u32(d4) & 0x3ffffff;
    h0 += c * 5;
    c = h0 >> 26;
    h0 &= 0x3ffffff;
    h1 += c;

    h[0] = h0;
    h[1] = h1;
    h[2] = h2;
    h[3] = h3;
    h[4] = h4;
  }

  void update(const u8 *m, size_t n) {
    while (n > 0) {
      size_t take = 16 - fill;
      if (take > n)
        take = n;
      std::memcpy(buf + fill, m, take);
      fill += take;
      m += take;
      n -= take;
      if (fill == 16) {
        block(buf, 1u << 24);
        fill = 0;
      }
    }
  }

  void final(u8 tag[16]) {
    if (fill > 0) {
      u8 p[16];
      std::memset(p, 0, sizeof(p));
      std::memcpy(p, buf, fill);
      p[fill] = 1;
      block(p, 0);
    }
    u32 h0 = h[0], h1 = h[1], h2 = h[2], h3 = h[3], h4 = h[4];
    u32 c;
    c = h1 >> 26;
    h1 &= 0x3ffffff;
    h2 += c;
    c = h2 >> 26;
    h2 &= 0x3ffffff;
    h3 += c;
    c = h3 >> 26;
    h3 &= 0x3ffffff;
    h4 += c;
    c = h4 >> 26;
    h4 &= 0x3ffffff;
    h0 += c * 5;
    c = h0 >> 26;
    h0 &= 0x3ffffff;
    h1 += c;

    u32 g0 = h0 + 5;
    c = g0 >> 26;
    g0 &= 0x3ffffff;
    u32 g1 = h1 + c;
    c = g1 >> 26;
    g1 &= 0x3ffffff;
    u32 g2 = h2 + c;
    c = g2 >> 26;
    g2 &= 0x3ffffff;
    u32 g3 = h3 + c;
    c = g3 >> 26;
    g3 &= 0x3ffffff;
    u32 g4 = h4 + c - (1u << 26);

    u32 mask = (g4 >> 31) - 1;
    g0 &= mask;
    g1 &= mask;
    g2 &= mask;
    g3 &= mask;
    g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;

    u32 w0 = ((h0) | (h1 << 26)) + pad[0];
    u32 w1 = ((h1 >> 6) | (h2 << 20)) + pad[1] + (w0 >> 32);
    w0 &= 0xffffffff;
    u32 w2 = ((h2 >> 12) | (h3 << 14)) + pad[2] + (w1 >> 32);
    w1 &= 0xffffffff;
    u32 w3 = ((h3 >> 18) | (h4 << 8)) + pad[3] + (w2 >> 32);
    w2 &= 0xffffffff;
    w3 &= 0xffffffff;
    store32(tag + 0, w0);
    store32(tag + 4, w1);
    store32(tag + 8, w2);
    store32(tag + 12, w3);
  }
};

void chacha20_poly1305_tag(const u8 key[32], const u8 nonce[12], const u8 *aad,
                           size_t aadlen, const u8 *ct, size_t ctlen,
                           u8 tag[16]) {
  u8 block0[64];
  chacha20_block(key, 0, nonce, block0);
  Poly1305 p;
  p.init(block0);

  static const u8 zeros[16] = {0};
  p.update(aad, aadlen);
  if (aadlen % 16)
    p.update(zeros, 16 - (aadlen % 16));
  p.update(ct, ctlen);
  if (ctlen % 16)
    p.update(zeros, 16 - (ctlen % 16));

  u8 lens[16];
  for (int i = 0; i < 8; ++i)
    lens[i] = u8(u64(aadlen) >> (8 * i));
  for (int i = 0; i < 8; ++i)
    lens[8 + i] = u8(u64(ctlen) >> (8 * i));
  p.update(lens, 16);
  p.final(tag);
}

// ---------------------------------------------------------------- X25519
// (radix 2^25.5) Layout ref10: v = h0 + h1*2^26 + h2*2^51 + h3*2^77 + h4*2^102
// + h5*2^128
//              + h6*2^153 + h7*2^179 + h8*2^204 + h9*2^230
// v[i] < 2^26 < 2^25.
struct fe {
  u32 v[10];
};

static void fe_zero(fe &r) {
  for (int i = 0; i < 10; ++i)
    r.v[i] = 0;
}
static void fe_one(fe &r) {
  fe_zero(r);
  r.v[0] = 1;
}

static void fe_unpack(fe &r, const u8 s[32]) {
  u32 b[32];
  for (int i = 0; i < 32; ++i)
    b[i] = s[i];
  r.v[0] = b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24);
  r.v[1] = (b[4] | (b[5] << 8) | (b[6] << 16) | (b[7] << 24)) >> 2;
  r.v[2] = (b[7] | (b[8] << 8) | (b[9] << 16) | (b[10] << 24)) >> 3;
  r.v[3] = (b[10] | (b[11] << 8) | (b[12] << 16) | (b[13] << 24)) >> 5;
  r.v[4] = (b[13] | (b[14] << 8) | (b[15] << 16) | (b[16] << 24)) >> 6;
  r.v[5] = (b[16] | (b[17] << 8) | (b[18] << 16) | (b[19] << 24)) >> 0;
  r.v[6] = (b[19] | (b[20] << 8) | (b[21] << 16) | (b[22] << 24)) >> 1;
  r.v[7] = (b[22] | (b[23] << 8) | (b[24] << 16) | (b[25] << 24)) >> 3;
  r.v[8] = (b[25] | (b[26] << 8) | (b[27] << 16) | (b[28] << 24)) >> 4;
  r.v[9] = (b[28] | (b[29] << 8) | (b[30] << 16) | (b[31] << 24)) >> 6;
  r.v[0] &= 0x3ffffff;
  r.v[1] &= 0x3ffffff;
  r.v[2] &= 0x3ffffff;
  r.v[3] &= 0x3ffffff;
  r.v[4] &= 0x3ffffff;
  r.v[5] &= 0x3ffffff;
  r.v[6] &= 0x3ffffff;
  r.v[7] &= 0x3ffffff;
  r.v[8] &= 0x3ffffff;
  r.v[9] &= 0x3ffffff;
}

static void fe_pack(u8 s[32], const fe &a) {
  fe t = a;
  u32 c;
  c = t.v[0] >> 26;
  t.v[0] &= 0x3ffffff;
  t.v[1] += c;
  c = t.v[1] >> 26;
  t.v[1] &= 0x3ffffff;
  t.v[2] += c;
  c = t.v[2] >> 26;
  t.v[2] &= 0x3ffffff;
  t.v[3] += c;
  c = t.v[3] >> 26;
  t.v[3] &= 0x3ffffff;
  t.v[4] += c;
  c = t.v[4] >> 26;
  t.v[4] &= 0x3ffffff;
  t.v[5] += c;
  c = t.v[5] >> 26;
  t.v[5] &= 0x3ffffff;
  t.v[6] += c;
  c = t.v[6] >> 26;
  t.v[6] &= 0x3ffffff;
  t.v[7] += c;
  c = t.v[7] >> 26;
  t.v[7] &= 0x3ffffff;
  t.v[8] += c;
  c = t.v[8] >> 26;
  t.v[8] &= 0x3ffffff;
  t.v[9] += c;
  c = t.v[9] >> 26;
  t.v[9] &= 0x3ffffff;
  t.v[0] += c * 19;
  c = t.v[0] >> 26;
  t.v[0] &= 0x3ffffff;
  t.v[1] += c;

  // pack 10 limbs into 32 bytes
  u64 acc = 0;
  int bits = 0, pos = 0;
  for (int i = 0; i < 10; ++i) {
    acc |= u64(t.v[i]) << bits;
    bits += (i & 1) ? 25 : 26;
    while (bits >= 8 && pos < 32) {
      s[pos++] = u8(acc);
      acc >>= 8;
      bits -= 8;
    }
  }
  if (pos < 32)
    s[pos] = u8(acc);
}

static void fe_add(fe &r, const fe &a, const fe &b) {
  for (int i = 0; i < 10; ++i)
    r.v[i] = a.v[i] + b.v[i];
}

static void fe_sub(fe &r, const fe &a, const fe &b) {
  static const u32 bias[10] = {0x7ffffda, 0x3fffffe, 0x7fffffe, 0x3fffffe,
                               0x7fffffe, 0x3fffffe, 0x7fffffe, 0x3fffffe,
                               0x7fffffe, 0x3fffffe};
  for (int i = 0; i < 10; ++i)
    r.v[i] = a.v[i] + bias[i] - b.v[i];
}

static void fe_carry(fe &a) {
  u32 c;
  c = a.v[0] >> 26;
  a.v[0] &= 0x3ffffff;
  a.v[1] += c;
  c = a.v[1] >> 26;
  a.v[1] &= 0x3ffffff;
  a.v[2] += c;
  c = a.v[2] >> 26;
  a.v[2] &= 0x3ffffff;
  a.v[3] += c;
  c = a.v[3] >> 26;
  a.v[3] &= 0x3ffffff;
  a.v[4] += c;
  c = a.v[4] >> 26;
  a.v[4] &= 0x3ffffff;
  a.v[5] += c;
  c = a.v[5] >> 26;
  a.v[5] &= 0x3ffffff;
  a.v[6] += c;
  c = a.v[6] >> 26;
  a.v[6] &= 0x3ffffff;
  a.v[7] += c;
  c = a.v[7] >> 26;
  a.v[7] &= 0x3ffffff;
  a.v[8] += c;
  c = a.v[8] >> 26;
  a.v[8] &= 0x3ffffff;
  a.v[9] += c;
  c = a.v[9] >> 26;
  a.v[9] &= 0x3ffffff;
  a.v[0] += c * 19;
  c = a.v[0] >> 26;
  a.v[0] &= 0x3ffffff;
  a.v[1] += c;
}

static void fe_mul(fe &r, const fe &a, const fe &b) {
  u64 t[19];
  for (int i = 0; i < 19; ++i)
    t[i] = 0;
  for (int i = 0; i < 10; ++i)
    for (int j = 0; j < 10; ++j)
      t[i + j] += u64(a.v[i]) * b.v[j];
  for (int i = 0; i < 9; ++i)
    t[i] += t[i + 10] * 19;
  u64 c = 0;
  for (int i = 0; i < 10; ++i) {
    t[i] += c;
    r.v[i] = u32(t[i] & 0x3ffffff);
    c = t[i] >> 26;
  }
  r.v[0] += u32(c * 19);
  fe_carry(r);
}

static void fe_sq(fe &r, const fe &a) { fe_mul(r, a, a); }

static void fe_invert(fe &r, const fe &z) {
  fe t0, t1, t2, t3;
  fe_sq(t0, z);       // 2
  fe_sq(t1, t0);      // 4
  fe_sq(t1, t1);      // 8
  fe_mul(t1, z, t1);  // 9
  fe_mul(t0, t0, t1); // 11
  fe_sq(t2, t0);      // 22
  fe_mul(t1, t1, t2); // 2^5 - 2^0
  fe_sq(t2, t1);
  for (int i = 1; i < 5; ++i)
    fe_sq(t2, t2);
  fe_mul(t1, t2, t1);
  fe_sq(t2, t1);
  for (int i = 1; i < 10; ++i)
    fe_sq(t2, t2);
  fe_mul(t2, t2, t1);
  fe_sq(t3, t2);
  for (int i = 1; i < 20; ++i)
    fe_sq(t3, t3);
  fe_mul(t2, t3, t2);
  fe_sq(t2, t2);
  for (int i = 1; i < 10; ++i)
    fe_sq(t2, t2);
  fe_mul(t1, t2, t1);
  fe_sq(t2, t1);
  for (int i = 1; i < 50; ++i)
    fe_sq(t2, t2);
  fe_mul(t2, t2, t1);
  fe_sq(t3, t2);
  for (int i = 1; i < 100; ++i)
    fe_sq(t3, t3);
  fe_mul(t2, t3, t2);
  fe_sq(t2, t2);
  for (int i = 1; i < 50; ++i)
    fe_sq(t2, t2);
  fe_mul(t1, t2, t1);
  fe_sq(t1, t1);
  for (int i = 1; i < 5; ++i)
    fe_sq(t1, t1);
  fe_mul(r, t1, t0);
}

static void fe_cswap(fe &a, u32 &dummy, fe &b) {
  (void)dummy;
  (void)a;
  (void)b;
}

static void x25519(u8 out[32], const u8 scalar[32], const u8 point[32]) {
  u8 e[32];
  std::memcpy(e, scalar, 32);
  e[0] &= 248;
  e[31] &= 127;
  e[31] |= 64;

  fe x1, x2, z2, x3, z3, a, b, c, d, e_, aa, bb, tmp, inv;
  fe_unpack(x1, point);
  fe_one(x2);
  fe_zero(z2);
  fe_one(x3);
  fe_zero(z3);

  u32 swap = 0;
  for (int pos = 254; pos >= 0; --pos) {
    u32 bit = (e[pos >> 3] >> (pos & 7)) & 1;
    swap ^= bit;
    u32 mask = 0u - swap;
    for (int i = 0; i < 10; ++i) {
      u32 t0 = (x2.v[i] ^ x3.v[i]) & mask;
      x2.v[i] ^= t0;
      x3.v[i] ^= t0;
      t0 = (z2.v[i] ^ z3.v[i]) & mask;
      z2.v[i] ^= t0;
      z3.v[i] ^= t0;
    }
    swap = bit;

    fe_add(a, x3, z3); // a = x3+z3
    fe_sub(b, x3, z3); // b = x3-z3
    fe_add(c, x2, z2); // c = x2+z2
    fe_sub(d, x2, z2); // d = x2-z2
    fe_mul(aa, a, d);  // aa = a*d
    fe_mul(bb, b, c);  // bb = b*c
    fe_add(x3, aa, bb);
    fe_sub(z3, aa, bb);
    fe_mul(c, a, a);
    fe_mul(d, b, b);
    fe_add(e_, c, d);
    fe_mul(x2, e_, d); // x2 = e*d ... ref10: x2 = c*d?
    // ref10: x2 = c*d ; z2 = d*x1*... ->
    fe_mul(x2, d, c);
    fe_sub(tmp, c, d);
    fe_mul(z2, x1, tmp);
    (void)e_;
  }
  u32 mask = 0u - swap;
  for (int i = 0; i < 10; ++i) {
    u32 t0 = (x2.v[i] ^ x3.v[i]) & mask;
    x2.v[i] ^= t0;
    x3.v[i] ^= t0;
    t0 = (z2.v[i] ^ z3.v[i]) & mask;
    z2.v[i] ^= t0;
    z3.v[i] ^= t0;
  }
  fe_invert(inv, z2);
  fe_mul(x2, x2, inv);
  fe_pack(out, x2);
}

}

KeyPair GenerateX25519() {
  KeyPair kp;
  kp.priv.resize(32);
  kp.pub.resize(32);
  random_bytes(kp.priv.data(), 32);
  u8 base[32];
  std::memset(base, 0, sizeof(base));
  base[0] = 9;
  x25519(kp.pub.data(), kp.priv.data(), base);
  return kp;
}

std::vector<uint8_t> DeriveSessionKey(const std::vector<uint8_t> &my_priv,
                                      const std::vector<uint8_t> &peer_pub,
                                      const std::string &info) {
  if (my_priv.size() != 32 || peer_pub.size() != 32)
    throw std::runtime_error("x25519 args");
  std::vector<uint8_t> shared(32);
  x25519(shared.data(), my_priv.data(), peer_pub.data());
  std::vector<uint8_t> out(32);
  hkdf(nullptr, 0, shared.data(), shared.size(),
       reinterpret_cast<const uint8_t *>(info.data()), info.size(), out.data(),
       out.size());
  return out;
}

std::vector<uint8_t> Seal(const std::vector<uint8_t> &key,
                          const std::vector<uint8_t> &plain,
                          const std::vector<uint8_t> &aad) {
  if (key.size() != 32)
    throw std::runtime_error("seal key");
  std::vector<uint8_t> out(12 + plain.size() + 16);
  uint8_t *nonce = out.data();
  random_bytes(nonce, 12);
  uint8_t *body = out.data() + 12;

  chacha20_xor(key.data(), 1, nonce, plain.data(), body, plain.size());
  chacha20_poly1305_tag(key.data(), nonce, aad.empty() ? nullptr : aad.data(),
                        aad.size(), body, plain.size(),
                        out.data() + 12 + plain.size());
  return out;
}

bool Open(const std::vector<uint8_t> &key, const std::vector<uint8_t> &envelope,
          std::vector<uint8_t> &plain, const std::vector<uint8_t> &aad) {
  if (key.size() != 32 || envelope.size() < 12 + 16)
    return false;
  const uint8_t *nonce = envelope.data();
  const uint8_t *ct = envelope.data() + 12;
  const size_t ctlen = envelope.size() - 28;
  const uint8_t *tag = envelope.data() + envelope.size() - 16;

  u8 expect[16];
  chacha20_poly1305_tag(key.data(), nonce, aad.empty() ? nullptr : aad.data(),
                        aad.size(), ct, ctlen, expect);
  u8 diff = 0;
  for (int i = 0; i < 16; ++i)
    diff |= expect[i] ^ tag[i];
  if (diff)
    return false;

  plain.resize(ctlen);
  chacha20_xor(key.data(), 1, nonce, ct, plain.data(), ctlen);
  return true;
}

std::string ToHex(const std::vector<uint8_t> &b) {
  static const char *h = "0123456789abcdef";
  std::string s;
  s.reserve(b.size() * 2);
  for (uint8_t c : b) {
    s.push_back(h[c >> 4]);
    s.push_back(h[c & 0xF]);
  }
  return s;
}

std::vector<uint8_t> FromHex(const std::string &s) {
  auto nib = [](char c) -> int {
    if (c >= '0' && c <= '9')
      return c - '0';
    if (c >= 'a' && c <= 'f')
      return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
      return c - 'A' + 10;
    return -1;
  };
  std::vector<uint8_t> out;
  if (s.size() % 2)
    return out;
  for (size_t i = 0; i < s.size(); i += 2) {
    int a = nib(s[i]), b = nib(s[i + 1]);
    if (a < 0 || b < 0)
      return {};
    out.push_back(uint8_t(a << 4 | b));
  }
  return out;
}

}
