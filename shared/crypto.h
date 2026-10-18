#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace crypto {

struct KeyPair {
    std::vector<uint8_t> priv;
    std::vector<uint8_t> pub;
};

KeyPair GenerateX25519();

std::vector<uint8_t> DeriveSessionKey(
    const std::vector<uint8_t>& my_priv,
    const std::vector<uint8_t>& peer_pub,
    const std::string& info);

std::vector<uint8_t> Seal(const std::vector<uint8_t>& key,
                          const std::vector<uint8_t>& plain,
                          const std::vector<uint8_t>& aad = {});

bool Open(const std::vector<uint8_t>& key,
          const std::vector<uint8_t>& envelope,
          std::vector<uint8_t>& plain,
          const std::vector<uint8_t>& aad = {});

std::string ToHex(const std::vector<uint8_t>& b);
std::vector<uint8_t> FromHex(const std::string& s);

}