#ifndef __WGHUB_INTERNAL_H__
#define __WGHUB_INTERNAL_H__

#include <memory>
#include <optional>
#include <openssl/evp.h>

namespace wghub::internal {
    const size_t WG_KEY_LEN = 32;
    std::string base64_encode(const uint8_t* bytes, size_t len);
    std::pair<std::shared_ptr<uint8_t[]>,size_t> base64_decode(const std::string& base64);
    std::string make_urlsafe(const std::string& base64str);
    std::string encrypt(const std::string& str, EVP_PKEY* privkey/*mine*/, EVP_PKEY* pubkey/*peer's*/);
    std::string decrypt(const std::string& encrypted_b64, EVP_PKEY* privkey/*mine*/, EVP_PKEY* pubkey/*peer's*/);
}

#endif // __WGHUB_INTERNAL_H__