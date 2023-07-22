#include <openssl/err.h>
#include <nlohmann/json.hpp>

#include "wghub-internal.h"
#include "wghub.h"

static const auto cipher = EVP_des_ede3_cbc();

static std::pair<std::shared_ptr<uint8_t[]>, std::shared_ptr<uint8_t[]>> 
    generate_key_and_iv_from_shared_key(const EVP_CIPHER* cipher, EVP_PKEY* privkey/*mine*/, EVP_PKEY* pubkey/*peer's*/)
{
    std::shared_ptr<EVP_PKEY_CTX> pkey_ctx(EVP_PKEY_CTX_new(privkey, EVP_PKEY_get0_engine(privkey)), EVP_PKEY_CTX_free);
    EVP_PKEY_derive_init(pkey_ctx.get());
    EVP_PKEY_derive_set_peer(pkey_ctx.get(), pubkey);
    size_t skeylen;
    EVP_PKEY_derive(pkey_ctx.get(), NULL, &skeylen);
    std::shared_ptr<uint8_t[]> shared_key_bytes(new uint8_t[skeylen]);
    EVP_PKEY_derive(pkey_ctx.get(), shared_key_bytes.get(), &skeylen);

    std::shared_ptr<uint8_t[]> key(new uint8_t[EVP_CIPHER_key_length(cipher)]), iv(new uint8_t[EVP_CIPHER_iv_length(cipher)]);
    if (EVP_BytesToKey(cipher, EVP_md5(), nullptr, shared_key_bytes.get(), skeylen, 1, key.get(), iv.get()) == 0) {
        throw std::runtime_error("EVP_BytesToKey() failed");
    }
    //else
    return {key, iv};
}

static std::shared_ptr<EVP_PKEY> get_privkey(const std::string& privkey_b64)
{
    auto privkey_bytes = wghub::internal::base64_decode(privkey_b64);
    if (privkey_bytes.second < wghub::internal::WG_KEY_LEN) throw std::runtime_error("Invalid private key provided");
    //else
    std::shared_ptr<EVP_PKEY> privkey(EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, privkey_bytes.first.get(), wghub::internal::WG_KEY_LEN), EVP_PKEY_free);
    if (!privkey) throw std::runtime_error("EVP_PKEY_new_raw_private_key() failed");
    //else
    return privkey;
}

static std::shared_ptr<EVP_PKEY> get_pubkey(const uint8_t* pubkey_bytes)
{
    std::shared_ptr<EVP_PKEY> pubkey(EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, pubkey_bytes, wghub::internal::WG_KEY_LEN), EVP_PKEY_free);
    if (!pubkey) throw std::runtime_error("Invalid public key");
    return pubkey;
}

namespace wghub {
namespace internal {
std::string base64_encode(const uint8_t* bytes, size_t len)
{
    char encoded[4*((len+2)/3)];
    if (!EVP_EncodeBlock((unsigned char*)encoded, bytes, len)) throw std::runtime_error("EVP_EncodeBlock() failed");
    //else
    return encoded;
}

std::pair<std::shared_ptr<uint8_t[]>,size_t> base64_decode(const std::string& base64)
{
    std::shared_ptr<uint8_t[]> decoded(new uint8_t[3*base64.length()/4]);
    std::shared_ptr<EVP_ENCODE_CTX> ctx(EVP_ENCODE_CTX_new(), EVP_ENCODE_CTX_free);
    EVP_DecodeInit(ctx.get());
    int outl, outl2;
    EVP_DecodeUpdate(ctx.get(), decoded.get(), &outl, (const unsigned char*)base64.c_str(), base64.length());
    EVP_DecodeFinal(ctx.get(), decoded.get() + outl, &outl2);
    return {decoded, (size_t)outl + outl2};
}

std::string make_urlsafe(const std::string& base64str)
{
    std::string urlsafe_str;
    for (auto c:base64str) {
        if (c == '+') c = '-';
        else if (c == '/') c = '_';
        urlsafe_str += c;
    }
    return urlsafe_str;
}

std::string encrypt(const std::string& str, EVP_PKEY* privkey/*mine*/, EVP_PKEY* pubkey/*peer's*/)
{
    auto [key, iv] = generate_key_and_iv_from_shared_key(cipher, privkey, pubkey);

    std::shared_ptr<EVP_CIPHER_CTX> ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!EVP_EncryptInit_ex(ctx.get(), cipher, NULL, key.get(), iv.get())) throw std::runtime_error("EVP_EncryptInit_ex() failed");
    uint8_t buf[str.length() + EVP_CIPHER_block_size(cipher) - 1];
    int len, tmplen;
    if (!EVP_EncryptUpdate(ctx.get(), buf, &len, (const unsigned char*)str.c_str(), str.length())) {
        throw std::runtime_error("EVP_EncryptUpdate() failed");
    }
    if (!EVP_EncryptFinal_ex(ctx.get(), buf + len, &tmplen)) {
        throw std::runtime_error("EVP_EncryptFinal_ex() failed");
    }
    return base64_encode(buf, len + tmplen);
}

std::string decrypt(const std::string& encrypted_b64, EVP_PKEY* privkey/*mine*/, EVP_PKEY* pubkey/*peer's*/)
{
    auto encrypted_bytes = base64_decode(encrypted_b64);

    auto [key, iv] = generate_key_and_iv_from_shared_key(cipher, privkey, pubkey);

    std::shared_ptr<EVP_CIPHER_CTX> ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!EVP_DecryptInit_ex(ctx.get(), cipher, NULL, key.get(), iv.get())) throw std::runtime_error("EVP_DecryptInit_ex() failed");

    uint8_t buf[encrypted_bytes.second + EVP_CIPHER_block_size(cipher)];
    int len;
    if (!EVP_DecryptUpdate(ctx.get(), buf, &len, encrypted_bytes.first.get(), encrypted_bytes.second)) {
        throw std::runtime_error("EVP_DecryptUpdate() failed");
    }
    int tmplen;
    if (!EVP_DecryptFinal_ex(ctx.get(), buf + len, &tmplen)) {
        auto err = ERR_get_error();
        char buf[120];
        ERR_error_string(err, buf);
        throw std::runtime_error("EVP_DecryptFinal_ex() failed: " + std::string(buf));
    }
    return std::string((const char*)buf, len + tmplen);
}
} // namespace internal


std::string generate_private_key()
{
    std::shared_ptr<uint8_t[]> privkey_bytes(new uint8_t[internal::WG_KEY_LEN]);
    if (getentropy(privkey_bytes.get(), internal::WG_KEY_LEN) != 0) throw std::runtime_error("getentropy() failed");
    // https://github.com/torvalds/linux/blob/master/include/crypto/curve25519.h#L61
    privkey_bytes[0] &= 248;
    privkey_bytes[31] = (privkey_bytes[31] & 127) | 64;

    return internal::base64_encode(privkey_bytes.get(), internal::WG_KEY_LEN);
}

std::string get_public_key_from_private_key(const std::string& private_key_b64)
{
    std::shared_ptr<EVP_PKEY> privkey(
        EVP_PKEY_new_raw_private_key(
            EVP_PKEY_X25519, NULL, internal::base64_decode(private_key_b64).first.get(), 
            internal::WG_KEY_LEN), 
        EVP_PKEY_free);
    if (!privkey) throw std::runtime_error("EVP_PKEY_new_raw_private_key() failed");
    //else
    std::shared_ptr<uint8_t[]> pubkey_bytes(new uint8_t[internal::WG_KEY_LEN]);
    size_t pubkey_len = internal::WG_KEY_LEN;
    if (!EVP_PKEY_get_raw_public_key(privkey.get(), pubkey_bytes.get(), &pubkey_len)) {
        throw std::runtime_error("EVP_PKEY_get_raw_public_key() failed");
    }
    return internal::base64_encode(pubkey_bytes.get(), internal::WG_KEY_LEN);    
}

std::string get_authorization_url(const std::string base, const std::string& public_key_b64)
{
    std::string url = base;
    if (!url.ends_with('/')) url += '/';
    return url  + "authorized/" + internal::make_urlsafe(public_key_b64);
}

ClientConfig decrypt_and_parse_client_config(const std::string& encrypted_client_config_b64,
    const std::string& privkey_b64)
{
    auto privkey = get_privkey(privkey_b64);

    auto comma_pos = encrypted_client_config_b64.find_first_of(',');
    if (comma_pos == encrypted_client_config_b64.npos) throw std::runtime_error("Invalid server response: no delimiter");

    auto peer_pubkey_b64 = encrypted_client_config_b64.substr(0, comma_pos);
    auto buf = encrypted_client_config_b64.substr(comma_pos + 1);

    auto peer_pubkey = get_pubkey(internal::base64_decode(peer_pubkey_b64).first.get());

    auto decrypted = internal::decrypt(buf, privkey.get(), peer_pubkey.get());

    auto json = nlohmann::json::parse(decrypted);
    if (!json.contains("address")) throw std::runtime_error("Field 'address' is missing");
    if (!json.contains("endpoint")) throw std::runtime_error("Field 'endpoint' is missing");
    if (!json.contains("peer-address")) throw std::runtime_error("Field 'peer-address' is missing");

    return {
        .address = json["address"],
        .endpoint = json["endpoint"],
        .peer_address = json["peer-address"],
        .peer_pubkey = peer_pubkey_b64,
        .ssh_key = json.contains("ssh-key")? std::make_optional(json["ssh-key"]) : std::nullopt,
        .serial = json.contains("serial")? std::make_optional(json["serial"]) : std::nullopt
    };
}

} // namespace wghub
