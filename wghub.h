#ifndef __WGHUB_H__
#define __WGHUB_H__

#include <string>
#include <optional>

namespace wghub {
    std::string generate_private_key();
    std::string get_public_key_from_private_key(const std::string& private_key_b64);
    struct ClientConfig {
      std::string address;
      std::string endpoint;
      std::string peer_address;
      std::string peer_pubkey;
      std::optional<std::string> ssh_key;
      std::optional<std::string> serial;

    };
    std::string get_authorization_url(const std::string base, const std::string& public_key_b64);
    ClientConfig decrypt_and_parse_client_config(const std::string& encrypted_client_config_b64, const std::string& privkey_b64);
}

#endif // __WGHUB_H__

