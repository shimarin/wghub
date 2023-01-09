#include <iostream>
#include <fstream>
#include <filesystem>
#include <memory>

#include <curl/curl.h>
#include <argparse/argparse.hpp>

#include "wghub.h"

static size_t curl_callback(char *buffer, size_t size, size_t nmemb, void *f)
{
    (*((std::string*)f)) += std::string(buffer, size * nmemb);
    return size * nmemb;
}

static int genkey(const std::filesystem::path& privkey_filename)
{
    if (std::filesystem::exists(privkey_filename)) {
        throw std::runtime_error("File " + privkey_filename.string() + " already exists. ");
    }
    auto privkey = wghub::generate_private_key();
    auto pubkey = wghub::get_public_key_from_private_key(privkey);
    std::ofstream privkey_stream(privkey_filename);
    std::filesystem::permissions(privkey_filename, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write);
    privkey_stream << privkey;
    std::cout << "New key pair generated. private key saved to " << privkey_filename << "." << std::endl;
    std::cout << "Corresponding public key = " << pubkey << std::endl;
    std::cout << "Provide this public key to your VPN administrator and then execute this program again to get individual VPN connection information." << std::endl;
    return 0;
}

static int get(const std::filesystem::path& privkey_filename, const std::string& base_url)
{
    std::ifstream privkey_stream(privkey_filename);
    if (!privkey_stream) throw std::runtime_error("Private key file couldn't be opened.");
    //else
    std::cout << "Private key file " << privkey_filename << " found." << std::endl;
    std::string privkey;
    privkey_stream >> privkey;
    auto pubkey = wghub::get_public_key_from_private_key(privkey);
    std::cout << "Corresponding public key = " << pubkey << std::endl;

    auto url = wghub::get_authorization_url(base_url, pubkey);

    std::cout << "Obtaining WireGuard connection info from  " << url << " ..." << std::endl;

    std::shared_ptr<CURL> curl(curl_easy_init(), curl_easy_cleanup);
    curl_easy_setopt(curl.get(), CURLOPT_URL, url.c_str());
    std::string buf;
    curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, curl_callback);
    curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, &buf);
    auto res = curl_easy_perform(curl.get());
    if (res != CURLE_OK) {
        throw std::runtime_error(curl_easy_strerror(res));
    }
    long http_code = 0;
    curl_easy_getinfo(curl.get(), CURLINFO_RESPONSE_CODE, &http_code);

    if (http_code == 404) {
        std::cerr << "Not authorized yet(HTTP 404)" << std::endl;
        return 1;
    }
    if (http_code != 200) throw std::runtime_error("Server error: status code=" + std::to_string(http_code));

    auto config = wghub::decrypt_and_parse_client_config(buf, privkey);

    std::cout << "========== /etc/wireguard/<your favourite interface name>.conf ==========" << std::endl;
    std::cout << "[Interface]" << std::endl;
    std::cout << "PrivateKey=<content of privkey.txt here>"  << std::endl;
    std::cout << "Address=" << config.address << std::endl;
    std::cout << "[Peer]" << std::endl;
    std::cout << "PublicKey=" << config.peer_pubkey << std::endl;
    std::cout << "endpoint=" << config.endpoint << std::endl;
    std::cout << "AllowedIPs=" << config.peer_address << std::endl;
    std::cout << "PersistentKeepalive=25" << std::endl;

    return 0;
}

int main(int argc, char* argv[])
{
    argparse::ArgumentParser program(argv[0]);
    program.add_argument("-f", "--privkey-file").help("Private key file")
        .default_value<std::string>("privkey.txt");

    argparse::ArgumentParser genkey_command("genkey");
    program.add_subparser(genkey_command);

    argparse::ArgumentParser get_command("get");
    get_command.add_argument("base-url").help("Base URL of service")
        .default_value<std::string>("https://hub.walbrix.net/wghub");
    program.add_subparser(get_command);

    try {
        program.parse_args(argc, argv);
    }
    catch (const std::runtime_error& err) {
        std::cerr << err.what() << std::endl;
        if (program.is_subcommand_used("genkey")) {
            std::cerr << genkey_command;
        } else if (program.is_subcommand_used("get")) {
            std::cerr << get_command;
        } else {
            std::cerr << program;
        }
        return 1;
    }

    try {
        std::filesystem::path privkey_filename = program.get("--privkey-file");
        if (program.is_subcommand_used("genkey")) {
            return genkey(privkey_filename);
        }
        if (program.is_subcommand_used("get")) {
            return get(privkey_filename, get_command.get("base-url"));
        }
        //else
        std::cout << program;
    }
    catch (const std::runtime_error& err) {
        std::cerr << err.what() << std::endl;
    }
    return 1;
}
