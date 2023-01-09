#include <sys/wait.h>

#include <iostream>
#include <fstream>
#include <filesystem>
#include <optional>
#include <functional>
#include <set>
#include <map>

#include <ext/stdio_filebuf.h> // for __gnu_cxx::stdio_filebuf

#include <argparse/argparse.hpp>
#include <iniparser4/iniparser.h>
#include <nlohmann/json.hpp>

#include "wghub.h"
#include "wghub-internal.h"

static const std::filesystem::path 
    wg_conf_path("/etc/wireguard/wghub.conf"), 
    data_dir("/var/lib/wghub"),
    public_dir = data_dir / "public", // directory to be disclosured
    serial_dir = data_dir / "serial",
    endpoint_hostname_file = data_dir / "endpoint_hostname";
static const std::string network_prefix("fd00::/8");
static const std::string interface("wghub");

static std::string make_urlunsafe(const std::string& urlsafe_base64str)
{
    std::string urlunsafe_str;
    for (auto c:urlsafe_base64str) {
        if (c == '-') c = '+';
        else if (c == '_') c = '/';
        urlunsafe_str += c;
    }
    return urlunsafe_str;
}

static std::string pubkey_bytes_to_address(const uint8_t* pubkey_bytes)
{
    char buf[4*8+7+1];
    sprintf(buf, "fd%02x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",
        (int)pubkey_bytes[0],
        (((int)pubkey_bytes[1]) << 8) | pubkey_bytes[2],
        (((int)pubkey_bytes[3]) << 8) | pubkey_bytes[4],
        (((int)pubkey_bytes[5]) << 8) | pubkey_bytes[6],
        (((int)pubkey_bytes[7]) << 8) | pubkey_bytes[8],
        (((int)pubkey_bytes[9]) << 8) | pubkey_bytes[10],
        (((int)pubkey_bytes[11]) << 8) | pubkey_bytes[12],
        (((int)pubkey_bytes[13]) << 8) | pubkey_bytes[14]
    );
    return buf;
}

static std::string pubkey_b64_to_serial(const std::string& pubkey_b64)
{
    auto pubkey_bytes = wghub::internal::base64_decode(pubkey_b64);
    const uint8_t* b = pubkey_bytes.first.get() + 27;
    std::string serial;
    for (auto n:{
        (b[0] >> 3) & 0x1f,
        ((b[0] << 2) + (b[1] >> 6)) & 0x1f,
        (b[1] >> 1) & 0x1f,
        ((b[1] << 4) + (b[2] >> 4)) & 0x1f,
        ((b[2] << 1) + (b[3] >> 7)) & 0x1f,
        (b[3] >> 2) & 0x1f,
        ((b[3] << 3) + (b[4] >> 5)) & 0x1f,
        b[4] & 0x1f
    }) {
        serial += "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"[n];
    }
    return serial;
}

int init(const std::string& endpoint_hostname)
{
    std::filesystem::create_directories(serial_dir);
    std::filesystem::create_directories(public_dir);

    std::ofstream f(endpoint_hostname_file);
    if (!f) throw std::runtime_error(endpoint_hostname_file.string() + " cannot be opened for write");
    f << endpoint_hostname;

    return 0;
}

int authorize(const std::string& peer_pubkey_b64, const std::string& serial, bool force)
{
    std::string endpoint_hostname;
    {
        std::ifstream f(endpoint_hostname_file);
        if (!f) throw std::runtime_error("Cannot open " + endpoint_hostname_file.string() + ". 'init' not done yet?");
        f >> endpoint_hostname;
    }

    auto peer_pubkey_bytes = wghub::internal::base64_decode(peer_pubkey_b64);
    auto address/*of client*/ = pubkey_bytes_to_address(peer_pubkey_bytes.first.get());

    std::shared_ptr<EVP_PKEY> peer_pubkey(EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_pubkey_bytes.first.get(), 
        std::min(wghub::internal::WG_KEY_LEN, peer_pubkey_bytes.second)), EVP_PKEY_free);
    if (!peer_pubkey) throw std::runtime_error("Invalid client public key " + peer_pubkey_b64);

    std::shared_ptr<dictionary> wg_conf(iniparser_load(wg_conf_path.c_str()), iniparser_freedict);
    if (!wg_conf) throw std::runtime_error("Couldn't open " + wg_conf_path.string());
    // else
    auto privkey_base64 = iniparser_getstring(wg_conf.get(), "interface:PrivateKey", NULL);
    if (!privkey_base64) throw std::runtime_error("PrivateKey is not defined in " + wg_conf_path.string());
    //else
    auto privkey_bytes = wghub::internal::base64_decode(privkey_base64);
    auto privkey = std::shared_ptr<EVP_PKEY>(EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, privkey_bytes.first.get(),
        std::min(wghub::internal::WG_KEY_LEN, privkey_bytes.second)), EVP_PKEY_free);
    if (!privkey) throw std::runtime_error("Private key is invalid(EVP_PKEY_new_raw_private_key failed).");

    unsigned char my_pubkey_bytes[wghub::internal::WG_KEY_LEN];
    size_t my_pubkey_len = wghub::internal::WG_KEY_LEN;
    if (!EVP_PKEY_get_raw_public_key(privkey.get(), my_pubkey_bytes, &my_pubkey_len)) {
        throw std::runtime_error("Unable to generate public key from private key(EVP_PKEY_get_raw_public_key failed)");
    }
    auto port = iniparser_getstring(wg_conf.get(), "interface:ListenPort", NULL);
    if (!port) throw std::runtime_error("ListenPort is not defined in " + wg_conf_path.string());;

    auto my_address = iniparser_getstring(wg_conf.get(), "interface:Address", NULL);
    if (!my_address) throw std::runtime_error("Address is not defined in " + wg_conf_path.string());;

    auto homedir_cstr = getenv("HOME");
    std::filesystem::path homedir(homedir_cstr? homedir_cstr : "/root");
    std::ifstream id_rsa_pub(homedir / ".ssh/id_rsa.pub");
    std::optional<std::string> sshkey = id_rsa_pub? [](auto& f){
        std::string s;
        return (std::getline(f, s) && s != "") ? std::make_optional(s) : std::nullopt;
    }(id_rsa_pub) : std::nullopt;

    nlohmann::json json;
    json["endpoint"] = endpoint_hostname + ':' + port;
    json["peer-address"] = std::string(my_address);
    json["address"] = address + "/128";
    if (sshkey) json["ssh-key"] = sshkey.value();
    json["serial"] = serial;

    auto client_file =  public_dir / wghub::internal::make_urlsafe(peer_pubkey_b64);
    if (!std::filesystem::exists(client_file) || force) {
        std::ofstream f(client_file);
        if (!f) throw std::runtime_error("client file couldn't be open for write");
        //else
        f << wghub::internal::base64_encode(my_pubkey_bytes, my_pubkey_len) << ',' << wghub::internal::encrypt(json, privkey.get(), peer_pubkey.get()) << std::endl;
    } else {
        throw std::runtime_error("Client file " + client_file.string() + " already exists.  Use --force to overwrite");
    }

    std::ofstream f(serial_dir / serial);
    if (!f) throw std::runtime_error("serial file couldn't be opened for write");
    f << peer_pubkey_b64 << std::endl;
    f << address << std::endl;

    std::cout << "Client authorized successfully." << std::endl;
    std::cout << "Serial: " << serial << std::endl;
    std::cout << "Public Key: " << peer_pubkey_b64 << std::endl;
    std::cout << "Client file: " << client_file << std::endl;
    std::cout << "Address: " << address << std::endl;

    return 0;
}

static std::string determine_pubkey(const std::string& serial_or_pubkey_b64)
{
    if (std::filesystem::exists(public_dir / wghub::internal::make_urlsafe(serial_or_pubkey_b64))) {
        return serial_or_pubkey_b64;
    }

    //else
    if (std::filesystem::exists(serial_dir / serial_or_pubkey_b64)) {
        std::ifstream f(serial_dir / serial_or_pubkey_b64);
        if (f) {
            std::string s;
            f >> s;
            return s;
        }
    }

    throw std::runtime_error(serial_or_pubkey_b64 + " is not a serial or pubkey");
}

int show(const std::string& serial_or_pubkey_b64)
{
    auto peer_pubkey_b64 = determine_pubkey(serial_or_pubkey_b64);

    auto peer_pubkey_bytes = wghub::internal::base64_decode(peer_pubkey_b64);
    std::shared_ptr<EVP_PKEY> peer_pubkey(
            EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_pubkey_bytes.first.get(), 
            std::min(wghub::internal::WG_KEY_LEN, peer_pubkey_bytes.second)), EVP_PKEY_free);
    if (!peer_pubkey) throw std::runtime_error("Invalid client public key " + peer_pubkey_b64);

    std::shared_ptr<dictionary> wg_conf(iniparser_load(wg_conf_path.c_str()), iniparser_freedict);
    if (!wg_conf) throw std::runtime_error("Couldn't open " + wg_conf_path.string());
    // else
    auto privkey_base64 = iniparser_getstring(wg_conf.get(), "interface:PrivateKey", NULL);
    if (!privkey_base64) throw std::runtime_error("PrivateKey is not defined in " + wg_conf_path.string());
    //else
    auto privkey_bytes = wghub::internal::base64_decode(privkey_base64);
    auto privkey = std::shared_ptr<EVP_PKEY>(EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, privkey_bytes.first.get(), 
        std::min(wghub::internal::WG_KEY_LEN, privkey_bytes.second)), EVP_PKEY_free);
    if (!privkey) throw std::runtime_error("Private key is invalid(EVP_PKEY_new_raw_private_key failed).");

    auto client_file = public_dir / wghub::internal::make_urlsafe(peer_pubkey_b64);
    std::ifstream f(client_file);
    if (!f) throw std::runtime_error(client_file.string() + " couldn't be opened");
    //else
    std::string line;
    f >> line;
    auto comma_pos = line.find_first_of(',');
    if (comma_pos != line.npos) line.erase(line.begin(), line.begin() + comma_pos + 1);

    std::cout << wghub::internal::decrypt(line, privkey.get(), peer_pubkey.get()) << std::endl;
    return 0;
}

int _delete(const std::string& serial_or_pubkey_b64)
{
    auto peer_pubkey_b64 = determine_pubkey(serial_or_pubkey_b64);
    auto client_file = public_dir / wghub::internal::make_urlsafe(peer_pubkey_b64);

    std::filesystem::remove(client_file);

    return 0;
}

int load()
{
    std::shared_ptr<dictionary> wg_conf(iniparser_load(wg_conf_path.c_str()), iniparser_freedict);
    if (!wg_conf) throw std::runtime_error("Couldn't open " + wg_conf_path.string());

    auto privkey_base64 = iniparser_getstring(wg_conf.get(), "interface:PrivateKey", NULL);
    if (!privkey_base64) throw std::runtime_error("PrivateKey is not defined in " + wg_conf_path.string());
    auto my_address = iniparser_getstring(wg_conf.get(), "interface:Address", NULL);
    if (!my_address) throw std::runtime_error("Address is not defined in " + wg_conf_path.string());

    auto exec_command = [](const std::string& program, const std::vector<const char*>& argv) {
        auto pid = fork();
        if (pid < 0) throw std::runtime_error("fork() failed");
        if (pid == 0) {
            _exit(execvp(program.c_str(), const_cast<char* const*>(argv.data())));
        }
        int wstatus;
        if (waitpid(pid, &wstatus, 0) < 0 || !WIFEXITED(wstatus)) {
            throw std::runtime_error("external program " + program + " aborted abnormally.");
        }
        return WEXITSTATUS(wstatus);
    };

    if (exec_command("ip", {"ip", "route", "replace", network_prefix.c_str(), "dev", interface.c_str(), NULL}) < 0) {
        throw std::runtime_error("'ip route replace' command failed.");
    }

    int fd[2];
    if (pipe(fd) < 0) throw std::runtime_error("pipe() failed");

    auto pid = fork();
    if (pid < 0) throw std::runtime_error("fork() failed");
    if (pid == 0) {
        dup2(fd[1], STDOUT_FILENO);
        close(fd[0]);
        _exit(execlp("wg", "wg", "show", interface.c_str(), "peers", NULL));
    }
    //else
    close(fd[1]);

    std::set<std::string> present_peers;
    {
        __gnu_cxx::stdio_filebuf<char> filebuf(fd[0], std::ios::in);
        std::istream f(&filebuf);
        std::string line;
        while (std::getline(f, line)) {
            if (line != "") present_peers.insert(line);
        }
    }

    int wstatus;
    waitpid(pid, &wstatus, 0);
    if (!WIFEXITED(wstatus) || WEXITSTATUS(wstatus) != 0) throw std::runtime_error("wg command failed");

    for (const auto& d : std::filesystem::directory_iterator(public_dir)) {
        if (!d.is_regular_file()) continue;
        auto pubkey_b64 = make_urlunsafe(d.path().filename().string());
        if (present_peers.find(pubkey_b64) == present_peers.end()) {
            auto pubkey_bytes = wghub::internal::base64_decode(pubkey_b64);
            auto address = pubkey_bytes_to_address(pubkey_bytes.first.get());
            exec_command("wg", 
                {"wg", "set", interface.c_str(), "peer", pubkey_b64.c_str(), "allowed-ips", (address + "/128").c_str(), 
                NULL});
        } else {
            present_peers.erase(pubkey_b64);
        }
    }

    for (const auto& p:present_peers) {
        exec_command("wg", {"wg", "set", interface.c_str(), "peer", p.c_str(), "remove", NULL});
    }

    return 0;
}

static int _main(int argc, char* argv[])
{
    argparse::ArgumentParser program(argv[0]);

    argparse::ArgumentParser init_command("init");
    init_command.add_argument("endpoint-hostname").nargs(1);
    program.add_subparser(init_command);

    argparse::ArgumentParser authorize_command("authorize");
    authorize_command.add_argument("-s", "--serial");
    authorize_command.add_argument("-f", "--force").default_value(false).implicit_value(true);
    authorize_command.add_argument("pubkey").nargs(1);
    program.add_subparser(authorize_command);

    argparse::ArgumentParser show_command("show");
    show_command.add_argument("pubkey_or_serial").nargs(1);
    program.add_subparser(show_command);
    argparse::ArgumentParser delete_command("delete");
    delete_command.add_argument("pubkey_or_serial").nargs(1);
    program.add_subparser(delete_command);
    argparse::ArgumentParser load_command("load");
    program.add_subparser(load_command);

    try {
        program.parse_args(argc, argv);
    }
    catch (const std::runtime_error& err) {
        if (program.is_subcommand_used("init")) {
            std::cerr << init_command;
        } else if (program.is_subcommand_used("authorize")) {
            std::cerr << authorize_command;
        } else if (program.is_subcommand_used("show")) {
            std::cerr << show_command;
        } else if (program.is_subcommand_used("delete")) {
            std::cerr << delete_command;
        } else if (program.is_subcommand_used("load")) {
            std::cerr << load_command;
        } else {
            std::cerr << program;
        }
        return 1;
    }

    if (program.is_subcommand_used("init")) {
        return init(init_command.get("endpoint-hostname"));
    } 
    if (program.is_subcommand_used("authorize")) {
        const auto& pubkey = authorize_command.get("pubkey");
        return authorize(pubkey, authorize_command.present("--serial").value_or(pubkey_b64_to_serial(pubkey)),
             authorize_command.get<bool>("--force"));
    } 
    if (program.is_subcommand_used("show")) {
        return show(show_command.get("pubkey_or_serial"));
    } 
    if (program.is_subcommand_used("delete")) {
        return _delete(delete_command.get("pubkey_or_serial"));
    } 
    if (program.is_subcommand_used("load")) {
        return load();
    } 

    std::cout << program;
    return 1;
}

int main(int argc, char* argv[])
{
    try {
        return _main(argc, argv);
    }
    catch (const std::runtime_error& err) {
        std::cerr << err.what() << std::endl;
        return 1;
    }
}
