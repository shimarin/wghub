#include <string.h>
#include <nss.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <string>
#include <cassert>
#include <fstream>
#include <optional>
#include <filesystem>

static const std::filesystem::path serial_dir("/var/lib/wghub/serial");

static struct in6_addr lookup(const std::string& hostname)
{
    std::optional<std::filesystem::path> serial_file = std::nullopt;
    for (const auto& entry : std::filesystem::directory_iterator(serial_dir)) {
        if (!entry.is_regular_file()) continue;
        const auto& serial = entry.path().filename().string();
        if (std::equal(serial.begin(), serial.end(), hostname.begin(), hostname.end(), [](char c1, char c2) {
            return std::tolower(c1) == std::tolower(c2);
        })) {
            serial_file = entry.path();
            break;
        }
    }

    if (!serial_file) throw NSS_STATUS_NOTFOUND;

    std::string address;

    {
        std::ifstream f(serial_file.value());
        if (!f) throw NSS_STATUS_NOTFOUND;

        f >> address; // skip pubkey
        f >> address;
    }

    if (address == "") throw NSS_STATUS_NOTFOUND;

    struct in6_addr addr;
    if (inet_pton(AF_INET6, address.c_str(), &addr) != 1) {
        throw NSS_STATUS_NOTFOUND;
    }
    //else
    return addr;
}

#define ALIGN(a) (((a+sizeof(void*)-1)/sizeof(void*))*sizeof(void*))

static enum nss_status fill_in_hostent(
                                const char *hn,
                struct hostent *result,
                char *buffer, size_t buflen,
                int *errnop, int *h_errnop,
                                int32_t *ttlp,
                char **canonp,
                                const struct in6_addr& addr) {

        size_t alen = sizeof(in6_addr);

        size_t l = strlen(hn);
        size_t ms = ALIGN(l+1)+sizeof(char*)+ALIGN(alen)+sizeof(char*)*2;
        if (buflen < ms) {
                *errnop = ENOMEM;
                *h_errnop = NO_RECOVERY;
                return NSS_STATUS_TRYAGAIN;
        }

        /* First, fill in hostname */
        char* r_name = buffer;
        memcpy(r_name, hn, l+1);
        size_t idx = ALIGN(l+1);

        /* Second, create aliases array */
        char* r_aliases = buffer + idx;
        *(char**) r_aliases = NULL;
        idx += sizeof(char*);

        /* Third, add address */
        char* r_addr = buffer + idx;
        *(struct in6_addr*) r_addr = addr;
        idx += ALIGN(alen);

        /* Fourth, add address pointer array */
        char* r_addr_list = buffer + idx;
        ((char**) r_addr_list)[0] = r_addr;
        ((char**) r_addr_list)[1] = NULL;
        idx += sizeof(char*)*2;

        /* Verify the size matches */
        assert(idx == ms);

        result->h_name = r_name;
        result->h_aliases = (char**) r_aliases;
        result->h_addrtype = AF_INET6;
        result->h_length = alen;
        result->h_addr_list = (char**) r_addr_list;

        if (ttlp) *ttlp = 0;
        if (canonp) *canonp = r_name;

        return NSS_STATUS_SUCCESS;
}

extern "C" {
enum nss_status _nss_wghub_gethostbyname3_r(
                const char *name,
                int af,
                struct hostent *host,
                char *buffer, size_t buflen,
                int *errnop, int *h_errnop,
                int32_t *ttlp,
                char **canonp) {

        if (af == AF_UNSPEC) af = AF_INET6;

        if (af != AF_INET6) {
                *errnop = EAFNOSUPPORT;
                *h_errnop = NO_DATA;
                return NSS_STATUS_UNAVAIL;
        }

        try {
                auto addr = lookup(name);
                return fill_in_hostent(name, host, buffer, buflen, errnop, h_errnop, ttlp, canonp, addr);
        }
        catch (enum nss_status& st) {
                if (st == NSS_STATUS_NOTFOUND) {
                        *errnop = ENOENT;
                        *h_errnop = HOST_NOT_FOUND;
                } else if (st == NSS_STATUS_TRYAGAIN) {
                        *errnop = EINVAL;
                        *h_errnop = NO_RECOVERY;
                } else {
                        *errnop = EINVAL;
                        *h_errnop = NO_RECOVERY;
                }
                return st;
        }
}

enum nss_status _nss_wghub_gethostbyname2_r(
                const char *name,
                 int af,
                 struct hostent *host,
                char *buffer, size_t buflen,
                 int *errnop, int *h_errnop) {

         return _nss_wghub_gethostbyname3_r(
                         name,
                         af,
                         host,
                         buffer, buflen,
                         errnop, h_errnop,
                         NULL,
                         NULL);
}

enum nss_status _nss_wghub_gethostbyname_r(
        const char *name,
        struct hostent* host,
        char *buffer, size_t buflen,
        int *errnop, int *h_errnop
        ) {

        try {
                auto addr = lookup(name);
                return fill_in_hostent(name, host, buffer, buflen, errnop, h_errnop, NULL, NULL, addr);
        }
        catch (enum nss_status& st) {
                if (st == NSS_STATUS_NOTFOUND) {
                        *errnop = ENOENT;
                        *h_errnop = HOST_NOT_FOUND;
                } else if (st == NSS_STATUS_TRYAGAIN) {
                        *errnop = EINVAL;
                        *h_errnop = NO_RECOVERY;
                } else {
                        *errnop = EINVAL;
                        *h_errnop = NO_RECOVERY;
                }
                return st;
        }

}
} // extern "C"
