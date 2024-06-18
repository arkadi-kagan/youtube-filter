// Adopted from https://quuxplusone.github.io/blog/2020/01/26/openssl-part-3/
// and https://www.openssl.org/docs/man1.1.1/man3/BIO_do_handshake.html
// Author: Arkadi Kagan

#include "ProxyHTTPS.h"
#include <string.h>
#include <signal.h>
#include <unistd.h>

static const int SERVER_PORT = 5000;
static const std::string TARGET_HOST = "www.youtube.com";
// static const std::string TARGET_HOST = "www.google.com";
static char g_hostname[PATH_MAX];


static int print_help(const char* app_name)
{
    std::cout
        << "Before using this program, you have to generate certificate:\n"
        << "    openssl ecparam -genkey -name prime256v1 -noout -out server-private-key.pem\n"
        << "    openssl ec -in server-private-key.pem -pubout -out server-public-key.pem\n"
        << "    openssl req -new -x509 -sha256 -key server-private-key.pem -subj \"/CN=" << g_hostname << "\" -out server-certificate.pem\n"
        << "    sudo cp ./server-certificate.pem /usr/local/share/ca-certificates/server-certificate.crt\n";
    std::cout << std::endl;
    return 1;
}

static bool save_text(const std::string& buffer, const std::string& filename)
{
    FILE* f = fopen(filename.c_str(), "w");
    if (f == nullptr)
        return false;
    fwrite(buffer.c_str(), 1, buffer.length(), f);
    fclose(f);
    return true;
}

int main(int cargs, const char** vargs)
{
    // Ignore SIGPIPE: https://github.com/Azure/azure-iot-sdk-c/issues/1423#issuecomment-668655861
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGPIPE);
    pthread_sigmask(SIG_BLOCK, &set, NULL);


    char hostname[PATH_MAX];
    gethostname(hostname, sizeof(hostname));
    std::cout << "HTTPS proxy server from \"https://" << hostname << ":" << SERVER_PORT << "\" to \"https://" << TARGET_HOST << "\"\n";
    std::cout << "Author: Arkadi Kagan\n" << std::endl;

    if (cargs > 1 && (strcmp(vargs[1], "-?") == 0 ||
                         strcmp(vargs[1], "-h") == 0 ||
                         strcmp(vargs[1], "--help") == 0))
    {
        return print_help(vargs[0]);
    }

    ProxyHTTPS proxy;
    proxy.init(hostname, SERVER_PORT, TARGET_HOST, std::map<std::string, std::string>{
        {"accounts.google.com", "/"},
        {"accounts.youtube.com", "/"},
    },{
        "/base.js",
        "/desktop_polymer.js",
    });
    return proxy.run(hostname);
}
