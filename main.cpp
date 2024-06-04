// Adopted from https://quuxplusone.github.io/blog/2020/01/26/openssl-part-3/
// Author: Arkadi Kagan

#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <iostream>
#include <map>
#include <string>
#include <vector>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

static int print_help(const char* app_name)
{
    char hostname[PATH_MAX];
    gethostname(hostname, sizeof(hostname));
    std::cout
        << "Before using this program, you have to generate certificate:\n"
        << "    openssl ecparam -genkey -name prime256v1 -noout -out server-private-key.pem\n"
        << "    openssl ec -in server-private-key.pem -pubout -out server-public-key.pem\n"
        << "    openssl req -new -x509 -sha256 -key server-private-key.pem -subj \"/CN=" << hostname << "\" -out server-certificate.pem\n"
        << "    sudo cp ./server-certificate.pem /usr/local/share/ca-certificates/server-certificate.crt\n"
        << "\n"
        << "Next, grant port 443 binding permission:\n";
    if (app_name[0] == '/')
        std::cout << "    sudo setcap CAP_NET_BIND_SERVICE=+eip " << app_name << "\n";
    else if (app_name[0] == '.' && app_name[1] == '/')
        std::cout << "    sudo setcap CAP_NET_BIND_SERVICE=+eip " << getenv("PWD") << "/" << app_name + 2 << "\n";
    else
        std::cout << "    sudo setcap CAP_NET_BIND_SERVICE=+eip " << getenv("PWD") << "/" << app_name << "\n";
    std::cout << std::endl;
    return 1;
}

static int print_errors_and_exit(const std::string& msg)
{
    std::cerr << msg << std::endl;
    return -1;
}
[[noreturn]] static void print_errors_and_throw(const std::string& msg)
{
    throw std::runtime_error(msg);
}

static std::string trim(const std::string str)
{
    size_t start = 0;
    while (start < str.length() && isspace(str[start]))
        start++;
    size_t end = str.length();
    while (end > 0 && isspace(str[end - 1]))
        end--;
    return str.substr(start, end);
}

static BIO* accept_new_tcp_connection(BIO* accept_bio)
{
    if (BIO_do_accept(accept_bio) <= 0)
    {
        print_errors_and_exit(strerror(errno));
        return nullptr;
    }
    return BIO_pop(accept_bio);
}

static std::string receive_some_data(BIO* bio)
{
    char buffer[1024];
    int  len = BIO_read(bio, buffer, sizeof(buffer));
    if (len < 0)
    {
        print_errors_and_throw("error in BIO_read");
    }
    else if (len > 0)
    {
        return std::string(buffer, len);
    }
    else if (BIO_should_retry(bio))
    {
        return receive_some_data(bio);
    }
    else
    {
        print_errors_and_throw("empty BIO_read");
    }
}

static std::vector<std::string> split_headers(const std::string& text)
{
    std::vector<std::string> lines;
    const char*              start = text.c_str();
    while (const char* end = strstr(start, "\r\n"))
    {
        lines.push_back(std::string(start, end));
        start = end + 2;
    }
    return lines;
}

static std::string receive_http_message(BIO* bio, std::map<std::string, std::string>& split_header)
{
    std::string headers        = receive_some_data(bio);
    char*       end_of_headers = strstr(&headers[0], "\r\n\r\n");
    while (end_of_headers == nullptr)
    {
        headers += receive_some_data(bio);
        end_of_headers = strstr(&headers[0], "\r\n\r\n");
    }
    std::string body = std::string(end_of_headers + 4, &headers[headers.size()]);
    headers.resize(end_of_headers + 2 - &headers[0]);
    size_t content_length = 0;
    for (const std::string& line : split_headers(headers))
    {
        size_t colon_pos = line.find_first_of(':');
        if (colon_pos != std::string::npos)
        {
            std::string header_name   = trim(line.substr(0, colon_pos));
            std::string value         = trim(line.substr(colon_pos + 1));
            split_header[header_name] = value;
            if (header_name == "Content-Length")
            {
                content_length = std::stoul(value.c_str());
            }
        }
    }
    while (body.size() < content_length)
    {
        body += receive_some_data(bio);
    }
    return headers + "\r\n" + body;
}

static void send_http_response(BIO* bio, const std::string& body)
{
    std::string response = "HTTP/1.1 200 OK\r\n";
    response += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    response += "\r\n";

    BIO_write(bio, response.data(), response.size());
    BIO_write(bio, body.data(), body.size());
    BIO_flush(bio);
}

static SSL* get_ssl(BIO* bio)
{
    SSL* ssl = nullptr;
    BIO_get_ssl(bio, &ssl);
    if (ssl == nullptr)
    {
        print_errors_and_exit("Error in BIO_get_ssl");
    }
    return ssl;
}

static void verify_the_certificate(SSL* ssl)
{
    int err = SSL_get_verify_result(ssl);
    if (err != X509_V_OK)
    {
        const char* message = X509_verify_cert_error_string(err);
        print_errors_and_exit(std::string("Certificate verification error: ") + message + " (error " + std::to_string(err) + ")");
        return;
    }
    X509* cert = SSL_get_peer_certificate(ssl);
    if (cert == nullptr)
    {
        print_errors_and_exit("No certificate was presented by the server");
        return;
    }
}

int main(int cargs, const char** vargs)
{
    if (cargs > 1 && (strcmp(vargs[1], "-?") == 0 ||
                         strcmp(vargs[1], "-h") == 0 ||
                         strcmp(vargs[1], "--help") == 0))
    {
        return print_help(vargs[0]);
    }

    SSL_CTX* ctx_server = SSL_CTX_new(TLS_method());
    SSL_CTX_set_min_proto_version(ctx_server, TLS1_2_VERSION);

    if (SSL_CTX_use_certificate_file(ctx_server, "server-certificate.pem", SSL_FILETYPE_PEM) <= 0)
    {
        return print_errors_and_exit("Error loading server certificate");
    }
    if (SSL_CTX_use_PrivateKey_file(ctx_server, "server-private-key.pem", SSL_FILETYPE_PEM) <= 0)
    {
        return print_errors_and_exit("Error loading server private key");
    }

    SSL_CTX* ctx_client = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_min_proto_version(ctx_client, TLS1_2_VERSION);

    BIO* accept_bio = BIO_new_accept("443");
    if (BIO_do_accept(accept_bio) <= 0)
    {
        return print_errors_and_exit("Error in BIO_do_accept (binding to port 443)");
    }
    int         fd                  = BIO_get_fd(accept_bio, nullptr);
    static auto shutdown_the_socket = [&fd]() {
        close(fd);
    };
    signal(SIGINT, [](int) { shutdown_the_socket(); });

    while (BIO* bio_1 = accept_new_tcp_connection(accept_bio))
    {
        BIO* bio = BIO_new_ssl(ctx_server, 0);
        BIO_push(bio, bio_1);
        try
        {
            std::map<std::string, std::string> split_header;
            std::string                        request = receive_http_message(bio, split_header);
            printf("Got request:\n");
            printf("%s\n", request.c_str());
            std::string connection_string = split_header["Host"];
            BIO*        client_bio        = BIO_new_connect(connection_string.c_str());
            if (client_bio == nullptr)
            {
                print_errors_and_exit("Error in client BIO_new_connect");
            }
            if (BIO_do_connect(client_bio) <= 0)
            {
                print_errors_and_exit("Error in client BIO_do_connect");
            }
            BIO* ssl_bio_client = BIO_new_ssl(ctx_client, 1);
            BIO_push(ssl_bio_client, client_bio);
            SSL_set_tlsext_host_name(get_ssl(ssl_bio_client), split_header["Host"].c_str());
            SSL_set1_host(get_ssl(ssl_bio_client), split_header["Host"].c_str());

            if (BIO_do_handshake(ssl_bio_client) <= 0)
            {
                print_errors_and_exit("Error in client BIO_do_handshake");
            }
            verify_the_certificate(get_ssl(ssl_bio_client));

            BIO_write(ssl_bio_client, request.c_str(), request.length());
            BIO_flush(ssl_bio_client);

            std::string response = receive_http_message(ssl_bio_client, split_header);
            printf("%s\n", response.c_str());

            BIO_write(bio, response.c_str(), response.length());
            BIO_flush(bio);

            BIO_pop(ssl_bio_client);
            BIO_free_all(ssl_bio_client);
            BIO_free_all(client_bio);
        }
        catch (const std::exception& ex)
        {
            printf("Worker exited with exception:\n%s\n", ex.what());
        }
        BIO_pop(bio);
        BIO_free_all(bio);
        BIO_free_all(bio_1);
    }

    BIO_free_all(accept_bio);
    SSL_CTX_free(ctx_server);

    printf("\nClean exit!\n");

    return 0;
}
