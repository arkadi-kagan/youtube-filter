#include "ProxyHTTPS.h"
#include <signal.h>
#include <sys/socket.h>
#include <zip.h>
#include <zlib.h>


static const std::string HTTPS_PORT = "443";

// Proxy for a single proxy/target pair
std::string ProxyHTTPS::trim(const std::string str)
{
    size_t start = 0;
    while (start < str.length() && isspace(str[start]))
        start++;
    size_t end = str.length();
    while (end > 0 && isspace(str[end - 1]))
        end--;
    return str.substr(start, end - start);
}

void ProxyHTTPS::replace_all(std::string& body, const std::string& from, const std::string& to, int regex_group)
{
    std::regex re(from);
    std::smatch m;
    while (std::regex_search(body, m, re))
        body = body.substr(0, m.position(regex_group)) + to + body.substr(m.position(regex_group) + m.length(regex_group));
}

BIO* ProxyHTTPS::accept_new_tcp_connection(BIO* accept_bio)
{
    if (BIO_do_accept(accept_bio) <= 0)
    {
        std::cerr << strerror(errno) << std::endl;
        return nullptr;
    }
    return BIO_pop(accept_bio);
}

std::vector<uint8_t> ProxyHTTPS::receive_some_data(BIO* bio)
{
    uint8_t buffer[1024];
    int  len = BIO_read(bio, buffer, sizeof(buffer));
    if (len < 0)
    {
        std::cerr << "error in BIO_read" << std::endl;
    }
    else if (len > 0)
    {
        return std::vector<uint8_t>(buffer, buffer + len);
    }
    else if (BIO_should_retry(bio))
    {
        return receive_some_data(bio);
    }
    else
    {
        std::cerr << "empty BIO_read" << std::endl;
    }
    return {};
}

std::vector<std::string> ProxyHTTPS::split_headers(const std::string& text)
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

void ProxyHTTPS::send_http_message(BIO* bio, const std::map<std::string, std::string>& split_header, const std::vector<uint8_t>& body)
{
    std::string enter = "\r\n";
    std::string header_separator = ": ";
    std::vector<uint8_t> buffer;
    if (split_header.count("---START---") == 0)
        return;
    for (const auto& pair : split_header)
    {
        if (pair.first == "---START---")
        {
            buffer.insert(buffer.begin(), pair.second.begin(), pair.second.end());
        }
        else
        {
            buffer.insert(buffer.end(), pair.first.begin(), pair.first.end());
            buffer.insert(buffer.end(), header_separator.begin(), header_separator.end());
            buffer.insert(buffer.end(), pair.second.begin(), pair.second.end());
        }
        buffer.insert(buffer.end(), enter.begin(), enter.end());
    }
    buffer.insert(buffer.end(), enter.begin(), enter.end());
    buffer.insert(buffer.end(), body.begin(), body.end());

    BIO_write(bio, buffer.data(), buffer.size());
    BIO_flush(bio);

    // Print for debugging
    // buffer.insert(buffer.end(), 0);
    // printf("Debug send_http_message:\n%s\n", buffer.data());
}

void ProxyHTTPS::read_chunked(BIO* bio, std::vector<uint8_t>& body)
{
    // See https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Transfer-Encoding#directives
    size_t i, chunk_size_start, chunk_size_end;
    long chunk_size;
    enum Status { NOTHING, CHUNK_SIZE_STARTED, CHUNK_SIZE_R, CHUNK_SIZE_N, END };
    Status status = NOTHING;
    std::vector<uint8_t> buffer;
    buffer.insert(buffer.begin(), body.begin(), body.end());
    body.clear();

    while (status != END)
    {
        switch (status)
        {
        case NOTHING:
            if (buffer.empty())
                buffer = receive_some_data(bio);
            if (buffer.empty())
            {
                status = END;
                break;
            }
            chunk_size_start = 0;
            chunk_size_end = 1;
            status = CHUNK_SIZE_STARTED;
            if (!isxdigit(buffer[chunk_size_start]))
            {
                std::cerr << "Wrong chunk size" << std::endl;
                status = END;
            }
            break;
        case CHUNK_SIZE_STARTED:
            if (buffer.size() == chunk_size_end)
            {
                auto tmp = receive_some_data(bio);
                if (tmp.empty())
                {
                    std::cerr << "Wrong chunk size" << std::endl;
                    status = END;
                    break;
                }
                buffer.insert(buffer.end(), tmp.begin(), tmp.end());
            }
            if (buffer[chunk_size_end] == '\r')
            {
                chunk_size = strtol((char*)&buffer[chunk_size_start], nullptr, 16);
                if (chunk_size == 0)
                    status = END;
                else
                    status = CHUNK_SIZE_R;
                break;
            }
            if (!isxdigit(buffer[chunk_size_end]))
            {
                std::cerr << "Wrong chunk size" << std::endl;
                status = END;
                break;
            }
            chunk_size_end++;
            break;
        case CHUNK_SIZE_R:
            if (buffer.size() == chunk_size_end + 1)
            {
                auto tmp = receive_some_data(bio);
                if (tmp.empty())
                {
                    std::cerr << "Wrong chunk size" << std::endl;
                    status = END;
                    break;
                }
                buffer.insert(buffer.end(), tmp.begin(), tmp.end());
            }
            if (buffer[chunk_size_end + 1] != '\n')
            {
                std::cerr << "Wrong chunk size" << std::endl;
                status = END;
                break;
            }
            status = CHUNK_SIZE_N;
            break;
        case CHUNK_SIZE_N:
            buffer.erase(buffer.begin() + chunk_size_start, buffer.begin() + chunk_size_end + 2); // chunk_size + "\r\n"
            while (buffer.size() < chunk_size + 2)  // Read trailing "\r\n" as well
            {
                auto tmp = receive_some_data(bio);
                if (tmp.empty())
                {
                    std::cerr << "Wrong chunk size" << std::endl;
                    status = END;
                    break;
                }
                buffer.insert(buffer.end(), tmp.begin(), tmp.end());
            }
            body.insert(body.end(), buffer.begin(), buffer.begin() + chunk_size);
            if (status == END)
                break;
            if (buffer[chunk_size] != '\r' || buffer[chunk_size + 1] != '\n')
            {
                std::cerr << "Wrong chunk size" << std::endl;
                status = END;
                break;
            }
            buffer.erase(buffer.begin(), buffer.begin() + chunk_size + 2);
            status = NOTHING;
            break;
        case END:
            break;
        }
    }
}

std::vector<uint8_t> ProxyHTTPS::receive_http_message(BIO* bio, std::map<std::string, std::string>& split_header)
{
    split_header.clear();
    std::vector<uint8_t> headers        = receive_some_data(bio);
    if (headers.empty())
        return {};
    char*       end_of_headers = strstr((char*)&headers[0], "\r\n\r\n");
    while (end_of_headers == nullptr)
    {
        auto tmp = receive_some_data(bio);
        headers.insert(headers.end(), tmp.begin(), tmp.end());
        end_of_headers = strstr((char*)&headers[0], "\r\n\r\n");
    }
    std::vector<uint8_t> body((uint8_t*)end_of_headers + 4, &headers[headers.size()]);
    end_of_headers[2] = 0;
    size_t content_length = 0;
    for (const std::string& line : split_headers((char*)&headers[0]))
    {
        size_t colon_pos = line.find_first_of(':');
        if (split_header.empty())
        {
            split_header["---START---"] = trim(line);
        }
        else if (colon_pos != std::string::npos)
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
    if (split_header.count("---START---") == 0)
        return body;
    if (split_header.count("Content-Length") > 0)
    {
        while (body.size() < content_length)
        {
            auto tmp = receive_some_data(bio);
            body.insert(body.end(), tmp.begin(), tmp.end());
        }
    }
    else if (split_header["---START---"].substr(0, 4) == "HTTP" && split_header.count("Transfer-Encoding") > 0 && split_header["Transfer-Encoding"] == "chunked")
    {
        read_chunked(bio, body);
        split_header.erase("Transfer-Encoding");
        split_header["Content-Length"] = std::to_string(body.size());
    }
    return body;
}

SSL* ProxyHTTPS::get_ssl(BIO* bio)
{
    SSL* ssl = nullptr;
    BIO_get_ssl(bio, &ssl);
    if (ssl == nullptr)
    {
        std::cerr << "Error in BIO_get_ssl" << std::endl;
    }
    return ssl;
}

void ProxyHTTPS::verify_the_certificate(SSL* ssl)
{
    int err = SSL_get_verify_result(ssl);
    if (err != X509_V_OK)
    {
        const char* message = X509_verify_cert_error_string(err);
        std::cerr << "Certificate verification error: " << message << " (error " << err << ")" << std::endl;
        return;
    }
    X509* cert = SSL_get_peer_certificate(ssl);
    if (cert == nullptr)
    {
        std::cerr << "No certificate was presented by the server" << std::endl;
        return;
    }
}

void ProxyHTTPS::set_timeout(BIO* bio)
{
    int fd = BIO_get_fd(bio, nullptr);
    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof tv);
}

void ProxyHTTPS::replace_domain_name(std::string& buffer, const std::string& from, const std::string& to)
{
    size_t pos = 0;
    while (true)
    {
        pos = buffer.find(from, pos);
        while (pos != std::string::npos && pos > 0)
        {
            if (buffer[pos - 1] != '.' && !isalnum(buffer[pos - 1]))
                break;
            if (pos >= 3 && buffer.substr(pos - 3, 3) == "%2F") // encoded "/", as in "https://"
                break;
            if (pos >= 5 && buffer.substr(pos - 5, 5) == "%252F")
                break;
            if (pos >= 2 && buffer[pos - 1] == '.' && !isalnum(buffer[pos - 2]))
                break;
            pos = buffer.find(from, pos + 1);
        }
        if (pos == std::string::npos)
            break;
        buffer =
            buffer.substr(0, pos) +
            to +
            buffer.substr(pos + from.length());
        pos += from.length();
    }
}

void ProxyHTTPS::replace_all_server_to_target(std::vector<uint8_t>& buffer, const std::string& host_name)
{
    std::string buffer_str((char*)buffer.data(), buffer.size());
    replace_all_server_to_target(buffer_str, host_name);
    buffer.clear();
    buffer.insert(buffer.end(), buffer_str.begin(), buffer_str.end());
}
void ProxyHTTPS::replace_all_server_to_target(std::string& buffer, const std::string& host_name)
{
    for (const auto& pair : m_server_port_to_target)
    {
        replace_domain_name(buffer, host_name + ":" + pair.first, pair.second);
        replace_domain_name(buffer, host_name + "%3A" + pair.first, pair.second);
        replace_domain_name(buffer, host_name + "%253A" + pair.first, pair.second);
    }
}

void ProxyHTTPS::replace_all_target_to_server_and_filter(
    std::vector<uint8_t>& buffer,
    const std::string& host_name,
    const std::map<std::string, std::string>& request_header)
{
    std::string buffer_str((char*)buffer.data(), buffer.size());
    adopt_all_domain_names(buffer_str);
    filter(buffer_str, request_header);
    replace_all_target_to_server(buffer_str, host_name);
    buffer.clear();
    buffer.insert(buffer.end(), buffer_str.begin(), buffer_str.end());
}
void ProxyHTTPS::replace_all_target_to_server(std::string& buffer, const std::string& host_name)
{
    for (const auto& pair : m_server_port_to_target)
    {
        replace_domain_name(buffer, pair.second + ":" + HTTPS_PORT, host_name + ":" + pair.first);
        replace_domain_name(buffer, pair.second, host_name + ":" + pair.first);
    }
}

std::vector<uint8_t> ProxyHTTPS::unzip(const std::vector<uint8_t>& buffer)
{
    zip_error_t ziperr = {0};
    zip_source_t* src = zip_source_buffer_create(buffer.data(), buffer.size(), 0, &ziperr);
    if (src == nullptr)
        return buffer;
    std::vector<uint8_t> result;
    zip_t* zip = zip_open_from_source(src, ZIP_RDONLY, &ziperr);
    if (zip_get_num_entries(zip, ZIP_FL_NODIR) == 1)
    {
        zip_stat_t stat;
        zip_stat_init(&stat);
        zip_source_stat(src, &stat);
        result.resize(stat.size);
        zip_file_t* f = zip_fopen_index(zip, 0, ZIP_FL_NODIR);
        zip_fread(f, result.data(), result.size());
        zip_fclose(f);
    }
    else
    {
        result = buffer;
    }
    zip_close(zip);
    return result;
}

std::vector<uint8_t> ProxyHTTPS::ungzip(const std::vector<uint8_t>& buffer)
{
    // http://zlib.net/zlib_how.html
    constexpr const int CHUNK = 16384;
    int ret;
    z_stream strm;

    // allocate inflate state
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = 0;
    strm.next_in = Z_NULL;
    ret = inflateInit(&strm);
    if (ret != Z_OK)
        return buffer;

    // un-gzip in one chunk - do garbage otherwise
    strm.avail_in = buffer.size();
    strm.next_in = (uint8_t*)buffer.data();
    std::vector<uint8_t> result(CHUNK);
    strm.avail_out = result.size();
    strm.next_out = result.data();
    ret = inflate(&strm, Z_NO_FLUSH);
    if (ret == Z_STREAM_END)
        result.resize(strm.total_out);
    else
        result = buffer;

    inflateEnd(&strm);

    return result;
}

bool ProxyHTTPS::is_text(const std::string& content_type)
{
    if (content_type.find("text/html") != std::string::npos)
        return true;
    if (content_type.find("text/javascript") != std::string::npos)
        return true;
    return false;
}

void ProxyHTTPS::adopt_all_domain_names(const std::string& buffer)
{
    std::set<std::string> ignore = {
        "about",
        "www.",
    };
    std::vector<std::string> https_tokens = {
        "https://",
        "https%3A%2F%2F",
        "https%253A%252F%252F",
        "href=\"//",
    };

    for (const auto& https : https_tokens)
    {
        size_t pos = 0;
        while (pos != std::string::npos)
        {
            pos = buffer.find(https, pos);
            if (pos == std::string::npos)
                break;
            pos += https.length();
            size_t start = pos;
            while (
                    isalnum(buffer[pos]) ||
                    strchr(".-\\", buffer[pos]) != nullptr
                    )
                pos++;
            std::string target = buffer.substr(start, pos - start);
            target.erase(std::remove(target.begin(), target.end(), '\\'), target.end());    // https://stackoverflow.com/a/20326454
            if (target.empty())
                continue;
            if (ignore.count(target) > 0)
                continue;
            adopt_site(target);
        }
    }
}

void ProxyHTTPS::init(
    const std::string& host_name,
    int first_port,
    const std::string& main_target)
{
    m_host_name = host_name;
    m_first_port = first_port;
    adopt_site(main_target);
}

std::string ProxyHTTPS::wget_text(const std::string& target, const std::string& path)
{
    std::string url = "https://" + target;
    std::string result;
    try
    {
        SSL_CTX* ctx_client = SSL_CTX_new(TLS_client_method());
        SSL_CTX_set_min_proto_version(ctx_client, TLS1_2_VERSION);

        if (SSL_CTX_set_default_verify_paths(ctx_client) != 1)
        {
            std::cerr << "Error setting up trust store" << std::endl;
            return "";
        }

        std::string connection_string = target + ":" + HTTPS_PORT;
        BIO*        client_bio        = BIO_new_connect(connection_string.c_str());
        if (client_bio == nullptr)
        {
            std::cerr << "Error in client BIO_new_connect" << std::endl;
        }
        if (BIO_do_connect(client_bio) <= 0)
        {
            std::cerr << "Error in client BIO_do_connect" << std::endl;
        }
        BIO* ssl_bio_client = BIO_new_ssl(ctx_client, 1);
        BIO_push(ssl_bio_client, client_bio);

        SSL_set_tlsext_host_name(get_ssl(ssl_bio_client), target.c_str());
        SSL_set1_host(get_ssl(ssl_bio_client), target.c_str());

        if (BIO_do_handshake(ssl_bio_client) <= 0)
        {
            std::cerr << "Error in client BIO_do_handshake" << std::endl;
        }
        verify_the_certificate(get_ssl(ssl_bio_client));

        send_http_message(
            ssl_bio_client,
            {
                {"---START---", "GET " + path + " HTTP/1.1"},
                {"Host", target},
                {"Accept-Encoding", "identity"},
                {"Cache-Control", "no-cache"},
                {"Pragma", "no-cache"},
                {"User-Agent", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0"},
                {"Connection", "keep-alive"},
            },
            {});

        std::map<std::string, std::string> response_header;
        std::vector<uint8_t> response_body = receive_http_message(ssl_bio_client, response_header);
        result = std::string((char*)response_body.data(), response_body.size());

        BIO_pop(ssl_bio_client);
        BIO_free_all(ssl_bio_client);
        BIO_free_all(client_bio);
    }
    catch (const std::exception& ex)
    {
        std::cerr << "Failed to read \"" << url << "\":\n" << ex.what() << std::endl;
    }
    return result;
}

int ProxyHTTPS::run_single_port(const std::string& host_name, const std::string& server_port)
{
    signal(SIGPIPE, SIG_IGN);

    std::string target = m_server_port_to_target[server_port];

    SSL_CTX* ctx_server = SSL_CTX_new(TLS_server_method());
    SSL_CTX_set_min_proto_version(ctx_server, TLS1_2_VERSION);

    if (SSL_CTX_use_certificate_file(ctx_server, "server-certificate.pem", SSL_FILETYPE_PEM) <= 0)
    {
        std::cerr << "Error loading server certificate" << std::endl;
        return -1;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx_server, "server-private-key.pem", SSL_FILETYPE_PEM) <= 0)
    {
        std::cerr << "Error loading server private key" << std::endl;
        return -1;
    }
    if (SSL_CTX_check_private_key(ctx_server) <= 0)
    {
        std::cerr << "Private key is not valid" << std::endl;
        return -1;
    }

    SSL_CTX* ctx_client = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_min_proto_version(ctx_client, TLS1_2_VERSION);

    if (SSL_CTX_set_default_verify_paths(ctx_client) != 1)
    {
        std::cerr << "Error setting up trust store" << std::endl;
        return -1;
    }

    BIO* accept_bio = BIO_new_accept(server_port.c_str());
    if (BIO_do_accept(accept_bio) <= 0)
    {
        std::cerr << "Error in BIO_do_accept (binding to port " << server_port << ")" << std::endl;
        return -1;
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
            set_timeout(bio);

            std::map<std::string, std::string> request_header;
            std::vector<uint8_t> request_body = receive_http_message(bio, request_header);
            if (request_header.count("---START---") == 0)
            {
                BIO_free_all(bio);
                continue;
            }
            if (is_text(request_header["Accept"]))
                request_header["Accept-Encoding"] = "identity";

            for (auto& request_pair : request_header)
            {
                replace_all_server_to_target(request_pair.second, host_name);
                adopt_all_domain_names(request_pair.second);
            }
            replace_all_server_to_target(request_body, host_name);
            
            std::cout << "Request from " << server_port << ": " << request_header["---START---"] << std::endl;

            std::string connection_string = target + ":" + HTTPS_PORT;
            BIO*        client_bio        = BIO_new_connect(connection_string.c_str());
            if (client_bio == nullptr)
            {
                std::cerr << "Error in client BIO_new_connect" << std::endl;
            }
            if (BIO_do_connect(client_bio) <= 0)
            {
                std::cerr << "Error in client BIO_do_connect" << std::endl;
            }
            BIO* ssl_bio_client = BIO_new_ssl(ctx_client, 1);
            BIO_push(ssl_bio_client, client_bio);

            set_timeout(ssl_bio_client);

            SSL_set_tlsext_host_name(get_ssl(ssl_bio_client), target.c_str());
            SSL_set1_host(get_ssl(ssl_bio_client), target.c_str());

            if (BIO_do_handshake(ssl_bio_client) <= 0)
            {
                std::cerr << "Error in client BIO_do_handshake" << std::endl;
            }
            verify_the_certificate(get_ssl(ssl_bio_client));

            send_http_message(ssl_bio_client, request_header, request_body);

            std::map<std::string, std::string> response_header;
            std::vector<uint8_t> response_body = receive_http_message(ssl_bio_client, response_header);

            if (response_header.count("Content-Encoding") > 0 && response_header["Content-Encoding"] == "zip")
            {
                response_body = unzip(response_body);
                response_header["Content-Encoding"] = "identity";
            }

            if (response_header.count("Content-Encoding") > 0 && response_header["Content-Encoding"] == "gzip")
            {
                response_body = ungzip(response_body);
                response_header["Content-Encoding"] = "identity";
            }

            if (is_text(response_header["Content-Type"]))
                replace_all_target_to_server_and_filter(response_body, host_name, request_header);

            if (response_header.count("Content-Length") > 0)
                response_header["Content-Length"] = std::to_string(response_body.size());
            
            response_header["Access-Control-Allow-Origin"] = "*";

            for (auto& response_pair : response_header)
            {
                adopt_all_domain_names(response_pair.second);
                replace_all_target_to_server(response_pair.second, host_name);
            }

            std::cout << "Response to " << server_port << ": " << response_header["---START---"] << std::endl;

            send_http_message(bio, response_header, response_body);

            BIO_pop(ssl_bio_client);
            BIO_free_all(ssl_bio_client);
            BIO_free_all(client_bio);
        }
        catch (const std::exception& ex)
        {
            std::cerr << "Worker exited with exception:\n" << ex.what() << std::endl;
        }

        BIO_free_all(bio);
    }

    BIO_free_all(accept_bio);
    SSL_CTX_free(ctx_server);

    std::cout << "\nClean exit for target \"" << target << "\"" << std::endl;

    return 0;
}

int ProxyHTTPS::run()
{
    for (auto& th : m_threads)
        th.join();
    return 0;
}

void ProxyHTTPS::adopt_site(const std::string& target)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_target_to_server_port.count(target) > 0)
        return;
    std::set<int> skip_ports = {
        5060, 5061,     // Default for Voice Over IP
    };
    int next_port = m_first_port;
    if (!m_server_port_to_target.empty())
        next_port = atoi(m_server_port_to_target.rbegin()->first.c_str()) + 1;
    while (skip_ports.count(next_port) > 0)
        next_port++;
    std::string next_port_str = std::to_string(next_port);
    m_target_to_server_port[target] = next_port_str;
    m_server_port_to_target[next_port_str] = target;

    std::cout << "Adopted " << target << " = " << m_host_name << ":" << next_port << std::endl;

    m_threads.push_back(std::thread([this, next_port_str](){
        run_single_port(m_host_name, next_port_str);
    }));
}

void ProxyHTTPS::filter(std::string& buffer, const std::map<std::string, std::string>& request_header)
{
    // This filter will be filled with debug code.
    // Real filter must be implemented in ProxyHTTPS heir.
    std::vector<std::string> tokens = {
        "action_handle_signin",
    };
    for (const auto& token : tokens)
    {
        auto pos = buffer.find(token);
        if (pos != std::string::npos)
        {
            std::cout << "Found " << token << std::endl;
            if (pos > 40)
                std::cout << "\t" << buffer.substr(pos - 40, 70) << std::endl;
            else
                std::cout << "\t" << buffer.substr(0, 20) << std::endl;
            std::cout << "request_header:\n";
            for (const auto& pair : request_header)
            {
                std::cout << pair.first << ": " << pair.second << std::endl;
            }
        }
    }
}
