#pragma once

#include <string>
#include <iostream>
#include <map>
#include <set>
#include <string>
#include <vector>
#include <regex>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

// Proxy for a single proxy/target pair
class ProxyHTTPS
{
protected:
    std::string trim(const std::string str);
    void replace_all(std::string& body, const std::string& from, const std::string& to, int regex_group = 0);

    BIO* accept_new_tcp_connection(BIO* accept_bio);
    std::vector<uint8_t> receive_some_data(BIO* bio);
    std::vector<std::string> split_headers(const std::string& text);
    void send_http_message(BIO* bio, const std::map<std::string, std::string>& split_header, const std::vector<uint8_t>& body);
    void read_chunked(BIO* bio, std::vector<uint8_t>& body);
    std::vector<uint8_t> receive_http_message(BIO* bio, std::map<std::string, std::string>& split_header);
    SSL* get_ssl(BIO* bio);
    void verify_the_certificate(SSL* ssl);

    std::string regex_encode(const std::string& value);
    void replace_domain_name(std::string& buffer, const std::string& from, const std::string& to);
    void replace_all_server_to_target(std::vector<uint8_t>& buffer, const std::string& host_name);
    void replace_all_server_to_target(std::string& buffer, const std::string& host_name);
    void replace_all_target_to_server_and_filter(
        std::vector<uint8_t>& buffer,
        const std::string& host_name,
        const std::map<std::string, std::string>& request_header);
    void replace_all_target_to_server(std::string& buffer, const std::string& host_name);

    bool is_text(const std::string& content_type);

    int run_single_port(const std::string& host_name, const std::string& server_port);

    virtual void filter(std::string& buffer, const std::map<std::string, std::string>& request_header);

protected:
    std::map<std::string, std::string> m_server_port_to_target;

public:
    void init(
        const std::string& host_name,
        int first_port,
        const std::string& main_target,
        const std::map<std::string, std::string>& other_targets,
        const std::vector<std::string>& filenames);

    int run(const std::string& host_name);

    std::string wget_text(const std::string& target, const std::string& path);
};
