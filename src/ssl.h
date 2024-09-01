#pragma once

// Standard libraries
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <string>
#include <array>
#include <unordered_map>
#include <cstring>

// C libraries
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <ifaddrs.h>

// OpenSSL libraries
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <vector>

// Custom types
#include <cstdint>  // for uintptr_t
using CertificateMap = std::unordered_map<std::string, std::pair<in_port_t,std::string>>; //maps P2P-ID to <port,certificate>

enum class SSLStatus{
    ACCEPTED = 0 ,                  //Server status: SSL Connection was accepted successfully. Encryption works, we authenticated ourself.
    CONNECTED,                      //Client status: SSL Connection was conntected successfully. Encryption works, authenticity of peer ensured.
    HANDSHAKE_SERVER_WRITE_CERT,    //Server status: Server has not been able to flush certificate (send). Retry until fully flushed.
    HANDSHAKE_CLIENT_READ_CERT,     //Client status: Client has not been able to receive full server certificate. Retry until fully available.
    AWAITING_ACCEPT,                //Server status: Transitioned from HANDSHAKE_SERVER_WRITE_CERT. Server has fully flushed certificate. Waits on accept() for the client's connect(). NOTE: SLIGHT AMBIGUITY. Status with AWAITING... means that we wait on the function. WE CALL THE AWAITED FUNCTION.
    AWAITING_CONNECT,               //Client status: Transitioned from HANDSHAKE_CLIENT_READ_CERT. Client has fully read certificate. Waits on connect() for the server's accept(). NOTE: SLIGHT AMBIGUITY. Status with AWAITING... means that we wait on the function. WE CALL THE AWAITED FUNCTION.
    FATAL_ERROR_ACCEPT_CONNECT      //Universal status: Major malfunction of / deviation from protocol. Error state used to indicate a (near) future tear_down_connection()
};

namespace NetworkUtils {
    bool is_non_blocking(int fd);
    bool getIPv6(char* buffer, size_t size);
    void send_data_with_length_prefix(int sock_fd, const char* data, size_t length);
    char* receive_data_with_length_prefix(int sock_fd, size_t& length);
    void prepare_data_with_length_prefix(std::vector<unsigned char>& buffer, const char* data, size_t length);
    char* extract_data_with_length_prefix(const std::vector<unsigned char>& buffer, size_t& length);
}

namespace SSLUtils {
    void check_ssl_blocking_mode(SSL* ssl);
    SSL_CTX* create_context(bool am_i_server);
    void send_certificate(int client_fd, X509* cert);
    void receive_certificate(int sock_fd, X509*& cert);
    void set_certificate_sendBuffer(int client_fd, X509* cert);

    void write_test_msg(SSL* ssl);
    void read_test_msg(SSL* ssl, char* buffer, size_t buflen);
    bool compare_x509_certs(X509* cert1, X509* cert2);
    bool compare_x509_cert_with_pem(X509* received_cert, const std::string& stored_pem_str);
    bool extract_ipv6_from_cert(X509* cert, std::string& ipv6);
    bool extract_custom_id(X509* cert, unsigned char* received_id);
    SSLStatus try_ssl_accept(SSL* ssl);
    SSLStatus try_ssl_connect(SSL* ssl);
    bool isAliveSSL(SSLStatus status);
    X509* load_cert_from_char(const unsigned char* cert_str, size_t cert_len);
}

namespace KeyUtils {
    EVP_PKEY* generate_rsa_key();
    void save_private_key(EVP_PKEY* pkey, const std::string& filename);
    void save_public_key(EVP_PKEY* pkey, const std::string& filename);
}

namespace CertUtils {
    X509* create_self_signed_cert(EVP_PKEY* pkey, const std::string& ipv6, const std::string& id);
    void save_certificate(X509* cert, const std::string& filename);
    CertificateMap load_certificate_map(const std::string& filename);
    void save_certificate_map(const CertificateMap& cert_map, const std::string& filename);
}

namespace Utils {
    std::string bin_to_hex(const unsigned char* data, size_t len);
    void print_hex(const unsigned char* s, size_t length);
}