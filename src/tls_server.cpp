#include "ssl.cpp"
#include <iostream>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <cstring>
#include <sstream>
#include <fstream>
#include <iomanip>
#include <unordered_map>
#include <cstdint>  // for uintptr_t

#define P2PServerPort 7402

// Define a type for the certificate map
using CertificateMap = std::unordered_map<std::string, std::string>; //maps IDs to certificates

bool getIPv6(char* buffer, size_t size){
    ifaddrs *interfaces, *ifa;
    char ipstr[INET6_ADDRSTRLEN];

    if (getifaddrs(&interfaces) == -1) {
        std::cerr << "getifaddrs failed, unable to find IPv6 addr." << std::endl;
        return false;
    }

    for(ifa = interfaces; ifa != 0; ifa= ifa->ifa_next){
        if(ifa->ifa_addr == NULL){
            continue;
        }
        if(ifa->ifa_addr->sa_family == AF_INET6){
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)ifa->ifa_addr;

            if(inet_ntop(AF_INET6,&ipv6->sin6_addr,ipstr,size) != NULL){
                std::strncpy(buffer,ipstr, size);
                freeifaddrs(interfaces); // Free memory and exit early
                return true;
            }
        }
    }
    //No IPv6 interface available.
    freeifaddrs(interfaces);
    return false;

}

// Function to save the private key to a file
void save_private_key(EVP_PKEY* pkey, const std::string& filename) {
    FILE* file = fopen(filename.c_str(), "w+b"); //write as new binary file (w+b inary)
    if (file) {
        PEM_write_PrivateKey(file, pkey, nullptr, nullptr, 0, nullptr, nullptr);
        fclose(file);
    } else {
        std::cerr << "Failed opening file for writing private key" << std::endl;
    }
}

void save_public_key(EVP_PKEY* pkey, const std::string& filename) {
    FILE* file = fopen(filename.c_str(), "w+b"); //write as new binary file (w+b inary)
    if (file) {
        PEM_write_PUBKEY(file, pkey);
        fclose(file);
    } else {
        std::cerr << "Failed opening file for writing public key" << std::endl;
    }
}

void save_certificate(X509* cert, const std::string& filename) {
    FILE* file = fopen(filename.c_str(), "w+b"); //write as new binary file (w+b inary)
    if (file) {
        PEM_write_X509(file, cert);
        fclose(file);
    } else {
        std::cerr << "Failed opening file for writing certificate" << std::endl;
    }
}



// Function to load the certificate map from a file
CertificateMap load_certificate_map(const std::string& filename) {
    CertificateMap cert_map;
    std::ifstream file(filename);

    if (file.is_open()) {
        std::string id, cert;
        while (std::getline(file, id)) {
            std::ostringstream cert_stream;
            std::string line;
            while (std::getline(file, line) && !line.empty()) {
                cert_stream << line << "\n";
            }
            cert_map[id] = cert_stream.str();
        }
        file.close();
    }
    return cert_map;
}

// Function to save the certificate map to a file
void save_certificate_map(const CertificateMap& cert_map, const std::string& filename) {
    std::ofstream file(filename, std::ios::trunc);

    if (file.is_open()) {
        for (const auto& pair : cert_map) {
            file << pair.first << "\n" << pair.second << "\n\n";
        }
        file.close();
    }
}

// Helper function to convert binary data to a hexadecimal string (ID conversion)
std::string bin_to_hex(const unsigned char* data, size_t len) {
    std::ostringstream oss;
    for (size_t i = 0; i < len; ++i) {
        oss << std::setw(2) << std::setfill('0') << std::hex << (int)data[i];
    }
    return oss.str();
}


// Function to send data with length prefix
void send_data_with_length_prefix(int sock_fd, const char* data, size_t length) {
    // Prefix: 4 bytes for length
    uint32_t data_length = static_cast<uint32_t>(length);
    uint32_t net_length = htonl(data_length);

    // Send the length prefix
    if (send(sock_fd, &net_length, sizeof(net_length), 0) == -1) {
        perror("send: length prefix");
        return;
    }

    // Send the actual data
    if (send(sock_fd, data, length, 0) == -1) {
        perror("send: data");
    }
}

// Function to send the and certificate
void send_certificate(int client_fd, X509* cert) {

    // Send certificate
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(bio, cert);
    int cert_len = BIO_pending(bio);
    char* cert_data = (char*)malloc(cert_len);
    BIO_read(bio, cert_data, cert_len);
    BIO_free(bio);

    send_data_with_length_prefix(client_fd, cert_data, cert_len);
    free(cert_data);
}


// Function to receive data with length prefix
char* receive_data_with_length_prefix(int sock_fd, size_t& length) {
    // Receive the length prefix
    uint32_t net_length;
    if (recv(sock_fd, &net_length, sizeof(net_length), 0) <= 0) {
        perror("recv: length prefix");
        return nullptr;
    }
    uint32_t data_length = ntohl(net_length);
    std::cout << "Length prefix was:" << data_length << std::endl;
    // Allocate buffer for the data
    char* buffer = (char*)malloc(data_length);
    if (buffer == nullptr) {
        std::cerr << "Memory allocation failed." << std::endl;
        return nullptr;
    }

    // Receive the actual data
    size_t total_received = 0;
    while (total_received < data_length) {
        ssize_t bytes_received = recv(sock_fd, buffer + total_received, data_length - total_received, 0);
        if (bytes_received <= 0) {
            perror("recv: data");
            free(buffer);
            return nullptr;
        }
        total_received += bytes_received;
    }

    std::cout << "Data that was transmitted:\n" << std::string(buffer,data_length);

    length = data_length;
    return buffer;
}

// Function to receive the certificate
void receive_certificate(int sock_fd, X509*& cert) {
    size_t length;


    // Receive certificate
    char* cert_data = receive_data_with_length_prefix(sock_fd, length);
    if (!cert_data) {
        std::cerr << "Failed to receive certificate data" << std::endl;
        return;
    }

    BIO *bio = BIO_new_mem_buf(cert_data, length);
    if (!bio) {
        std::cerr << "Failed to create BIO for certificate" << std::endl;
        free(cert_data);
        return;
    }

    cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    if (!cert) {
        std::cerr << "Failed to read certificate" << std::endl;
        ERR_print_errors_fp(stderr);
    }

    BIO_free(bio);
    free(cert_data);
}


int main(int argc, char const *argv[])
{
    bool am_i_server = true;
    if(argc != 3){
        std::cerr << "Provide whether this program mirrors server or client side (s/c) and provide Port" << std::endl;
        return EXIT_FAILURE;
    }
    if(argv[1][0] == 'c'){
        am_i_server = false;
    }
    size_t port;
    {
        std::string_view portview(argv[2]);
        port = std::strtoul(portview.data(), nullptr, 10);
    }

    std::cout << "Argument parsing complete. Am i server? " << (am_i_server? "Yes":"No") << ". Port" << (am_i_server? " to connect to":"") << ": " << port << std::endl;
    std::string certmap_filename = "cert_map" + std::string(am_i_server ? "_s" : "_c") + ".txt";
    CertificateMap cert_map = load_certificate_map(certmap_filename);




    //1. Init SSL library
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    //End of certificate generation. Testing needed. Next: Transmit certificate and pubkey over insecure TCP connection:--------------

    int sock_fd;
    SSL_CTX* ctx;
    SSL* ssl;
    
    if(am_i_server){
        //Setup everything needed for ssl. Especially, generate own, self-signed certificate.

        EVP_PKEY* pkey = generate_rsa_key();
        if (!pkey) {
            std::cerr << "Failed to generate RSA key pair" << std::endl;
            return EXIT_FAILURE;
        }

        //Generate random 256 bit P2P-ID:
        std::array<unsigned char, 32> id; 
        if(RAND_priv_bytes(id.data(),id.size()) <= 0){
            std::cerr << "Failed to generate random bytes for custom P2P ID" << std::endl;
            EVP_PKEY_free(pkey);
            return EXIT_FAILURE;
        }
        std::cout << "Generated ID as hex ";
        print_hex(id.data(), 32);

        std::cout << "Generated server ID is ";
        for(auto c: id){
            std::cout << c;
        }
        std::cout << std::endl;


        //Retrieve own IPv6 ip to include in certificate:
        char ipv6_buf[INET6_ADDRSTRLEN];

        if(!getIPv6(ipv6_buf,sizeof(ipv6_buf))){
            std::cerr << "Failed to retrieve own IPv6 address" << std::endl;
            EVP_PKEY_free(pkey);
            return EXIT_FAILURE;
        }



        //Generate self-signed certificate

        X509* cert = create_self_signed_cert(pkey, ipv6_buf,reinterpret_cast<const char*>(id.data()));
        if(!cert){
            std::cerr << "Failed to generate self-signed X509 certificate" << std::endl;
            EVP_PKEY_free(pkey);
            return EXIT_FAILURE;
        }

        // Save the private key and certificate to files
        save_private_key(pkey, "private_key.pem");
        save_public_key(pkey, "public_key.pem"); //Optional, could be derived
        save_certificate(cert, "certificate.pem");


        sock_fd = socket(AF_INET6, SOCK_STREAM, 0); //socket fd to accept incoming connection (server)
        if (sock_fd < 0) {
            std::cerr << "Failed to create socket." << std::endl;
            return EXIT_FAILURE;
        }

        struct sockaddr_in6 server_addr; //server socket configuration
        server_addr.sin6_family = AF_INET6;
        server_addr.sin6_port = htons(port);
        inet_pton(AF_INET6, "::1", &server_addr.sin6_addr); //local ip addr.

        if (bind(sock_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            std::cerr << "Failed to bind socket." << std::endl;
            return EXIT_FAILURE;
        }


        if (listen(sock_fd, 1) < 0) { //Wait for one connection
            std::cerr << "Failed to listen on socket." << std::endl;
            return EXIT_FAILURE;
        }


        int client_fd = accept(sock_fd, NULL, NULL);

        if (client_fd < 0) {
            std::cerr << "Failed to accept connection." << std::endl;
            return EXIT_FAILURE;
        }



        // Send public key and certificate with length prefix
        send_certificate(client_fd, cert);

        //SSL context
        ctx = create_context(true);
        SSL_CTX_use_certificate(ctx, cert);
        SSL_CTX_use_PrivateKey(ctx, pkey);



        //SSL Object: Per individual connection (in this case, one connection only).
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_fd);
        int ret = SSL_accept(ssl);
        ERR_print_errors_fp(stderr);
        
        //Transmit data securely over ssl encrypted socket (ssl)
        write_test_msg(ssl);

        std::cout << "Test message written." << std::endl;

        //Clean everything;
        EVP_PKEY_free(pkey);
        X509_free(cert);
        close(client_fd);
    }else{
        //CLIENT SIDE:
        sock_fd = socket(AF_INET6,SOCK_STREAM,0); //socket fd to create outgoing tcp connection(client)
        if (sock_fd < 0) {
            std::cerr << "Failed to create socket." << std::endl;
            return EXIT_FAILURE;
        }

        struct sockaddr_in6 server_addr;
        server_addr.sin6_family = AF_INET6;
        server_addr.sin6_port = htons(port);
        inet_pton(AF_INET6, "::1", &server_addr.sin6_addr); //local ip addr.
        if (connect(sock_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            std::cerr << "Failed to connect to server." << std::endl;
            return EXIT_FAILURE;
        }
        // Receive public key over insecure channel (TOFU)
        X509* cert = nullptr;
        receive_certificate(sock_fd, cert);

        std::cout << "Cert pointer value:" << reinterpret_cast<uintptr_t>(cert) << std::endl;
        
        // Retrieve the ID from the certificate
        unsigned char received_id[32];
        if (extract_custom_id(cert, received_id, sizeof(received_id))) {
            std::cout << "ID extracted successfully:" << std::string((char*)received_id,8) << std::endl;

        } else {
            std::cerr << "Failed to extract ID from certificate." << std::endl;
        }
        std::cout << "Checkpoint Client side" << std::endl;
        std::string hex_id = bin_to_hex(received_id, 32);


        if (cert_map.find(hex_id) != cert_map.end()) {
            std::cout << "Certificate already recognized." << std::endl;
        } else {
            // Add the new certificate to the map
            BIO *bio = BIO_new(BIO_s_mem());
            PEM_write_bio_X509(bio, cert);
            int cert_len = BIO_pending(bio);
            char* cert_pem = (char*)malloc(cert_len + 1);
            BIO_read(bio, cert_pem, cert_len);
            cert_pem[cert_len] = '\0';
            BIO_free(bio);

            cert_map[hex_id] = cert_pem;
            free(cert_pem);
        }
        
        // Save the updated certificate map
        save_certificate_map(cert_map, certmap_filename);
        ctx = create_context(false);

        X509_STORE* store = SSL_CTX_get_cert_store(ctx);
        if (X509_STORE_add_cert(store, cert) != 1) {
            std::cerr << "Failed to add certificate to trusted store." << std::endl;
            // Handle error or exit as needed
        }

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, sock_fd);

        //Init connection
        if (SSL_connect(ssl) <= 0) {
            std::cerr << "Error connecting client ssl to server." << std::endl; 
        } else {
            std::cout << "SSL Connection established and verified." << std::endl;
        }


        char msg_buffer[256];
        
        read_test_msg(ssl,msg_buffer,256);

        std::printf("%s\n",msg_buffer);

        std::cout << "Client exited regularly." << std::endl;
        //Clean up
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(sock_fd);
    return 0;
}
