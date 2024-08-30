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
        if(!ssl){
            std::cerr << "Server: SSL object null pointer" << std::endl;
        }
        SSL_set_fd(ssl, client_fd);
        int ret = SSL_accept(ssl);
        if(!ret){
            std::cerr << "Server: SSL accept failed null pointer" << std::endl;
        }
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
            std::cout << "ID extracted successfully" << std::endl;
        } else {
            std::cerr << "Failed to extract ID from certificate." << std::endl;
        }
        std::string hex_id = bin_to_hex(received_id, 32);
        std::string ipv6_str{};
        
        if(extract_ipv6_from_cert(cert,ipv6_str)){
            std::cout << "IPv6 extracted successfully: " << ipv6_str << std::endl;
        }else{
            std::cerr << "Failed to extract IPv6 from certificate." << std::endl;
        }
        std::cout << "Checkpoint Client side" << std::endl;



        if (cert_map.find(hex_id) != cert_map.end()) {
            std::cout << "Certificate already recognized." << std::endl;
            //compare certificates
        } else {
            // Add the new certificate to the map
            BIO *bio = BIO_new(BIO_s_mem());
            PEM_write_bio_X509(bio, cert);
            int cert_len = BIO_pending(bio);
            char* cert_pem = (char*)malloc(cert_len + 1);
            BIO_read(bio, cert_pem, cert_len);
            cert_pem[cert_len] = '\0';
            BIO_free(bio);

            cert_map[hex_id] = std::string(cert_pem);
            free(cert_pem);
        }

        /*
        For debugging begin
        Works!*/
        //std::cout << "Should be true: " << (compare_x509_cert_with_pem(cert,cert_map[hex_id])? "True" : "False") << std::endl;
        /*
        For debugging end
        */
        
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
        
        read_test_msg(ssl,msg_buffer, 256);

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
