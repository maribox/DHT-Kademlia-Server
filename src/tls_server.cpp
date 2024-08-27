#include "ssl.cpp"
#include <ifaddrs.h>
#include <netinet/in.h>
#include <cstring>

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

int main(int argc, char const *argv[])
{
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
    save_public_key(pkey, "public_key.pem");
    save_certificate(cert, "certificate.pem");

    //TODO: BASED. Certificate generation complete. Testing needed --------------

    int sockfd;
    struct sockaddr_in server_addr;

    //1. Init SSL library
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    // Create SSL contexts
    // (outgoing connection (sent request) means that i am a client, waiting to be served)
    // (incoming connection (awaited request) means that i am a server, serving the request)
    SSL_CTX *server_ctx = create_context(true);
    SSL_CTX *client_ctx = create_context(false);


    return 0;
}
