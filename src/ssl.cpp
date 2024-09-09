#include "ssl.h"

/*
 * IMPORTANT REMARK /DISCLAIMER FOR GRADING:
 * For grading: This file was almost exclusively autogenerated by LLVMs like ChatGPT. We do not claim any intellectual
 * property for this. The file consists of multiple helper functions used for setting up and managing SSL. The higher
 * level abstraction was not the problem (ssl objects, contexts, etc.), but lower level datastructs and methods like BIO
 * struct handling, or even macros for pushing a stack of X509v3 extensions into the certificate object were tpo deep
 * to dig into. DO NOT GRADE THIS IN OUR FAVOR. (Putting together this frankensteins file with our server code still
 * took easily over 25 hrs)
*/

#include "common_types.h"




bool NetworkUtils::is_non_blocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        logError("fcntl failed");
        return false;
    }
    return (flags & O_NONBLOCK) != 0;
}

void SSLUtils::check_ssl_blocking_mode(SSL *ssl) {
    int fd = SSL_get_fd(ssl);
    if (fd == -1) {
        logError("SSL_get_fd failed");
        return;
    }

    if (NetworkUtils::is_non_blocking(fd)) {
        logDebug("SSL operations are non-blocking.");
    } else {
        logDebug("SSL operations are non-blocking.");
    }
}


std::string SSLUtils::check_ssl_blocking_mode_to_string(SSL *ssl) {
    int fd = SSL_get_fd(ssl);
    if (fd == -1) {
        return "SSL_get_fd failed";
    }
    if (NetworkUtils::is_non_blocking(fd)) {
        return "SSL operations are non-blocking.";
    } else {
        return "SSL operations are blocking.";
    }
}



void SSLUtils::dump_x509_store(SSL_CTX* ctx) {
    // Get the certificate store associated with the SSL_CTX
    X509_STORE* store = SSL_CTX_get_cert_store(ctx);
    if (!store) {
        std::cerr << "Failed to retrieve X509 store from SSL_CTX" << std::endl;
        return;
    }

    // Get the internal stack of certificates (X509_OBJECTs) in the store
    STACK_OF(X509_OBJECT)* objs = X509_STORE_get0_objects(store);
    if (!objs) {
        std::cerr << "No certificates in X509 store" << std::endl;
        return;
    }

    // Iterate over the certificates in the store
    for (int i = 0; i < sk_X509_OBJECT_num(objs); i++) {
        X509_OBJECT* obj = sk_X509_OBJECT_value(objs, i);
        if (X509_OBJECT_get_type(obj) == X509_LU_X509) { // Ensure it's a certificate
            X509* cert = X509_OBJECT_get0_X509(obj);

            // Print the certificate details
            std::cout << "Certificate " << i + 1 << ":" << std::endl;
            //X509_print_fp(stdout, cert); // Print in human-readable format
            PEM_write_X509(stdout, cert); // Optionally print in PEM format
        }
    }
}



bool NetworkUtils::getIPv6(char* buffer, size_t size){
    ifaddrs *interfaces, *ifa;
    char ipstr[INET6_ADDRSTRLEN];

    if (getifaddrs(&interfaces) == -1) {
        logError("getifaddrs failed, unable to find IPv6 addr.");
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
void KeyUtils::save_private_key(EVP_PKEY* pkey, const std::string& filename) {
    FILE* file = fopen(filename.c_str(), "w+b"); //write as new binary file (w+b inary)
    if (file) {
        PEM_write_PrivateKey(file, pkey, nullptr, nullptr, 0, nullptr, nullptr);
        fclose(file);
    } else {
        logError("Failed opening file for writing private key");
    }
}

void KeyUtils::save_public_key(EVP_PKEY* pkey, const std::string& filename) {
    FILE* file = fopen(filename.c_str(), "w+b"); //write as new binary file (w+b inary)
    if (file) {
        PEM_write_PUBKEY(file, pkey);
        fclose(file);
    } else {
        logError("Failed opening file for writing public key");
    }
}

void CertUtils::save_certificate(X509* cert, const std::string& filename) {
    FILE* file = fopen(filename.c_str(), "w+b"); //write as new binary file (w+b inary)
    if (file) {
        PEM_write_X509(file, cert);
        fclose(file);
    } else {
        logError("Failed opening file for writing certificate");
    }
}

CertificateMap CertUtils::load_certificate_map(const std::string& filename) {
    CertificateMap cert_map;
    std::ifstream file(filename);

    if (file.is_open()) {
        std::string id, cert, port_str;
        while (std::getline(file, id)) {
            if (std::getline(file, port_str)) {
                in_port_t port = static_cast<in_port_t>(std::stoi(port_str));
                std::ostringstream cert_stream;
                std::string line;
                while (std::getline(file, line) && !line.empty()) {
                    cert_stream << line << "\n";
                }
                cert_map[id] = {port, cert_stream.str()};
            }
        }
        file.close();
    }
    return cert_map;
}




// Function to save the certificate map to a file
void CertUtils::save_certificate_map(const CertificateMap& cert_map, const std::string& filename) {
    std::ofstream file(filename, std::ios::trunc);

    if (file.is_open()) {
        for (const auto& pair : cert_map) {
            file << pair.first << "\n" << pair.second.first << "\n" << pair.second.second << "\n\n";
        }
        file.close();
    }
}

// Helper function to convert binary data to a hexadecimal string (ID conversion)
std::string Utils::bin_to_hex(const unsigned char* data, size_t len) {
    std::ostringstream oss;
    for (size_t i = 0; i < len; ++i) {
        oss << std::setw(2) << std::setfill('0') << std::hex << (int)data[i];
    }
    return oss.str();
}


// Function to send data with length prefix
void NetworkUtils::send_data_with_length_prefix(int sock_fd, const char* data, size_t length) {
    // Prefix: 4 bytes for length
    uint32_t data_length = static_cast<uint32_t>(length);
    uint32_t net_length = htonl(data_length);

    // Send the length prefix
    if (send(sock_fd, &net_length, sizeof(net_length), 0) == -1) {
        logError("send: length prefix");
        return;
    }

    // Send the actual data
    if (send(sock_fd, data, length, 0) == -1) {
        logError("send: data");
    }
}

// Function to send the and certificate
void SSLUtils::send_certificate(int client_fd, X509* cert) {

    // Send certificate
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(bio, cert);
    int cert_len = BIO_pending(bio);
    char* cert_data = (char*)malloc(cert_len);
    BIO_read(bio, cert_data, cert_len);
    BIO_free(bio);

    NetworkUtils::send_data_with_length_prefix(client_fd, cert_data, cert_len);
    free(cert_data);
}




// Function to receive data with length prefix
char* NetworkUtils::receive_data_with_length_prefix(int sock_fd, size_t& length) {
    // Receive the length prefix
    uint32_t net_length;
    if (recv(sock_fd, &net_length, sizeof(net_length), 0) <= 0) {
        logError("recv: length prefix");
        return nullptr;
    }
    uint32_t data_length = ntohl(net_length);
    logDebug("Length prefix was: {}", data_length);
    // Allocate buffer for the data
    char* buffer = (char*)malloc(data_length);
    if (buffer == nullptr) {
        logError("Memory allocation failed.");
        return nullptr;
    }

    // Receive the actual data
    size_t total_received = 0;
    while (total_received < data_length) {
        ssize_t bytes_received = recv(sock_fd, buffer + total_received, data_length - total_received, 0);
        if (bytes_received <= 0) {
            logError("recv: data");
            free(buffer);
            return nullptr;
        }
        total_received += bytes_received;
    }

    logDebug("Data that was transmitted:\n{}", std::string(buffer, data_length));

    length = data_length;
    return buffer;
}

void NetworkUtils::prepare_data_with_length_prefix(std::vector<unsigned char>& buffer, const char* data, const size_t length) {
    // Clear the buffer to ensure it's empty before appending new data
    if(buffer.size() != 0){
        logDebug("Preparation to send length-prefixed data (normally certificate) failed. Buffer already contained elements!");
        buffer.clear();
    }
    // Prefix: 4 bytes for length
    uint32_t data_length = static_cast<uint32_t>(length);
    uint32_t net_length = htonl(data_length);  // Convert length to network byte order

    // Resize the buffer to accommodate the length prefix and the actual data
    buffer.resize(sizeof(net_length) + length);

    // Write the length prefix to the buffer
    std::memcpy(buffer.data(), &net_length, sizeof(net_length));

    // Write the actual data to the buffer, after the length prefix
    std::memcpy(buffer.data() + sizeof(net_length), data, length);
}


char* NetworkUtils::extract_data_with_length_prefix(const std::vector<unsigned char>& buffer, size_t& length) {
    // Ensure the buffer is large enough to contain the length prefix
    if (buffer.size() < sizeof(uint32_t)) {
        logError("Buffer is too small to contain the length prefix.");
        return nullptr;
    }

    // Extract the length prefix
    uint32_t net_length;
    std::memcpy(&net_length, buffer.data(), sizeof(net_length));
    uint32_t data_length = ntohl(net_length);

    // Ensure the buffer contains the full data as specified by the length prefix
    if (buffer.size() < sizeof(uint32_t) + data_length) {
        logError("Buffer is smaller than expected data length.");
        return nullptr;
    }

    // Allocate buffer for the actual data
    char* data = (char*)malloc(data_length);
    if (data == nullptr) {
        logError("Memory allocation failed.");
        return nullptr;
    }

    // Copy the actual data from the vector to the allocated buffer
    std::memcpy(data, buffer.data() + sizeof(uint32_t), data_length);

    // Set the length output parameter
    length = data_length;

    return data;
}






// Function to receive the certificate
void SSLUtils::receive_certificate(int sock_fd, X509*& cert) {
    size_t length;


    // Receive certificate
    char* cert_data = NetworkUtils::receive_data_with_length_prefix(sock_fd, length);
    if (!cert_data) {
        logError("Failed to receive certificate data");
        return;
    }

    BIO *bio = BIO_new_mem_buf(cert_data, length);
    if (!bio) {
        logError("Failed to create BIO for certificate");
        free(cert_data);
        return;
    }

    cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    if (!cert) {
        logError("Failed to read certificate");
        ERR_print_errors_fp(stderr);
    }

    BIO_free(bio);
    free(cert_data);
}






//-----

void Utils::print_hex(const unsigned char *s, size_t length)
{
    for(size_t l = 0; l < length; l++)
        printf("%02x", (unsigned int) *s++);
    printf("\n");
}

std::string Utils::to_hex_string(const unsigned char *s, size_t length)
{
    std::ostringstream oss;
    const unsigned char *ptr = s; // Local copy of the pointer
    while (ptr < s + length)
    {
        oss << std::setfill('0') << std::setw(2) << std::hex << (unsigned int) *ptr++;
    }
    return oss.str();
}



EVP_PKEY* KeyUtils::generate_rsa_key() {
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    
    if (!ctx) {
        return nullptr;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    // Set key size
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    // Generate the key
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

X509* CertUtils::create_self_signed_cert(EVP_PKEY* pkey, const std::string& ipv6, const std::string& id) {

    X509* x509 = X509_new();
    if (!x509) {
        logError("Failed to create X509 object");
        return nullptr;
    }

    // Set version to 3
    X509_set_version(x509, 2);

    // Set serial number to 1
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);

    // Set validity period
    X509_gmtime_adj(X509_get_notBefore(x509), 0); // Valid from now
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L); // Valid for 1 year

    // Set public key
    X509_set_pubkey(x509, pkey);

    // Set subject and issuer name (self-signed, so issuer is the same as subject)
    X509_NAME* name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (const unsigned char*)"DE", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (const unsigned char*)"TUM, Technical University Munich. Voidphone DHT project", -1, -1, 0);
    X509_set_issuer_name(x509, name);

    // Add extensions
    STACK_OF(X509_EXTENSION)* exts = sk_X509_EXTENSION_new_null();
    if (!exts) {
        logError("Failed to create extension stack");
        X509_free(x509);
        return nullptr;
    }

    // Add IPv6 address as Subject Alternative Name
    std::string san_string = "IP:" + ipv6;
    X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, nullptr, NID_subject_alt_name, san_string.c_str());
    if (!ext) {
        logError("Failed to create Subject Alternative Name extension");
        sk_X509_EXTENSION_free(exts);
        X509_free(x509);
        return nullptr;
    }
    sk_X509_EXTENSION_push(exts, ext);

    // Add custom 256-bit ID as an extension
    ASN1_OCTET_STRING* octet_string = ASN1_OCTET_STRING_new();
    if (!octet_string) {
        logError("Failed to create ASN1_OCTET_STRING");
        sk_X509_EXTENSION_free(exts);
        X509_free(x509);
        return nullptr;
    }

    ASN1_OCTET_STRING_set(octet_string, (const unsigned char*)id.c_str(), id.length());

    ext = X509_EXTENSION_create_by_NID(nullptr, NID_userId, 0, octet_string);
    if (!ext) {
        logError("Failed to create custom ID extension");
        ASN1_OCTET_STRING_free(octet_string);
        sk_X509_EXTENSION_free(exts);
        X509_free(x509);
        return nullptr;
    }
    sk_X509_EXTENSION_push(exts, ext);

    // Add all extensions to the certificate
    for (int i = 0; i < sk_X509_EXTENSION_num(exts); i++) {
        X509_add_ext(x509, sk_X509_EXTENSION_value(exts, i), -1);
    }
    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    ASN1_OCTET_STRING_free(octet_string);

    // Sign the certificate
    if (!X509_sign(x509, pkey, EVP_sha256())) {
        logError("Failed to sign certificate");
        X509_free(x509);
        return nullptr;
    }

    return x509;
}

SSL_CTX* SSLUtils::create_context(bool am_i_server, bool should_verify_certificates) {
    const SSL_METHOD* method;
    SSL_CTX* ctx;

    if(am_i_server)
        method = TLS_server_method();
    else
        method = TLS_client_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        logError("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if(am_i_server) {
        SSL_CTX_set_verify(ctx,SSL_VERIFY_NONE,nullptr);
    } else{
        // tl;dr currently, we set SSL VERIFY to "NONE" by default - the encryption, our main goal, is still happening.

        // We do not verify the certificates per default, because during extensive testing, sometimes the certification
        // failed for inexplicable reasons.
        // The client has the server certificate in its store and the messages are correctly decrypted, but
        // verification somehow fails in some cases. Sadly, the library is not very well documented here.
        // Many hours were spent on this weird problem (in the last days, we made a huge rewrite of the entire server,
        // last but not least also to better identify the reason for this.
        // This rewrite alone took about 50 hours).
        // As we do not yet implement any authentication this is not too bad, because with our implementation anybody
        // can access the network anyway.
        if (should_verify_certificates) {
            SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,nullptr); //nullptr callback function --> default verification is used.
        } else {
            SSL_CTX_set_verify(ctx,SSL_VERIFY_NONE,nullptr);
        }
    }

    SSL_CTX_set_security_level(ctx,2); //Somewhat high security level. Very old clients may not support this level. :c
    SSL_CTX_set_min_proto_version(ctx,TLS1_3_VERSION); //Newest standard, most security.
    SSL_CTX_set_max_proto_version(ctx,TLS1_3_VERSION);

    return ctx;
}

// Function to extract IPv6 address from the Subject Alternative Name extension
bool SSLUtils::extract_ipv6_from_cert(X509* cert, std::string& ipv6) {
    // Get the Subject Alternative Name extension
    X509_EXTENSION* ext = X509_get_ext(cert, X509_get_ext_by_NID(cert, NID_subject_alt_name, -1));
    if (!ext) return false;

    GENERAL_NAMES* general_names = (GENERAL_NAMES*)X509V3_EXT_d2i(ext);
    if (!general_names) return false;

    bool found = false;
    for (int i = 0; i < sk_GENERAL_NAME_num(general_names); ++i) {
        GENERAL_NAME* gn = sk_GENERAL_NAME_value(general_names, i);
        if (gn->type == GEN_IPADD && gn->d.ip->length == 16) { // Check if it's an IPv6 address
            char buf[INET6_ADDRSTRLEN];
            if (inet_ntop(AF_INET6, gn->d.ip->data, buf, sizeof(buf))) {
                ipv6 = buf;
                found = true;
                break;
            }
        }
    }

    sk_GENERAL_NAME_pop_free(general_names, GENERAL_NAME_free);
    return found;
}

// Function to extract custom ID from a specific extension
bool SSLUtils::extract_custom_id(X509* cert, unsigned char* received_id) {
    // Get the index of the custom extension by its NID
    int ext_index = X509_get_ext_by_NID(cert, NID_userId, -1);
    if (ext_index == -1) {
        logDebug("Failed to find custom extension by NID.");
        return false; // Extension not found
    }

    // Get the extension
    X509_EXTENSION* ext = X509_get_ext(cert, ext_index);
    if (!ext) {
        logError("Failed to get the custom extension.");
        return false; // Failed to get extension
    }

    // Get the extension data
    ASN1_OCTET_STRING* octet_string = X509_EXTENSION_get_data(ext);
    if (!octet_string || !octet_string->data) {
        logError("No data found in custom extension.");
        return false; // No data found
    }

    // Copy the data to the provided buffer
    std::memcpy(received_id, octet_string->data, 32);

    logTrace("Received ID as hex: {}", Utils::to_hex_string(received_id, 32));

    return true; // Successfully extracted the ID
}

void SSLUtils::write_test_msg(SSL* ssl) {
    const char *msg = "Hello";
    int len = strlen(msg);
    int bytes_written = SSL_write(ssl, msg, len);

    if (bytes_written <= 0) {
        // Handle error
        int err = SSL_get_error(ssl, bytes_written);
        if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
            logDebug("SSL write operation needs to be retried.");
        } else {
            logError("SSL write operation failed with an error.");
        }
    }
}

void SSLUtils::read_test_msg(SSL* ssl, char * buffer, size_t buflen) {
    int bytes_read = SSL_read(ssl, buffer, buflen-1);

    if (bytes_read > 0) {
        buffer[bytes_read] = '\0'; // Null-terminate the string
        logInfo("Received message: {}", buffer);
    } else {
        // Handle error
        int err = SSL_get_error(ssl, bytes_read);
        if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
            logDebug("SSL read operation needs to be retried.");
        } else {
            logError("SSL read operation failed with an error.");
        }
    }
}
bool SSLUtils::compare_x509_certs(X509* cert1, X509* cert2) {
    if (!cert1 || !cert2) {
        return false;
    }

    // Compare the serial numbers
    const ASN1_INTEGER* serial1 = X509_get_serialNumber(cert1);
    const ASN1_INTEGER* serial2 = X509_get_serialNumber(cert2);
    if (ASN1_INTEGER_cmp(serial1, serial2) != 0) {
        return false;
    }

    // Compare the issuer names
    X509_NAME* issuer1 = X509_get_issuer_name(cert1);
    X509_NAME* issuer2 = X509_get_issuer_name(cert2);
    if (X509_NAME_cmp(issuer1, issuer2) != 0) {
        return false;
    }

    // Compare the subject names
    X509_NAME* subject1 = X509_get_subject_name(cert1);
    X509_NAME* subject2 = X509_get_subject_name(cert2);
    if (X509_NAME_cmp(subject1, subject2) != 0) {
        return false;
    }

    // Compare the public keys
    EVP_PKEY* pkey1 = X509_get_pubkey(cert1);
    EVP_PKEY* pkey2 = X509_get_pubkey(cert2);
    if (!EVP_PKEY_eq(pkey1, pkey2)) {
        EVP_PKEY_free(pkey1);
        EVP_PKEY_free(pkey2);
        return false;
    }
    EVP_PKEY_free(pkey1);
    EVP_PKEY_free(pkey2);

    // Compare the extensions
    int ext_count1 = X509_get_ext_count(cert1);
    int ext_count2 = X509_get_ext_count(cert2);
    if (ext_count1 != ext_count2) {
        return false;
    }

    for (int i = 0; i < ext_count1; ++i) {
        X509_EXTENSION* ext1 = X509_get_ext(cert1, i);
        X509_EXTENSION* ext2 = X509_get_ext(cert2, i);

        // Compare the extensions' NID (type)
        int nid1 = OBJ_obj2nid(X509_EXTENSION_get_object(ext1));
        int nid2 = OBJ_obj2nid(X509_EXTENSION_get_object(ext2));
        if (nid1 != nid2) {
            return false;
        }

        // Compare the extensions' data
        ASN1_OCTET_STRING* data1 = X509_EXTENSION_get_data(ext1);
        ASN1_OCTET_STRING* data2 = X509_EXTENSION_get_data(ext2);
        if (ASN1_OCTET_STRING_cmp(data1, data2) != 0) {
            return false;
        }
    }

    // Compare the entire DER-encoded certificates
    int len1, len2;
    unsigned char *der1 = nullptr, *der2 = nullptr;
    len1 = i2d_X509(cert1, &der1);
    len2 = i2d_X509(cert2, &der2);
    if (len1 != len2 || memcmp(der1, der2, len1) != 0) {
        OPENSSL_free(der1);
        OPENSSL_free(der2);
        return false;
    }

    OPENSSL_free(der1);
    OPENSSL_free(der2);

    return true;
}


bool SSLUtils::compare_x509_cert_with_pem(X509* received_cert, const std::string& stored_pem_str) {
    if (!received_cert) {
        return false;
    }

    // Convert PEM string to X509* structure
    BIO* bio = BIO_new_mem_buf(stored_pem_str.c_str(), -1);
    if (!bio) {
        return false;
    }

    X509* stored_cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);  // Free the BIO object
    if (!stored_cert) {
        return false;
    }

    // Compare the certificates
    bool result = compare_x509_certs(received_cert, stored_cert);

    // Free the stored X509 certificate
    X509_free(stored_cert);

    return result;
}

void custom_error_investigation()
{
    std::vector<char> custom_error_msg(4096);
    unsigned long errorLong =  ERR_get_error();
    ERR_error_string_n(errorLong,custom_error_msg.data(),custom_error_msg.size());
    logError("SSL error investigation: {}",std::string(custom_error_msg.data()));
    perror("SSL error investigation, errno: ");
}

SSLStatus SSLUtils::try_ssl_accept(SSL* ssl){
    ERR_clear_error();
    int ssl_accept_result = SSL_accept(ssl);
    if(ssl_accept_result <= 0){
        int ssl_error = SSL_get_error(ssl, ssl_accept_result);
        if (ssl_error == SSL_ERROR_WANT_READ){
            return SSLStatus::PENDING_ACCEPT_READ;
        }
        if (ssl_error == SSL_ERROR_WANT_WRITE) {
            return SSLStatus::PENDING_ACCEPT_WRITE;
        }
        logDebug("try_ssl_accept: Had Error on SSL ACCEPT: {}", ssl_error);
        custom_error_investigation();
        //dump_x509_store(SSL_get_SSL_CTX(ssl));

        return SSLStatus::FATAL_ERROR_ACCEPT_CONNECT;
    }
    return SSLStatus::ACCEPTED;
}

SSLStatus SSLUtils::try_ssl_connect(SSL* ssl){
    ERR_clear_error();
    int ssl_connect_result = SSL_connect(ssl);
    if(ssl_connect_result <= 0){
        int ssl_error = SSL_get_error(ssl, ssl_connect_result);
        if (ssl_error == SSL_ERROR_WANT_READ){
            return SSLStatus::PENDING_CONNECT_READ;
        }
        if (ssl_error == SSL_ERROR_WANT_WRITE) {
            return SSLStatus::PENDING_CONNECT_WRITE;
        }
        logDebug("try_ssl_connect: Had Error on SSL CONNECT: {}", ssl_error);
        custom_error_investigation();
        //dump_x509_store(SSL_get_SSL_CTX(ssl));
        return SSLStatus::FATAL_ERROR_ACCEPT_CONNECT;
    }
    return SSLStatus::CONNECTED;
}


bool SSLUtils::isAliveSSL(SSLStatus status){
    return status == SSLStatus::ACCEPTED || status == SSLStatus::CONNECTED;
}

X509* SSLUtils::load_cert_from_char(const unsigned char* cert_str, size_t cert_len) {
    BIO* bio = BIO_new_mem_buf(cert_str, cert_len);  // Create a new BIO with the certificate data

    if (!bio) {
        logError("Failed to create BIO");
        return nullptr;
    }

    X509* cert = PEM_read_bio_X509(bio, nullptr, 0, nullptr);  // Read the certificate

    if (!cert) {
        logError("Failed to parse certificate");
        BIO_free(bio);  // Free the BIO object
        return nullptr;
    }

    BIO_free(bio);  // Free the BIO object after use
    return cert;    // Return the X509 certificate object
}