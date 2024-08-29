#pragma once

#include <iostream>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <array>
#include <cstring>

#include <iomanip>

void print_hex(const unsigned char *s, size_t length)
{
    for(size_t l = 0; l < length; l++)
        printf("%02x", (unsigned int) *s++);
    printf("\n");
}


EVP_PKEY* generate_rsa_key() {
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


X509* create_self_signed_cert_depr(EVP_PKEY* pkey, const std::string& ipv6, const std::string& id) {
    X509* x509 = X509_new();
    X509_set_version(x509, 2);  //X509 Version 3 (index starting at 0 represents version 1)
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1); //Set serial number to 1
    X509_gmtime_adj(X509_getm_notBefore(x509), 0); //Now + 0 seconds
    X509_gmtime_adj(X509_getm_notBefore(x509), 31536000L); //Now + 1 year
    X509_set_pubkey(x509, pkey);

    //Own name, as we self-issue (self-sign)
    X509_NAME* name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (const unsigned char*) "DE", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (const unsigned char*)"TUM, Technical University Munich", -1, -1, 0);
    X509_set_issuer_name(x509, name);

    // Add IPv6 and custom 256-bit ID as extensions
    X509_EXTENSION* ext;
    STACK_OF(X509_EXTENSION) *exts = sk_X509_EXTENSION_new_null();

    // IPv6 address
    ext = X509V3_EXT_conf_nid(nullptr, nullptr, NID_subject_alt_name, ("IP:" + ipv6).c_str());
    sk_X509_EXTENSION_push(exts, ext);

    // Custom 256-bit ID:
    // Create an ASN1_OCTET_STRING to hold the 256-bit ID
    ASN1_OCTET_STRING* octet_string = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(octet_string, (const unsigned char*)id.c_str(), id.size());

    ext = X509_EXTENSION_create_by_NID(nullptr, NID_userId, 0, octet_string);
    sk_X509_EXTENSION_push(exts, ext);

    for (int i = 0; i < sk_X509_EXTENSION_num(exts); i++) {
        X509_add_ext(x509, sk_X509_EXTENSION_value(exts, i), -1);
    }
    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    ASN1_OCTET_STRING_free(octet_string);

    X509_sign(x509, pkey, EVP_sha256()); //sign certificate with private key.
    return x509;
}

X509* create_self_signed_cert(EVP_PKEY* pkey, const std::string& ipv6, const std::string& id) {

X509* x509 = X509_new();
    if (!x509) {
        std::cerr << "Failed to create X509 object" << std::endl;
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
        std::cerr << "Failed to create extension stack" << std::endl;
        X509_free(x509);
        return nullptr;
    }

    // Add IPv6 address as Subject Alternative Name
    std::string san_string = "IP:" + ipv6;
    X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, nullptr, NID_subject_alt_name, san_string.c_str());
    if (!ext) {
        std::cerr << "Failed to create Subject Alternative Name extension" << std::endl;
        sk_X509_EXTENSION_free(exts);
        X509_free(x509);
        return nullptr;
    }
    sk_X509_EXTENSION_push(exts, ext);

    // Add custom 256-bit ID as an extension
    ASN1_OCTET_STRING* octet_string = ASN1_OCTET_STRING_new();
    if (!octet_string) {
        std::cerr << "Failed to create ASN1_OCTET_STRING" << std::endl;
        sk_X509_EXTENSION_free(exts);
        X509_free(x509);
        return nullptr;
    }

    ASN1_OCTET_STRING_set(octet_string, (const unsigned char*)id.c_str(), id.length());

    ext = X509_EXTENSION_create_by_NID(nullptr, NID_userId, 0, octet_string);
    if (!ext) {
        std::cerr << "Failed to create custom ID extension" << std::endl;
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
        std::cerr << "Failed to sign certificate" << std::endl;
        X509_free(x509);
        return nullptr;
    }

    return x509;
}

SSL_CTX* create_context(bool am_i_server) {
    const SSL_METHOD* method;
    SSL_CTX* ctx;

    if(am_i_server)
        method = TLS_server_method();
    else
        method = TLS_client_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        std::cerr << "Unable to create SSL context" << std::endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

// Function to extract IPv6 address from the Subject Alternative Name extension
bool extract_ipv6_from_cert(X509* cert, std::string& ipv6) {
    // Get the Subject Alternative Name extension
    int ext_index = X509_get_ext_by_NID(cert, NID_subject_alt_name, -1);
    if (ext_index < 0) return false;

    X509_EXTENSION* ext = X509_get_ext(cert, ext_index);
    GENERAL_NAMES* general_names = (GENERAL_NAMES*)X509V3_EXT_d2i(ext);

    if (general_names) {
        for (int i = 0; i < sk_GENERAL_NAME_num(general_names); ++i) {
            GENERAL_NAME* gn = sk_GENERAL_NAME_value(general_names, i);
            if (gn->type == GEN_IPADD) {
                char buf[INET6_ADDRSTRLEN];
                if (inet_ntop(AF_INET6, &gn->d.ip, buf, sizeof(buf))) {
                    ipv6 = buf;
                    sk_GENERAL_NAME_pop_free(general_names, GENERAL_NAME_free);
                    return true;
                }
            }
        }
        sk_GENERAL_NAME_pop_free(general_names, GENERAL_NAME_free);
    }
    return false;
}

// Function to extract custom ID from a specific extension
bool extract_custom_id(X509* cert, unsigned char* received_id, size_t id_len) {
    // Get the index of the custom extension by its NID
    int ext_index = X509_get_ext_by_NID(cert, NID_userId, -1);
    if (ext_index == -1) {
        std::cout << "\nError 1" << std::endl;
        return false; // Extension not found
    }
    
    // Get the extension
    X509_EXTENSION* ext = X509_get_ext(cert, ext_index);
    if (!ext) {
        std::cout << "\nError 2" << std::endl;
        return false; // Failed to get extension
    }
    
    // Get the extension data
    ASN1_OCTET_STRING* octet_string = X509_EXTENSION_get_data(ext);
    if (!octet_string || !octet_string->data) {
        std::cout << "\nError 3" << std::endl;
        return false; // No data found
    }
    std::string s1((char*)octet_string->data,32);
    std::cout << "Received ID: " << std::hex << s1 <<std::endl;

    

    std::cout << "Id length of provided field " << octet_string->length << std::endl;
    
    // Copy the data to the provided buffer
    std::memcpy(received_id, octet_string->data, 32);
    
    std::cout << "Received ID as hex ";
    print_hex(received_id, 32);
    return true; // Successfully extracted the ID
}

std::string extract_ipv6(X509* cert) {
    int ext_index = X509_get_ext_by_NID(cert, NID_subject_alt_name, -1);
    if (ext_index == -1) {
        return "";
    }
    
    X509_EXTENSION* ext = X509_get_ext(cert, ext_index);
    if (!ext) {
        return "";
    }

    GENERAL_NAMES* names = static_cast<GENERAL_NAMES*>(X509V3_EXT_d2i(ext));
    if (!names) {
        return "";
    }

    std::string ipv6_address;
    for (int i = 0; i < sk_GENERAL_NAME_num(names); ++i) {
        GENERAL_NAME* name = sk_GENERAL_NAME_value(names, i);
        if (name->type == GEN_IPADD) {
            const unsigned char* ip = name->d.iPAddress->data;
            if (name->d.iPAddress->length == 16) { // IPv6 is 16 bytes
                char str[INET6_ADDRSTRLEN];
                if (inet_ntop(AF_INET6, ip, str, sizeof(str))) {
                    ipv6_address = str;
                }
            }
        }
    }

    GENERAL_NAMES_free(names);
    return ipv6_address;
}

bool extract_id_from_cert_dep(X509* cert, unsigned char* received_id, size_t id_len) {
    if (!cert || !received_id || id_len < 32) {
        std::cerr << "Invalid arguments passed to extract_id_from_cert" << std::endl;
        return false;
    }

    X509_NAME* subject_name = X509_get_subject_name(cert);
    if (!subject_name) {
        std::cerr << "Failed to get subject name from certificate." << std::endl;
        return false;
    }

    int idx = X509_NAME_get_index_by_NID(subject_name, NID_userId, -1);
    if (idx < 0) {
        std::cerr << "User ID not found in the certificate." << std::endl;
        return false;
    }

    X509_NAME_ENTRY* entry = X509_NAME_get_entry(subject_name, idx);
    if (!entry) {
        std::cerr << "Failed to get X509 name entry for user ID." << std::endl;
        return false;
    }

    ASN1_STRING* asn1_string = X509_NAME_ENTRY_get_data(entry);
    if (!asn1_string) {
        std::cerr << "Failed to get ASN1 string from X509 name entry." << std::endl;
        return false;
    }

    const unsigned char* id_ptr = ASN1_STRING_get0_data(asn1_string);
    if (!id_ptr) {
        std::cerr << "Failed to get data from ASN1 string." << std::endl;
        return false;
    }

    // Check the length of the ASN1 string
    int asn1_length = ASN1_STRING_length(asn1_string);
    if (asn1_length < 32) {
        std::cerr << "User ID length is shorter than expected." << std::endl;
        return false;
    }

    // Copy the ID into the buffer
    memcpy(received_id, id_ptr, 32);
    return true;
}




void write_test_msg(SSL* ssl){
    const char *msg = "Hello";
    int len = strlen(msg);
    int bytes_written = SSL_write(ssl, msg, len);

    if (bytes_written <= 0) {
        // Handle error
        int err = SSL_get_error(ssl, bytes_written);
        if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
            // Retry SSL_write() based on err value.
            std::cerr << "SSL write error 1" << std::endl;
        } else {
            // Handle other errors
            std::cerr << "SSL write error 2" << std::endl;
        }
    }
    return;
}


void read_test_msg(SSL* ssl, char * buffer, size_t buflen){
    int bytes_read = SSL_read(ssl, buffer, buflen-1);

    if (bytes_read > 0) {
        buffer[bytes_read] = '\0'; // Null-terminate the string
        printf("Received: %s\n", buffer);
    } else {
        // Handle error
        int err = SSL_get_error(ssl, bytes_read);
        if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
            // Retry SSL_read() based on err value.
            std::cerr << "SSL read error 1" << std::endl;
        } else {
            // Handle other errors
            std::cerr << "SSL read error 2" << std::endl;
        }
    }
}