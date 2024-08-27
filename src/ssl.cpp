#pragma once

#include <iostream>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <array>

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


X509* create_self_signed_cert(EVP_PKEY* pkey, const std::string& ipv6, const std::string& id) {
    X509* x509 = X509_new();
    X509_set_version(x509, 2);  //X509 Version 3 (index starting at 0 represents version 1)
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1); //Set serial number to 1
    X509_gmtime_adj(X509_getm_notBefore(x509), 0); //Now + 0 seconds
    X509_gmtime_adj(X509_getm_notBefore(x509), 31536000L); //Now + 1 year
    X509_set_pubkey(x509, pkey);

    //Own name, as we self-issue (self-sign)
    X509_NAME* name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (const unsigned char*) "DE", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char*)"TUM, Technical University Munich", -1, -1, 0);
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

void configure_context_client(SSL_CTX* ctx) {
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    if (!SSL_CTX_load_verify_locations(ctx, "/etc/ssl/certs/ca-certificates.crt", NULL)) {
        std::cerr << "Unable to load CA certificates" << std::endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

/*void configure_context_server(SSL_CTX* ctx) {
    SSL_CTX_set_ecdh_auto(ctx, 1);

    // Set the certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}*/