#pragma once

#define GENERAL_VERBOSE
#define TCP_VERBOSE
#define KADEMLIA_VERBOSE
#define SSL_VERBOSE

static constexpr size_t KEY_SIZE  = 32;

static constexpr size_t K = 20;
static constexpr size_t ALPHA = 3;

using Key = std::array<unsigned char,KEY_SIZE>;
using Value = std::vector<unsigned char>;
using NodeID = Key;

struct Node {
    in6_addr addr;
    in_port_t port;
    NodeID id;
};

