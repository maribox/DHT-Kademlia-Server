#pragma once

static constexpr size_t KEY_SIZE  = 32;

using Key = std::array<unsigned char,KEY_SIZE>;
using Value = std::vector<unsigned char>;
using NodeID = Key;

struct Node {
    in6_addr addr;
    in_port_t port;
    NodeID id;
};

