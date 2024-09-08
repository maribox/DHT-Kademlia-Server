#pragma once

#define GENERAL_VERBOSE
#define TCP_VERBOSE
#define KADEMLIA_VERBOSE
#define SSL_VERBOSE

//For logging
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#define logTrace spdlog::trace
#define logDebug spdlog::debug
#define logInfo spdlog::info
#define logWarn spdlog::warn
#define logError spdlog::error
#define logCritical spdlog::critical

static constexpr size_t KEY_SIZE  = 32;

static constexpr size_t K = 20;
static constexpr size_t ALPHA = 3;

inline bool operator==(const in6_addr & lhs, const in6_addr & rhs) {
    return std::memcmp(lhs.s6_addr, rhs.s6_addr, sizeof(lhs.s6_addr)) == 0;
}

using Key = std::array<unsigned char,KEY_SIZE>;
using Value = std::vector<unsigned char>;
using NodeID = Key;

struct Node {
public:
    in6_addr addr;
    in_port_t port;
    NodeID id;

    bool operator==(const Node& other) const {
        return addr == other.addr && port == other.port && id == other.id;
    }
    bool is_valid_node() const {
        return has_valid_id() && addr != in6addr_any && port != 0;
    }
private:
    bool has_valid_id() const { // TODO Frage @master why does ranges::all_of not work here
        return !std::all_of(id.begin(), id.end(), [](unsigned char byte){return byte == 0;});
    }
};

// for maps

inline std::size_t hash_it(const unsigned char* data, std::size_t size, std::size_t seed) {
    // Following 6 lines of code taken and adapted from https://stackoverflow.com/a/72073933/14236974 - Marius
    for (std::size_t i = 0; i < size; ++i) {
        unsigned char x = data[i];
        x = ((x >> 4) ^ x) * 0x45d9f3b;
        x = ((x >> 4) ^ x) * 0x45d9f3b;
        x = (x >> 4) ^ x;
        seed ^= x + 0x9e3779b9 + (seed << 6) + (seed >> 2);
    }
    return seed;
}

template <>
struct std::hash<Value>
{
    std::size_t operator()(const std::vector<unsigned char>& vec) const noexcept {
        std::size_t seed = hash_it(vec.data(), vec.size(), vec.size());
        return seed;
    }
};

template<>
struct std::hash<Node> {
    std::size_t operator()(const Node& node) const noexcept {
        std::size_t seed = 0;
        seed = hash_it(reinterpret_cast<const unsigned char*>(node.addr.s6_addr), sizeof(node.addr.s6_addr), seed);
        seed = hash_it(reinterpret_cast<const unsigned char*>(&node.port), sizeof(node.port), seed);
        seed = hash_it(node.id.data(), node.id.size(), seed);
        return seed;
    }
};
