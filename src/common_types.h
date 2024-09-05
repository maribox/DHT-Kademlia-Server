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

using Key = std::array<unsigned char,KEY_SIZE>;
using Value = std::vector<unsigned char>;
using NodeID = Key;

struct Node {
    in6_addr addr;
    in_port_t port;
    NodeID id;
};

