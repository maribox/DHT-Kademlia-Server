#pragma once

#include <optional>
#include <map>
#include <mutex>
#include <string>
#include <array>
#include <vector>

static constexpr size_t KEYSIZE  = 32;
static constexpr size_t HEADERSIZE  = 4;
using keyType = std::array<char,KEYSIZE>;
using valueType = std::vector<char>;
using socket_t  = int;

std::string key_to_string(const keyType& key);

enum ProcessingStatus{
    waitForCompleteMessageHeader = 0,
    waitForCompleteMessageBody = 1,
    processed = 1<<1,
    waitForRelaySend = 1<<2,
    waitForRelayAnswer = 1<<3,
    error = 1<<4
};

namespace DHTServerConfig {
    static constexpr u_short DHT_PORT = 7401;
};

struct ConnectionInfo{
        std::vector<char> receivedBytes;
        bool receivedBytesInUse;
        std::vector<char> sendBytes; //This is a todo send buffer. See epoll case EPOLLOUT.
        bool sendBytesInUse;
        socket_t relayTo{-1}; //Possibly relay the request to other server that sits closer (XOR) to the requested key.
    };

enum DHT_TYPE{
    DHT_PUT = 650,
    DHT_GET = 651,
    DHT_SUCCESS = 652,
    DHT_FAILURE = 653
    };

std::optional<valueType> get_from_storage(const keyType& key);
void save_to_storage(const keyType& key, valueType val);

bool send_dht_success(socket_t, keyType, valueType); // TODO
bool send_dht_failure(socket_t, keyType); // TODO
 // TODO
