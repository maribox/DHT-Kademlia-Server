#pragma once

#include <optional>
#include <map>
#include <mutex>
#include <string>
#include <array>
#include <vector>
#include <sys/epoll.h>

static constexpr size_t KEYSIZE  = 32;
static constexpr size_t HEADERSIZE  = 4;
using keyType = std::array<unsigned char,KEYSIZE>;
using valueType = std::vector<unsigned char>;
using socket_t  = int;

bool operator<=(const keyType& lhs, const keyType& rhs);

std::string key_to_string(const keyType& key);

enum ProcessingStatus{
    waitForCompleteMessageHeader = 0,
    waitForCompleteMessageBody = 1,
    processed = 1<<1,
    waitForRelaySend = 1<<2,
    waitForRelayAnswer = 1<<3,
    error = 1<<4
};

namespace ServerConfig {
    static constexpr u_short MODULE_API_PORT = 7401;
    static constexpr u_short P2P_PORT = 7402;
};

struct ConnectionInfo{
        std::vector<unsigned char> receivedBytes;
        bool receivedBytesInUse;
        std::vector<unsigned char> sendBytes; //This is a todo send buffer. See epoll case EPOLLOUT.
        bool sendBytesInUse;
        socket_t relayTo{-1}; //Possibly relay the request to other server that sits closer (XOR) to the requested key.
    };

enum DHT_TYPE{
    DHT_PUT = 650,
    DHT_GET = 651,
    DHT_SUCCESS = 652,
    DHT_FAILURE = 653,

    DHT_RPC_PING = 660,
    DHT_RPC_STORE = 661,
    DHT_RPC_FIND_NODE = 662,
    DHT_RPC_FIND_VALUE = 663,
    DHT_RPC_PING_REPLY = 670,
    DHT_RPC_STORE_REPLY = 671,
    DHT_RPC_FIND_NODE_REPLY = 672,
    DHT_RPC_FIND_VALUE_REPLY = 673,
    DHT_ERROR = 680
    };

std::optional<valueType> get_from_storage(const keyType& key);
void save_to_storage(const keyType& key, valueType val);

bool send_dht_success(socket_t, keyType, valueType); // TODO
bool send_dht_failure(socket_t, keyType); // TODO
 // TODO

int parse_commandline_args(int argc, const char* argv[]);

socket_t setupSocket(u_short port);

int setupEpoll(int epollfd, socket_t serversocket);

void runEventLoop(socket_t module_api_socket, socket_t p2p_socket, int epollfd,
                  std::vector<epoll_event>& epoll_events);

void handleDHTRPCPing(const ConnectionInfo& connectInfo);

void handleDHTPUT(ConnectionInfo& connectInfo);

void handleDHTGET(ConnectionInfo& connectInfo);

void handleDHTSUCCESS(ConnectionInfo& connectInfo);

void handleDHTFAILURE(ConnectionInfo& connectInfo);

void handleDHTRPCStore(const ConnectionInfo& connectInfo);

void handleDHTRPCFindNode(const ConnectionInfo& connectInfo);

void handleDHTRPCFindValue(const ConnectionInfo& connectInfo);

void handleDHTRPCPingReply(const ConnectionInfo& connectInfo);

void handleDHTRPCStoreReply(const ConnectionInfo& connectInfo);

void handleDHTRPCFindNodeReply(const ConnectionInfo& connectInfo);

void handleDHTRPCFindValueReply(const ConnectionInfo& connectInfo);

void handleDHTError(const ConnectionInfo& connectInfo);

bool convertToIPv6(const std::string& address_string, struct in6_addr& address);