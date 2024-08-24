#pragma once

#include <optional>
#include <map>
#include <mutex>
#include <string>
#include <array>
#include <vector>
#include <sys/epoll.h>

static constexpr size_t KEYSIZE  = 32;
static constexpr size_t RPC_ID_SIZE  = KEYSIZE;
static constexpr size_t NODE_ID_SIZE  = KEYSIZE;
static constexpr size_t HEADERSIZE  = 4;
static constexpr size_t NODESIZE  = 16 + 2 + 32; // using 16B for ipv6 instead of ipv4 as defined in midterm

using key_type = std::array<unsigned char,KEYSIZE>;
using value_type = std::vector<unsigned char>;
using message_t = std::vector<unsigned char>;
using socket_t  = int;

bool operator<=(const key_type& lhs, const key_type& rhs);

std::string key_to_string(const key_type& key);

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

enum class ConnectionType {
    MODULE_API, P2P
};

struct ConnectionInfo{
        ConnectionType connectionType;
        key_type rpc_id;
        message_t receivedBytes;
        bool receivedBytesInUse;
        message_t sendBytes; // TODO: This is a todo send buffer. See epoll case EPOLLOUT.
        bool sendBytesInUse;
        socket_t relayTo{-1}; //Possibly relay the request to other server that sits closer (XOR) to the requested key.
        socket_t replyTo{};
    };

enum MODULE_API_TYPE {
    DHT_PUT = 650,
    DHT_GET = 651,
    DHT_SUCCESS = 652,
    DHT_FAILURE = 653,
};

enum P2P_TYPE {
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

std::optional<value_type> get_from_storage(const key_type& key);
void save_to_storage(const key_type& key, value_type val);

bool send_dht_success(socket_t, key_type, value_type); // TODO
bool send_dht_failure(socket_t, key_type); // TODO
 // TODO

int parse_commandline_args(int argc, const char* argv[]);

socket_t setupServerSocket(u_short port);
socket_t setupConnectSocket(std::string address_string, u_short port);
int setupEpoll(int epollfd, socket_t serversocket);


void runEventLoop(socket_t module_api_socket, socket_t p2p_socket, int epollfd,
                  std::vector<epoll_event>& epoll_events);

bool handleDHTRPCPing(const ConnectionInfo& connectInfo);

bool handleDHTPUT(ConnectionInfo& connectInfo);

bool handleDHTGET(ConnectionInfo& connectInfo);

bool handleDHTSUCCESS(ConnectionInfo& connectInfo);

bool handleDHTFAILURE(ConnectionInfo& connectInfo);

bool handleDHTRPCStore(const ConnectionInfo& connectInfo, u_short body_size);

bool handleDHTRPCFindNode(const ConnectionInfo& connectInfo, u_short body_size);

bool handleDHTRPCFindValue(const ConnectionInfo& connectInfo, u_short body_size);

bool handleDHTRPCPingReply(const ConnectionInfo& connectInfo, u_short body_size);

bool handleDHTRPCStoreReply(const ConnectionInfo& connectInfo, u_short body_size);

bool handleDHTRPCFindNodeReply(const ConnectionInfo& connectInfo, u_short body_size);

bool handleDHTRPCFindValueReply(const ConnectionInfo& connectInfo, u_short body_size);

bool handleDHTError(const ConnectionInfo& connectInfo, u_short body_size);

bool convertToIPv6(const std::string& address_string, struct in6_addr& address);

void build_dht_header(size_t body_size, u_short message_type, message_t& message);

bool send_dht_message(socket_t socket, message_t message);