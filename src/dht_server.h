#pragma once

#include <optional>
#include <map>
#include <mutex>
#include <string>
#include <array>
#include <vector>
#include <sys/epoll.h>

#include "routing.h"
#include "common_types.h"

/* Naming scheme:
    classes/enums/structs/namespaces and types -> PascalCase
    functions/variables -> snake_case
    const values -> CAPS
*/

static constexpr size_t RPC_ID_SIZE  = KEY_SIZE;
static constexpr size_t NODE_ID_SIZE  = KEY_SIZE;
static constexpr size_t HEADER_SIZE  = 4;
static constexpr size_t NODE_SIZE  = 16 + 2 + 32; // using 16B for ipv6 instead of ipv4 as defined in midterm

using Message = std::vector<unsigned char>;

using socket_t  = int;

enum ProcessingStatus{
    WAIT_FOR_COMPLETE_MESSAGE_HEADER = 0,
    WAIT_FOR_COMPLETE_MESSAGE_BODY = 1,
    PROCESSED = 1<<1,
    WAIT_FOR_RELAY_SEND = 1<<2,
    WAIT_FOR_RELAY_ANSWER = 1<<3,
    ERROR = 1<<4
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
        Key rpc_id;
        Message receivedBytes;
        bool receivedBytesInUse;
        
        Message sendBytes; // TODO: This is a todo send buffer. See epoll case EPOLLOUT.
        size_t sentBytes{0};
        bool sendBytesInUse;

        socket_t relayTo{-1}; //Possibly relay the request to other server that sits closer (XOR) to the requested key.
        socket_t replyTo{};
    };

enum ModuleApiType {
    DHT_PUT = 650,
    DHT_GET = 651,
    DHT_SUCCESS = 652,
    DHT_FAILURE = 653,
};

enum P2PType {
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

enum ErrorType {
    DHT_BAD_REQUEST = 10,
    DHT_NOT_FOUND = 11,
    DHT_NOT_ACCEPTABLE = 12,
    DHT_SERVER_ERROR = 20,
};

bool operator<(const Key& lhs, const Key& rhs);
bool operator<=(const Key& lhs, const Key& rhs);
bool operator==(const Key& lhs, const Key& rhs);

std::string key_to_string(const Key& key);

std::optional<Value> get_from_storage(const Key& key);
void save_to_storage(const Key& key, Value val);

bool is_in_my_range(Key key);

bool is_valid_module_API_type(u_short value);
bool is_valid_P2P_type(u_short value);
bool is_valid_DHT_type(u_short dht_type);

void build_DHT_header(size_t body_size, u_short message_type, Message& message);
void write_body(Message& message, size_t body_offset, unsigned char* data, size_t data_size);
void read_body(const Message& message, size_t body_offset, unsigned char* data, size_t data_size);

bool send_DHT_message(socket_t socket, Message message);

bool send_DHT_put(socket_t socket, Key& key, Value& value);
bool handle_DHT_put(ConnectionInfo& connect_info);

bool send_DHT_get(socket_t socket, Key& key);
bool handle_DHT_get(ConnectionInfo& connect_info);

bool send_DHT_success(socket_t socket, Key& key, Value& value);
bool handle_DHT_success(ConnectionInfo& connect_info);

bool send_DHT_failure(socket_t socket, Key& key);
bool handle_DHT_failure(ConnectionInfo& connect_info);

bool send_DHT_RPC_ping(socket_t socket);
bool handle_DHT_RPC_ping(const ConnectionInfo& connect_info, u_short body_size);
bool send_DHT_RPC_ping_reply(socket_t socket);
bool handle_DHT_RPC_ping_reply(const ConnectionInfo& connect_info, u_short body_size);

bool send_DHT_RPC_store(socket_t socket, Key& key, Value& value);
bool handle_DHT_RPC_store(const ConnectionInfo& connect_info, u_short body_size);
bool send_DHT_RPC_store_reply(socket_t socket, Key& key, Value& value);
bool handle_DHT_RPC_store_reply(const ConnectionInfo& connect_info, u_short body_size);

bool send_DHT_RPC_find_node(socket_t socket, NodeID node_id);
bool handle_DHT_RPC_find_node(const ConnectionInfo& connect_info, u_short body_size);
bool send_DHT_RPC_find_node_reply(socket_t socket, Key rpc_id,  std::vector<Node> closest_nodes);
bool handle_DHT_RPC_find_node_reply(const ConnectionInfo& connect_info, u_short body_size);

bool send_DHT_RPC_find_value(socket_t socket, Key& key, Value& value);
bool handle_DHT_RPC_find_value(const ConnectionInfo& connect_info, u_short body_size);
bool send_DHT_RPC_find_value_reply(socket_t socket, Key& key, Value& value);
bool handle_DHT_RPC_find_value_reply(const ConnectionInfo& connect_info, u_short body_size);

bool send_DHT_error(socket_t socket, ErrorType error);
bool handle_DHT_error(const ConnectionInfo& connect_info, u_short body_size);

bool parse_header(const ConnectionInfo &connectInfo, u_short &message_size, u_short &dht_type);
bool parse_API_request(ConnectionInfo &connectInfo, u_short body_size, ModuleApiType module_api_type);
bool parse_P2P_request(ConnectionInfo& connectInfo, u_short body_size, P2PType p2p_type);

ProcessingStatus try_processing(socket_t curfd);

void accept_new_connection(int epollfd, std::vector<epoll_event>::value_type curEvent, ConnectionType connectionType);
void run_event_loop(socket_t module_api_socket, socket_t p2p_socket, int epollfd, std::vector<epoll_event>& epoll_events);

socket_t setup_server_socket(u_short port);
socket_t setup_connect_socket(std::string address_string, u_short port);
int setup_epoll(int epollfd, socket_t serversocket);

int parse_commandline_args(int argc, const char* argv[]);