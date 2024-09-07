#pragma once

//Library includes
#include <optional>
#include <map>
#include <mutex>
#include <string>
#include <array>
#include <vector>
#include <sys/epoll.h>
#include <filesystem>
#include <unordered_set>

//Project includes
#include "routing.h"
#include "common_types.h"
#include "ssl.h"


/* Naming scheme:
    classes/enums/structs/namespaces and types -> PascalCase
    functions/variables -> snake_case
    const values -> CAPS
*/

static constexpr size_t RPC_ID_SIZE  = KEY_SIZE;
static constexpr size_t NODE_ID_SIZE  = KEY_SIZE;
static constexpr size_t HEADER_SIZE  = 4;
static constexpr size_t RPC_SUB_HEADER_SIZE  = NODE_ID_SIZE + 2 + RPC_ID_SIZE;
static constexpr size_t NODE_SIZE  = 16 + 2 + 32; // using 16B for ipv6 instead of ipv4 as defined in midterm

using Message = std::vector<unsigned char>;
using namespace std::chrono_literals;

using socket_t  = int;

enum CertificateStatus{
    EXPECTED_CERTIFICATE = 0,
    NEW_VALID_CERTIFICATE,
    CERTIFICATE_NOT_FULLY_PRESENT,
    KNOWN_CERTIFICATE_CONTENT_MISMATCH,
    ERRORED_CERTIFICATE,
    
};

enum FlushResult
{
    EVERYTHING_WAS_SENT,
    PARTIALLY_SENT,
    ERROR_TO_TEAR
};


enum ProcessingStatus{
    WAIT_FOR_COMPLETE_MESSAGE_HEADER = 0,
    WAIT_FOR_COMPLETE_MESSAGE_BODY = 1,
    PROCESSED = 1<<1,
    MORE_TO_READ = 1<<2,
    ERROR = 1<<3
};

namespace ServerConfig {
    static constexpr u_short MODULE_API_PORT = 7401;
    static constexpr u_short P2P_PORT = 7402;
};

namespace SSLConfig {
    extern NodeID id;
    extern char ipv6_buf[INET6_ADDRSTRLEN];
    extern EVP_PKEY *pkey;
    extern X509 *cert;
    extern unsigned char *length_prefixed_cert_str;
    extern int cert_len;
    extern SSL_CTX *server_ctx;
    extern SSL_CTX *client_ctx;
    extern X509_STORE * client_cert_store;
    extern CertificateMap cert_map;
    extern std::string certmap_filename;
}

enum class ConnectionType {
    MODULE_API = 0, P2P
};

enum class ConnectionRole {
    SERVER = 0, CLIENT
};

enum class NetworkConnectionStatus {
    TCP_CONNECTED,
    AWAITING_FIND_NODE_REPLY, // first initial call to contact node, that returns its nodes that are close to our ID
    PERFORMING_NETWORK_EXPANSION, // next, we do "network expansion"
    // -> we generate random node ID's in every Bucket and do a node lookup request for those ID's
    //
    // Node Lookup:
    // We first send out a bunch of requests to the nodes that we know of that are the closest to the given key
    // after all the nodes returned, we again filter out the closest nodes from the ones we've received.
    // If there are new ones, we send requests to the new ones
    // We do this, until we don't find any new nodes.
    //
    // after every node lookup, we test whether we found any new nodes.
    // We need to keep in mind to only count nodes that gave us a response to a FIND_NODE request
    CONNECTED, // start accepting connections
};

struct ConnectionInfo{
    ConnectionType connection_type;
    ConnectionRole role;
    in6_addr client_addr;
    u_short client_port; // port in host byte order
    SSL* ssl;
    SSLStatus ssl_stat;
    Key rpc_id;
    Message receive_bytes;
    Message send_bytes;
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

enum ErrorType: u_short {
    DHT_BAD_REQUEST = 10,
    DHT_NOT_FOUND = 11,
    DHT_SERVER_ERROR = 20,
};





bool operator<(const Key& lhs, const Key& rhs);
bool operator<=(const Key& lhs, const Key& rhs);
bool operator==(const Key& lhs, const Key& rhs);

bool is_same_network_node_or_nodeid(const Node &lhs, const Node &rhs);

std::string key_to_string(const Key& key);
std::string ip_to_string(const in6_addr& ip);

Value* get_from_storage(const Key& key);
void save_to_storage(const Key& key, Value val);

bool is_in_my_range(Key key);

bool is_valid_module_API_type(u_short value);
bool is_valid_P2P_type(u_short value);
bool is_valid_DHT_type(u_short dht_type);

void build_DHT_header(Message& message, size_t message_size, u_short message_type);
void write_body(Message& message, size_t body_offset, const unsigned char* data, size_t data_size);
void read_body(const Message& message, size_t body_offset, unsigned char* data, size_t data_size);

void send_DHT_message(socket_t socketfd, const Message &message, int epollfd);

std::vector<Node> blocking_node_lookup(Key &key, size_t number_of_nodes = K);
void crawl_blocking_and_store(Key &key, Value &value, int time_to_live, int replication);
void crawl_blocking_and_return(Key &key, socket_t socket);

bool forge_DHT_put(socket_t socket, Key& key, Value& value);
bool handle_DHT_put(socket_t socket, u_short body_size);

bool forge_DHT_get(socket_t socket, Key& key);
bool handle_DHT_get(socket_t socket, u_short body_size);

bool forge_DHT_success(socket_t socket, int epollfd, const Key& key, const Value& value);
bool handle_DHT_success(socket_t socket, u_short body_size);

bool forge_DHT_failure(socket_t socket, int epollfd, Key& key);
bool handle_DHT_failure(socket_t socket, u_short body_size);

bool forge_DHT_RPC_ping(socket_t socket, int epollfd);
bool handle_DHT_RPC_ping(socket_t socket, int epollfd, u_short body_size);
bool forge_DHT_RPC_ping_reply(socket_t socket, int epollfd, Key rpc_id);
bool handle_DHT_RPC_ping_reply(socket_t socket, u_short body_size, std::unordered_set<socket_t>* successfully_pinged_sockets);

bool forge_DHT_RPC_store(socket_t socket, int epollfd, u_short time_to_live, Key& key, Value& value);
bool handle_DHT_RPC_store(socket_t socket, u_short body_size);
bool forge_DHT_RPC_store_reply(socket_t socket, int epollfd, Key rpc_id, Key& key, Value& value);
bool handle_DHT_RPC_store_reply(socket_t socket, u_short body_size);

bool forge_DHT_RPC_find_node(socket_t socket, int epollfd, NodeID target_node_id);
bool handle_DHT_RPC_find_node(socket_t socket, u_short body_size);
bool forge_DHT_RPC_find_node_reply(socket_t socket, int epollfd, Key rpc_id, std::vector<Node> closest_nodes);
bool handle_DHT_RPC_find_node_reply(socket_t socket, u_short body_size, std::unordered_set<Node>* closest_nodes_ptr = nullptr, std::mutex* returned_nodes_mutex_ptr = nullptr);

bool forge_DHT_RPC_find_value(socket_t socket, int epollfd, Key& key);
bool handle_DHT_RPC_find_value(socket_t socket, u_short body_size);
bool forge_DHT_RPC_find_value_reply(socket_t socket, int epollfd, Key rpc_id, const Key& key, const Value& value);
bool handle_DHT_RPC_find_value_reply(socket_t socket, u_short body_size, std::vector<Value>* found_values);

bool forge_DHT_error(socket_t socket, int epollfd, ErrorType error);
bool handle_DHT_error(socket_t socket, u_short body_size);

bool parse_header(const ConnectionInfo &connectInfo, u_short &message_size, u_short &dht_type);
bool parse_API_request(socket_t socket, u_short body_size, ModuleApiType module_api_type);
bool parse_P2P_request(socket_t socket, u_short body_size, P2PType p2p_type);

ProcessingStatus try_processing(socket_t curfd);

void accept_new_connection(int epollfd, const epoll_event &cur_event, ConnectionType connection_type);
void run_event_loop(socket_t module_api_socket, socket_t p2p_socket, int epollfd, std::vector<epoll_event>& epoll_events);

int add_epoll(int epollfd, socket_t serversocket, uint32_t events);
int mod_epoll(int epollfd, socket_t serversocket, uint32_t events);

socket_t setup_server_socket(u_short port);
socket_t setup_connect_socket(int epollfd, const in6_addr& address, u_int16_t port, ConnectionType connection_type);

bool read_EPOLLIN(int epollfd, const epoll_event& current_event);
bool handle_EPOLLIN(int epollfd, const epoll_event &current_event);
bool handle_EPOLLOUT(int epollfd, const epoll_event &current_event);

socket_t set_socket_blocking(socket_t peer_socket, bool blocking);
bool ensure_tls_blocking(socket_t peer_socket, int timeout_ms = 1000);

int parse_commandline_args(int argc, const char* argv[]);

