#pragma once

//Library includes
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

enum HandleResult {
    SUCCESS_CLOSE,
    SUCCESS_KEEP_OPEN,
    INVALID_P2P_REQUEST,
    FATAL_HANDLE_ERROR,
};

enum CertificateStatus{
    EXPECTED_CERTIFICATE = 0,
    NEW_VALID_CERTIFICATE,
    CERTIFICATE_NOT_FULLY_PRESENT,
    KNOWN_CERTIFICATE_CONTENT_MISMATCH,
    ERRORED_CERTIFICATE,
};

enum FlushResult
{
    FLUSHED_EVERYTHING,
    FLUSH_AGAIN,
    FLUSH_FATAL
};

enum PrefixedReceiveResult
{
    RECEIVED_EVERYTHING,
    RECEIVE_AGAIN,
    RECEIVE_FATAL
};


enum ProcessingStatus{
    WAIT_FOR_COMPLETE_MESSAGE_HEADER = 0,
    WAIT_FOR_COMPLETE_MESSAGE_BODY = 1,
    PROCESSED = 1<<1,
    MORE_TO_READ = 1<<2,
    PROCESSING_ERROR = 1<<3
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

    Message receive_bytes;
    Message send_bytes;
};
// TODO's for end of rewrite:
// 1. look at every forge/handle call and check that epollfd socket order is correct
// 2. Delete all declarations that are not defined in the .cpp
// 3. is OperationType actually needed
//
enum class NodeRefreshStatus {
    AWAITING_FIRST_REPLY,
    AWAITING_PEER_REPLIES
};

struct Request { // Requests involving NodeLookup: PUT, GET, NETWORK EXPANSION and maintenance
    std::unordered_map<socket_t, bool> peer_request_finished;   // maps sockets of peers to whether the request is finished
                                                                // -> could be because they replied or an async function was called
    std::unordered_set<Node> known_stale_nodes;

    // only defined for node refreshes ("random node lookups" in every bucket) -> network expansion and maintenance
    NodeRefreshStatus node_refresh_status;
    size_t node_count_before_refresh;

    // only defined for key - node lookup: PUT and GET
    Key key;
    int checked_nodes_count; // This is the number of nodes around the key wey want to look at
    std::unordered_set<Node> previous_closest_nodes;

    // only defined for PUT
    Value value;
};

enum OperationType {
    NODE_REFRESH_FOR_NETWORK_EXPANSION,
    NODE_LOOKUP_FOR_PUT,
    NODE_LOOKUP_FOR_GET,
    // NODE_LOOKUP_FOR_NETWORK_REFRESH

    FIND_VALUE,
    STORE
};

struct DHTInfo {
    OperationType operation_type;
    P2PType expected_p2p_reply;
    Request* request;    // shared variable among all participants of the requesting operation

    //Node contacted_node;
    //Node own_node;
    Key rpc_id; // TODO: deal with sending and receiving rpc id
};


enum ErrorType: u_short {
    DHT_BAD_REQUEST = 10,
    DHT_NOT_FOUND = 11,
    DHT_SERVER_ERROR = 20,
};



bool operator<(const Key& lhs, const Key& rhs);
bool operator<=(const Key& lhs, const Key& rhs);
bool operator==(const Key& lhs, const Key& rhs);

std::string key_to_string(const Key& key);
std::string ip_to_string(const in6_addr& ip);

Value* get_from_storage(const Key& key);
void save_to_storage(const Key &key, std::chrono::seconds ttl, Value &val);

bool is_valid_module_API_type(u_short value);
bool is_valid_P2P_type(u_short value);
bool is_valid_DHT_type(u_short dht_type);

void build_DHT_header(Message& message, size_t message_size, u_short message_type);
void write_body(Message& message, size_t body_offset, const unsigned char* data, size_t data_size);
void read_body(const Message& message, size_t body_offset, unsigned char* data, size_t data_size);

void send_DHT_message(int epollfd, socket_t socketfd, const Message &message);

std::vector<Node> blocking_node_lookup(Key &key, size_t number_of_nodes = K);
void crawl_blocking_and_store(Key &key, Value &value, int time_to_live, int replication);
void crawl_blocking_and_return(Key &key, socket_t socket);

void forge_DHT_put(socket_t socket, Key& key, Value& value);
HandleResult handle_DHT_put(socket_t socket, u_short body_size);

void forge_DHT_get(socket_t socket, Key& key);
HandleResult handle_DHT_get(socket_t socket, u_short body_size);

void forge_DHT_success(int epollfd, socket_t socket, const Key& key, const Value& value);
HandleResult handle_DHT_success(socket_t socket, u_short body_size);

void forge_DHT_failure(int epollfd, socket_t socket, Key& key);
HandleResult handle_DHT_failure(socket_t socket, u_short body_size);

void forge_DHT_RPC_ping(socket_t socket, int epollfd);
HandleResult handle_DHT_RPC_ping(int epollfd, socket_t socket, u_short body_size);
void forge_DHT_RPC_ping_reply(int epollfd, socket_t socket, Key rpc_id);
HandleResult handle_DHT_RPC_ping_reply(socket_t socket, u_short body_size, std::unordered_set<socket_t>* successfully_pinged_sockets);

void forge_DHT_RPC_store(socket_t socket, u_short time_to_live, Key& key, Value& value);
HandleResult handle_DHT_RPC_store(int epollfd, socket_t socket, u_short body_size);
void forge_DHT_RPC_store_reply(int epollfd, socket_t socket, Key rpc_id, Key& key, Value& value);
HandleResult handle_DHT_RPC_store_reply(socket_t socket, u_short body_size);

void forge_DHT_RPC_find_node(socket_t socket, NodeID target_node_id);
HandleResult handle_DHT_RPC_find_node(socket_t socket, u_short body_size);
void forge_DHT_RPC_find_node_reply(int epollfd, socket_t socket, Key rpc_id, std::vector<Node> closest_nodes);
HandleResult handle_DHT_RPC_find_node_reply(int epollfd, socket_t socket, u_short body_size);

void forge_DHT_RPC_find_value(socket_t socket, Key& key);
HandleResult handle_DHT_RPC_find_value(int epollfd, socket_t socket, u_short body_size);
void forge_DHT_RPC_find_value_reply(int epollfd, socket_t socket, Key rpc_id, const Key& key, const Value& value);
HandleResult handle_DHT_RPC_find_value_reply(socket_t socket, u_short body_size, std::vector<Value>* found_values);

void forge_DHT_error(socket_t socket, ErrorType error);
HandleResult handle_DHT_error(socket_t socket, u_short body_size);

bool parse_header(const ConnectionInfo &connectInfo, u_short &message_size, u_short &dht_type);
HandleResult handle_API_request(socket_t socket, u_short body_size, ModuleApiType module_api_type);
HandleResult handle_P2P_request(socket_t socket, u_short body_size, P2PType p2p_type);

ProcessingStatus try_processing(socket_t curfd);

void accept_new_connection(int epollfd, const epoll_event &cur_event, ConnectionType connection_type);

int add_to_epoll(int epollfd, socket_t serversocketfd);

socket_t setup_server_socket(u_short port);
socket_t setup_connect_socket(int epollfd, const in6_addr& address, u_int16_t port, ConnectionType connection_type);

bool read_EPOLLIN(int epollfd, const epoll_event& current_event);
bool handle_EPOLLIN(int epollfd, const epoll_event &current_event);
bool handle_EPOLLOUT(int epollfd, const epoll_event &current_event);

socket_t set_socket_blocking(socket_t peer_socket, bool blocking);
bool ensure_tls_blocking(socket_t peer_socket, int timeout_ms = 1000);


int parse_commandline_args(int argc, const char* argv[]);

/*
 * Server Callstack for ssl_accept new connection:
 * init_accept_ssl -> HANDSHAKE_SERVER_WRITE_CERT (possibly even --> PENDING_ACCEPT_READ/WRITE)
 * HANDSHAKE_SERVER_WRITE_CERT -> EPOLLOUT(flush_sendbuf) -> PENDING_ACCEPT_READ/WRITE
 * PENDING_ACCEPT_READ/WRITE -> try_ssl_accept() -> try_ssl_accept() -> ... -> try_ssl_accept() -> ACCEPTED
 */


socket_t init_tcp_connect_ssl(int epollfd, const in6_addr& address, u_int16_t port, ConnectionType connection_type);
/*
 * Client Callstack for ssl_connect to new connection:
 * init_tcp_connect_ssl -> TCP_PENDING
 * TCP_PENDING -> probe_tcp_connect_ssl -> HANDSHAKE_CLIENT_READ_CERT
 * HANDSHAKE_CLIENT_READ_CERT -> init_connect_ssl -> PENDING_CONNECT_READ/WRITE
 * PENDING_CONNECT_READ/WRITE -> try_ssl_connect  -> try_ssl_connect -> ... -> try_ssl_connect -> CONNECTED
 */