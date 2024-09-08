#include "dht_server.h"

#include <array>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/epoll.h>

#include <boost/program_options.hpp>
#include <boost/stacktrace.hpp>

#include <iostream>
#include <map>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <chrono>
#include <unordered_set>

//#include "routing.cpp"
namespace progOpt = boost::program_options;

namespace SSLConfig {
    NodeID id;
    char ipv6_buf[INET6_ADDRSTRLEN];
    EVP_PKEY *pkey;
    X509 *cert;
    unsigned char *length_prefixed_cert_str;
    int cert_len;
    SSL_CTX *server_ctx;
    SSL_CTX *client_ctx;
    X509_STORE *client_cert_store;
    CertificateMap cert_map;
    std::string certmap_filename;
}


/*
Important Remark: Maybe use a logger for keeping track of operations during runtime.
Boost provides one, seemingly a bit hard to set up, but anyway:
https://www.boost.org/doc/libs/1_82_0/libs/log/doc/html/index.html
*/


std::unordered_map<socket_t,ConnectionInfo> connection_map;
std::unordered_map<socket_t,DHTInfo> dht_map;

static constexpr size_t MAX_LIFETIME_SEC = 20*60; // 20 minutes in seconds
static constexpr size_t MIN_LIFETIME_SEC = 3*60;  //  3 minutes in seconds
static constexpr size_t DEFAULT_LIFETIME_SEC = 5*60; // 5 minutes in seconds

static constexpr size_t MAX_REPLICATION = 30;
static constexpr size_t MIN_REPLICATION = 3;
static constexpr size_t DEFAULT_REPLICATION = 20; // should be same to K


std::map<Key,std::pair<std::chrono::time_point<std::chrono::system_clock>, Value>> local_storage{};
std::mutex storage_lock;

RoutingTable routing_table;
std::thread purger;
std::atomic<bool> stop_purger(false);
std::condition_variable stop_purger_cv;
std::mutex stop_purger_cv_mutex;

int main_epollfd;

// Utility functions
template <typename T>
struct defer {
    T const t;
    explicit defer(T _t) : t(std::move(_t)){};
    defer(defer const&) = delete;
    ~defer() { t(); }
};

//defer close_http_socketfd{[&] { ::close(http_socketfd); }};





bool operator<(const Key& lhs, const Key& rhs) {
    for (size_t i = 0; i < KEY_SIZE; ++i) {
        if (lhs[i] < rhs[i]) {
            return true;
        }
        if (lhs[i] > rhs[i]) {
            return false;
        }
    }
    return false;
}

bool operator<=(const Key& lhs, const Key& rhs) {
    for (size_t i = 0; i < KEY_SIZE; ++i) {
        if (lhs[i] < rhs[i]) {
            return true;
        }
        if (lhs[i] > rhs[i]) {
            return false;
        }
    }
    return true;
}

bool operator==(const Key& lhs, const Key& rhs) {
    for (size_t i = 0; i < KEY_SIZE; ++i) {
        if (lhs[i] != rhs[i]) {
            return false;
        }
    }
    return true;
}

bool convert_to_ipv6(const std::string& address_string, struct in6_addr& address) {
    in_addr ipv4_addr{};
    if (inet_pton(AF_INET6, address_string.c_str(), &address) == 1) {
        return true;
    } else if (inet_pton(AF_INET, address_string.c_str(), &ipv4_addr) == 1) {
        // if IPv4, use IPv4-mapped IPv6 address with format ::ffff:<IPv4-address>
        memset(&address, 0, sizeof(address));
        address.s6_addr[10] = 0xff;
        address.s6_addr[11] = 0xff;
        memcpy(&address.s6_addr[12], &ipv4_addr, sizeof(ipv4_addr));
        try {
            char address_converted[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &address, address_converted, INET6_ADDRSTRLEN);
            logTrace("Converted address {} to {}", address_string, address_converted);
        } catch (...) {
            logError("Converted address {} but couldn't format.", address_string);
        }
        return true;
    }
    return false;  // Invalid address
}

std::string key_to_string(const Key &key) {
    return Utils::bin_to_hex(key.data(), 32);
}

std::string ip_to_string(const in6_addr& ip) {
    char ip_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ip, ip_str, sizeof(ip_str));
    return {ip_str};
}

bool send_buffer_empty(const ConnectionInfo &connection_info){
    return connection_info.send_bytes.empty();
}

bool recv_buffer_empty(const ConnectionInfo &connection_info){
    return connection_info.receive_bytes.empty();
}


void write_vector_to_sendbuf(ConnectionInfo &connection_info, const Message &to_send){
    auto &write_buffer = connection_info.send_bytes;
    write_buffer.reserve(write_buffer.size() + to_send.size()); //Avoid unnecessary reallocations
    write_buffer.insert(std::end(write_buffer),std::begin(to_send),std::end(to_send));
}

void write_charptr_to_sendbuf(ConnectionInfo &connection_info, const unsigned char* to_send_ptr, const size_t length){
    auto &write_buffer = connection_info.send_bytes;
    write_buffer.reserve(write_buffer.size() + length); //Avoid unnecessary reallocations
    write_buffer.insert(std::end(write_buffer), to_send_ptr, to_send_ptr + length);
}

void read_vector_from_recvbuf(ConnectionInfo &connection_info, Message &to_recv){
    auto &read_buf = connection_info.receive_bytes;
    to_recv.insert(std::end(to_recv), std::begin(read_buf),std::end(read_buf));
    read_buf.clear();
}


//TODO: Test if purger stop works
//Periodically purges local_storage
void purge_local_storage(std::chrono::seconds sleep_period){
    logDebug("New thread for purge_local_storage started. Will run forever.");
    while (true) {
        std::unique_lock<std::mutex> lk(stop_purger_cv_mutex);
        if (stop_purger_cv.wait_for(lk, sleep_period) == std::cv_status::timeout){
            lk.unlock();
            // We waited on cv so long that the wait timed out. This means we continue working! :)
            auto time_to_purge = std::chrono::system_clock::now();
            std::lock_guard<std::mutex> lock(storage_lock);
            for (auto it = local_storage.begin(); it != local_storage.end(); /* no increment here due to iterator invalidation! */) {
                auto &[time, value] = it->second;
                if (time < time_to_purge){
                    it = local_storage.erase(it);
                } else {
                    ++it;
                }
            }
        } else {
            if (stop_purger) {
                break;
            }
        }
    }
}



// SSL
// TODO revise
void tear_down_connection(int epollfd, socket_t socketfd){

    if(connection_map.contains(socketfd)){
        ConnectionInfo connection_info = connection_map.at(socketfd);
        //Module API socket (to client).
        if(connection_info.connection_type == ConnectionType::MODULE_API){
            close(socketfd);
            return;
        }
        //Else: P2P Connection Type.
        if(SSLUtils::isAliveSSL(connection_info.ssl_stat)){
           //SSL connection is up. Shut it down.
           SSL_shutdown(connection_info.ssl);
        }
        //Free ssl object of the connection.
        SSL_free(connection_info.ssl);
        //SSL objects all freed. Proceed with lower layer freeing.
        close(socketfd);
        connection_map.erase(socketfd);

        epoll_ctl(epollfd,EPOLL_CTL_DEL,socketfd,nullptr);

        logDebug("Tore down connection running over port: {}.", connection_info.client_port);

    }else{
        //Should be a dead branch:
        //TODO: Investigate
        logDebug("tear_down_connection: tore down connection which was not yet contained in the connection_map");
        close(socketfd);
    }
}


//TODO: FlushResult instead of bool pair lol
//Returns <is_socket_still_up?,everything_was_sent?>
std::pair<bool,bool> flush_write_connInfo_with_SSL(ConnectionInfo &connection_info, const int epollfd, const int socketfd){
    auto &sendbuf = connection_info.send_bytes;

    auto &ssl = connection_info.ssl;
    int bytes_flushed;
    std::pair ret = {true,false};
    auto &[is_socket_still_up,was_everything_sent] = ret;

    do{
        bytes_flushed = SSL_write(ssl,sendbuf.data(),sendbuf.size());
        if(bytes_flushed <= 0){
            int err = SSL_get_error(ssl, bytes_flushed);
            if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
                // Retry SSL_write() later.
                logDebug("SSL write error, try again later");
                is_socket_still_up = true;
                was_everything_sent = false;
                return ret;
            } else {
                tear_down_connection(epollfd,socketfd);
                logError("Other SSL write error: {}. Tore down connection", err);
                is_socket_still_up = false;
                was_everything_sent = false;
                return ret;
            }
        }
        //Partial written, advance buffer accordingly.
        sendbuf.erase(std::begin(sendbuf),std::begin(sendbuf) + bytes_flushed);

    } while(bytes_flushed > 0 && sendbuf.size() > 0);

    is_socket_still_up = true;
    was_everything_sent = true;
    return ret;
}

//Returns <is_socket_still_up?,everything_was_sent?>
std::pair<bool,bool> flush_write_connInfo_without_SSL(ConnectionInfo &connection_info, const int epollfd, const int socketfd){
    auto &sendbuf = connection_info.send_bytes;

    int bytes_flushed;
    std::pair ret = {true,false};
    auto &[is_socket_still_up,was_everything_sent] = ret;

    do{
        bytes_flushed = write(socketfd,sendbuf.data(),sendbuf.size());

        if(bytes_flushed == -1){
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // Retry write() later.
                logDebug("Socket write error, try again later");
                is_socket_still_up = true;
                was_everything_sent = false;
                return ret;
            } else {
                tear_down_connection(epollfd,socketfd);
                logError("Other socket write error. Tore down connection.");
                is_socket_still_up = false;
                was_everything_sent = false;
                return ret;
            }
        }
        //Partial written, advance buffer accordingly.
        sendbuf.erase(std::begin(sendbuf),std::begin(sendbuf) + bytes_flushed);
    } while(bytes_flushed > 0 && sendbuf.size() > 0);

    is_socket_still_up = true;
    was_everything_sent = true;
    return ret;
}

//Returns <is_socket_still_up?,was_everything_sent?>
std::pair<bool,bool> flush_sendbuf(socket_t socketfd, ConnectionInfo & connection_info, int epollfd){
    if(send_buffer_empty(connection_info)){
        return {true,true};
    }

    if(connection_info.connection_type == ConnectionType::MODULE_API){
        //Easy flush, simply write without respecting ssl.
        return flush_write_connInfo_without_SSL(connection_info,epollfd,socketfd);
    }

    //We are in a ConnectionType::P2P

    if(SSLUtils::isAliveSSL(connection_info.ssl_stat)){
        //Write with SSL
        return flush_write_connInfo_with_SSL(connection_info,epollfd,socketfd);
    }
    //Else: SSL is not active (yet). P2P-Connections enforce TLS, so this will happen soon.
    //Server & Client write without SSL encryption
    return flush_write_connInfo_without_SSL(connection_info,epollfd,socketfd);
}


bool flush_read_connInfo_with_SSL(ConnectionInfo &connection_info, const int epollfd, const int socketfd){
    auto &recvbuf = connection_info.receive_bytes;

    auto&ssl = connection_info.ssl;
    int bytes_flushed;

     std::vector<unsigned char> temp_buffer(4096); // Temporary buffer for reading

    do{
        ERR_clear_error();
        bytes_flushed = SSL_read(ssl,temp_buffer.data(),temp_buffer.size());

        if(bytes_flushed > 0){
            //Append bytes to recvbuf
            recvbuf.insert(std::end(recvbuf),std::begin(temp_buffer),std::begin(temp_buffer) + bytes_flushed);
            temp_buffer.erase(std::begin(temp_buffer),std::begin(temp_buffer) + bytes_flushed);
        } else{
            int err = SSL_get_error(ssl,bytes_flushed);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                // We should try reading or writing later, nothing to tear down
                return true; // Socket is still up
            }
            logDebug("SSL read returned <= 0, error is: {} ", SSL_get_error(ssl, bytes_flushed));
            tear_down_connection(epollfd, socketfd);
            return false; //Socket is down
        }

    }while (bytes_flushed>0);

    return true; // Socket is still up
}

bool flush_read_connInfo_without_SSL(ConnectionInfo &connection_info, const int epollfd, const int socketfd){
    auto &recvbuf = connection_info.receive_bytes;
    int bytes_flushed;

    std::vector<unsigned char> temp_buffer(4096); // Temporary buffer for reading

    do{
        bytes_flushed = read(socketfd, temp_buffer.data(), temp_buffer.size());

        if(bytes_flushed > 0){
            //Append the bytes read to the recvbuf
            recvbuf.insert(std::end(recvbuf),std::begin(temp_buffer),std::begin(temp_buffer) + bytes_flushed);
            temp_buffer.erase(std::begin(temp_buffer),std::begin(temp_buffer) + bytes_flushed);
        } else if (bytes_flushed == -1){
            if(errno == EAGAIN || errno == EWOULDBLOCK){
                // We should try reading later
                return true; // Socket is still up
            }else{
                // An error occurred, tear down the connection
                logDebug("An error occured during send without SSL. Tearing down connection.");
                tear_down_connection(epollfd, socketfd);
                return false; // Socket is down
            }
        }else if(bytes_flushed == 0){
            // Connection was closed by the peer
            logDebug("Connection was closed by peer on send without SSL. Tearing down connection.");
            tear_down_connection(epollfd, socketfd);
            return false; // Socket is down
        }
    } while (bytes_flushed > 0);

    return true; //Socket is still up
}


//Flushes the kernel-side socketfd-buffer into the connection_info receive_bytes buffer.
//Returns if the socketfd is still valid (connection is not torn down).
bool flush_recvbuf(socket_t socketfd, ConnectionInfo & connection_info, int epollfd){

    if(connection_info.connection_type == ConnectionType::MODULE_API){
        // Easy flush, simply read without respecting SSL
        return flush_read_connInfo_without_SSL(connection_info, epollfd, socketfd);
    }

    //We are in a ConnectionType::P2P
    if(SSLUtils::isAliveSSL(connection_info.ssl_stat)){
        return flush_read_connInfo_with_SSL(connection_info,epollfd,socketfd);
    }

    // Else: SSL is not active (yet). P2P-Connections enforce TLS, so this will happen soon.
    // Server & Client read without SSL encryption
    return flush_read_connInfo_without_SSL(connection_info,epollfd,socketfd);
}

//Returns true if the socketfd is still active. If the return parameter foreign_cert_str is not nullptr, data was correctly extracted.
bool receive_prefixed_sendbuf_in_charptr(const int epollfd, const socket_t socketfd, ConnectionInfo& connection_info,
                                         unsigned char* & foreign_length_prefixed_cert_str, uint32_t &data_length){
    foreign_length_prefixed_cert_str = nullptr;
    bool sock_still_active = flush_recvbuf(socketfd, connection_info,epollfd);
    if(!sock_still_active){
        return false;
    }
    auto &receive_buffer = connection_info.receive_bytes;

    if(receive_buffer.size() < sizeof(uint32_t)){
        //4 bytes are prefixed as length. If less is present, insufficient.
        return true;
    }
    uint32_t net_length;
    std::memcpy(&net_length,receive_buffer.data(),sizeof(net_length));
    data_length = ntohl(net_length);
    if(receive_buffer.size() < sizeof(net_length) + data_length){
        //Data was not fully received yet. Length prefix indicates that more data is awaited.
        return true;
    }
    foreign_length_prefixed_cert_str = (unsigned char *)malloc(data_length);
    if(!foreign_length_prefixed_cert_str){
        return true;
    }
    std::memcpy(foreign_length_prefixed_cert_str, receive_buffer.data() + sizeof(uint32_t), data_length);
    receive_buffer.erase(std::begin(receive_buffer), std::begin(receive_buffer) + sizeof(uint32_t) + data_length);
    return true;
}

// Storage

// Returns optional value, either the correctly looked up value, or no value.
Value* get_from_storage(const Key &key)
{
    auto it = local_storage.find(key);
    // We could also perform kademlia tree index checks here.
    if(it == local_storage.end()){ //Log look-up hit, but maybe outdated.
        return nullptr;
    }
    auto& [ttl,value] = it->second;
    if (ttl < std::chrono::system_clock::now()){
        return nullptr; // Log lookup-miss. //Will be purged automatically every 90s.
    }
    return &value; // Log lookup-hit.
}

void save_to_storage(const Key &key, std::chrono::seconds ttl, Value &val)
{
    std::lock_guard<std::mutex> lock(storage_lock);
    auto [it, succ] = local_storage.insert_or_assign(key, std::pair{std::chrono::system_clock::now() + ttl,val});
    // Log fresh_insert. True equiv. to "New value created". False equiv. to
    // "Overwritten, assignment"
}

// Message Handling+Construction utils

bool is_valid_module_API_type(u_short value) {
    return value >= DHT_PUT && value <= DHT_FAILURE;
}

bool is_valid_P2P_type(u_short value) {
    return (value >= DHT_RPC_PING && value <= DHT_RPC_FIND_VALUE) ||
           (value >= DHT_RPC_PING_REPLY && value <= DHT_RPC_FIND_VALUE_REPLY) ||
           value == DHT_ERROR;
}

bool is_valid_DHT_type(u_short dht_type) {
    return is_valid_P2P_type(dht_type) || is_valid_module_API_type(dht_type);
}



void build_DHT_header(Message& message, size_t message_size, u_short message_type) {
    // we are extracting high and low bytes here
    // >> 8 gives us the high byte
    // and & 0xFF masks out the low byte
    message[0] = (message_size) >> 8;
    message[1] = (message_size) & 0xFF;
    message[2] = message_type >> 8;
    message[3] = message_type & 0xFF;
}

void build_RPC_header(Message& message, Key& rpc_id) {
    NodeID node_id = routing_table.get_local_node().id;
    u_short port = routing_table.get_local_node().port;
    u_short network_order_port = htons(port);
    write_body(message, 0UL, node_id.data(), NODE_ID_SIZE);
    write_body(message, NODE_ID_SIZE, reinterpret_cast<unsigned char*>(&network_order_port), 2UL);
    write_body(message, NODE_ID_SIZE + 2, rpc_id.data(), RPC_ID_SIZE);
}

Key read_rpc_header(const Message& message, in6_addr peer_ip) {
    NodeID sender_node_id;
    read_body(message, 0, sender_node_id.data(), NODE_ID_SIZE);
    u_short network_order_port;
    read_body(message, NODE_ID_SIZE, reinterpret_cast<unsigned char*>(&network_order_port), 2);
    u_short sender_port = ntohs(network_order_port);
    Key rpc_id;
    read_body(message, NODE_ID_SIZE + 2, rpc_id.data(), RPC_ID_SIZE);

    auto peer = Node{peer_ip, sender_port, sender_node_id};
    if (!routing_table.contains(peer)) {
        logInfo("Got contacted by new peer reachable at {}:{}", ip_to_string(peer.addr), sender_port);
        routing_table.try_add_peer(peer);
    }

    return rpc_id;
}

void write_body(Message& message, size_t body_offset, const unsigned char* data, size_t data_size) {
    std::copy_n(data, data_size, message.data() + HEADER_SIZE + body_offset);
}

void read_body(const Message& message, size_t body_offset, unsigned char* data, size_t data_size) {
    std::copy_n(message.data() + HEADER_SIZE + body_offset, data_size, data);
}

void send_DHT_message(socket_t socketfd, const Message &message) {
    if (!message.empty()) {
        write_vector_to_sendbuf(connection_map.at(socketfd), message);
    }
    logTrace("Wrote data to sendbuffer for sending DHT message");
    // will be sent with next epoll wait
}

bool check_rpc_id(const Message &message, const Key &correct_rpc_id) {
    Key rpc_id;
    read_body(message, NODE_ID_SIZE + 2, rpc_id.data(), 32);
    if (rpc_id != correct_rpc_id) {
        logWarn("Got message with invalid rpc-id!");
        return false;
    }
    return true;
}

// Module API functions handling+construction functions

bool forge_DHT_put(socket_t socketfd, Key &key, Value &value) {
    return true;
}

bool handle_DHT_put(socket_t socketfd, u_short body_size) {
    const Message& message = connection_map.at(socketfd).receive_bytes;
    const u_short value_size = body_size - (4 + KEY_SIZE);

    // "Request of and storage of empty values is not allowed."
    if (value_size <= 0) {
        return false;
    }

    u_short network_order_TTL;
    read_body(message, 0, reinterpret_cast<unsigned char*>(&network_order_TTL), 2);
    int time_to_live = ntohs(network_order_TTL);
    if (time_to_live > MAX_LIFETIME_SEC || time_to_live < MIN_LIFETIME_SEC) {
        time_to_live = DEFAULT_LIFETIME_SEC;
    }

    unsigned char replication_data;
    read_body(message, 2, &replication_data, 1);
    int replication = static_cast<int>(replication_data);

    if (replication > MAX_REPLICATION || replication < MIN_REPLICATION) {
        replication = DEFAULT_REPLICATION;
    }

    Key key{};
    read_body(message, 4, key.data(), KEY_SIZE);
    Value value{};
    value.resize(value_size);
    read_body(message, 4 + KEY_SIZE, value.data(), value_size);

    // node_lookup = new NodeLookup() (should initiate returned_nodes, potentially think about min capacity of K*ALPHA and requested_socketfds/responeded_socketfds, potentially cap. of K)
    // protocol_map[socketfd].node_lookup = &node_lookup;
    // node_lookup.reason = DHT_PUT
    /*
     * for (node : get_closest_nodes(key)) {
     *  peer_socketfd = connect_socket();
     *  protocol_map[peer_socketfd].node_lookup = &node_lookup;
     *  send_find_node_rpc(peer_socketfd, key);
     *  node_lookup.requested_socketfds.push_back(peer_socketfd);
     *  // for finished node lookup, we need to send a store request to all, but don't need to return to the module, so don't need to save socketfd
     *  // If we don't get any responses, we only store ourselves
     *      -> if we don't have any nodes, store directly
     *      -> if we don't get any responses, ASYNC TIMEOUT-function
     *  // If we are in the closest_nodes
     *  }
     */

    logInfo("Got request to set key '{}' to value '{}'", key_to_string(key), Utils::bin_to_hex(value.data(), value.size()));

    /*
    std::thread([key, value, time_to_live, replication]() mutable {
        crawl_blocking_and_store(key, value, time_to_live, replication);
    }).detach();
    */

    return true;
}

bool forge_DHT_get(socket_t socketfd, Key &key) {
    return true;
}

bool handle_DHT_get(socket_t socketfd, u_short body_size) {
    if (body_size != KEY_SIZE) {
        return false;
    }
    const Message& message = connection_map.at(socketfd).receive_bytes;
    Key key;
    read_body(message, 0, key.data(), KEY_SIZE);

    // node_lookup = new NodeLookup()  (should initiate returned_nodes, potentially think about min capacity of K*ALPHA and requested_socketfds/responeded_socketfds, potentially cap. of K)
    // protocol_map[socketfd].node_lookup = &node_lookup;
    // node_lookup.reason = DHT_GET
    /*
     * for (node : get_closest_nodes(key)) {
     *  peer_socketfd = connect_socket();
     *  protocol_map[peer_socketfd].node_lookup = &node_lookup;
     *  send_find_node_rpc(peer_socketfd, key);
     *  node_lookup.requested_socketfds.push_back(peer_socketfd);
     *  // for finished node lookup, we need to send a get request to all -> state transition to WAITING_FIND_VALUE_REPLY
     *          -> continue in handle_FIND_VALUE_REPLY
     *  // If we don't get any responses, we only get from ourselves (maybe think about doing this first -> faster response)
     *      -> if we don't have any nodes, get directly, else DHT_FAILURE
     *      -> if we don't get any responses, ASYNC TIMEOUT-function to send DHT_FAILURE
     *  }
     */

    /*
    logInfo("Got request to get key '{}'", key_to_string(key));
    std::thread([key, socketfd]() mutable {
        crawl_blocking_and_return(key, socketfd);
    }).detach();
    */
    return true;
}

bool forge_DHT_success(int epollfd, socket_t socketfd, const Key &key, const Value &value) {
    size_t message_size = HEADER_SIZE + KEY_SIZE + value.size();
    Message message(message_size);

    build_DHT_header(message, message_size, DHT_SUCCESS);
    write_body(message, 0, key.data(), KEY_SIZE);
    write_body(message, KEY_SIZE, value.data(), value.size());

    logTrace("Sending DHT success back");

    send_DHT_message(epollfd, socketfd, message);
    return true;
}

bool handle_DHT_success(socket_t socketfd, u_short body_size) {
    return false;
}

bool forge_DHT_failure(int epollfd, socket_t socketfd, Key &key) {
    size_t message_size = HEADER_SIZE + KEY_SIZE;
    Message message(message_size);

    build_DHT_header(message, message_size, DHT_FAILURE);
    write_body(message, 0, key.data(), KEY_SIZE);

    logTrace("Sending DHT failure back");
    send_DHT_message(epollfd, socketfd, message);
    return true;
}

bool handle_DHT_failure(socket_t socketfd, u_short body_size) {
    return false;
}


// P2P/RPC handling+construction functions

void forge_DHT_RPC_ping(int epollfd, socket_t socketfd) {
    Key rpc_id = generate_random_nodeID();
    dht_map.at(socketfd).rpc_id = rpc_id;

    size_t body_size = RPC_SUB_HEADER_SIZE;
    size_t message_size = HEADER_SIZE  + body_size;
    u_short message_type = DHT_RPC_PING;
    Message message(message_size);

    build_DHT_header(message, message_size, message_type);
    build_RPC_header(message, rpc_id);

    logTrace("Sending DHT RPC ping");
    send_DHT_message(epollfd, socketfd, message);
}

bool handle_DHT_RPC_ping(const int epollfd, socket_t socketfd, const u_short body_size) {
    const Message& message = connection_map.at(socketfd).receive_bytes;
    Key rpc_id = read_rpc_header(message, connection_map.at(socketfd).client_addr);
    forge_DHT_RPC_ping_reply(socketfd, epollfd, rpc_id);
    return true;
}

bool forge_DHT_RPC_ping_reply(int epollfd, socket_t socketfd, Key rpc_id) {
    size_t body_size = RPC_SUB_HEADER_SIZE;
    size_t message_size = HEADER_SIZE + body_size;
    u_short message_type = DHT_RPC_PING_REPLY;
    Message message(message_size);

    build_DHT_header(message, message_size, message_type);
    build_RPC_header(message, rpc_id);

    logTrace("Sending DHT RPC ping reply");
    send_DHT_message(epollfd, socketfd, message);
    return true;
}

bool handle_DHT_RPC_ping_reply(const socket_t socketfd, const u_short body_size) {
    const Message& message = connection_map.at(socketfd).receive_bytes;
    if (!check_rpc_id(message, dht_map.at(socketfd).rpc_id)) {
        return false;
    }
    return true;
}

bool forge_DHT_RPC_store(int epollfd, socket_t socketfd, u_short time_to_live, const Key &key, const Value &value) {
    Key rpc_id = generate_random_nodeID();
    dht_map.at(socketfd).rpc_id = rpc_id;

    size_t body_size = RPC_SUB_HEADER_SIZE + 2 + KEY_SIZE + value.size();;
    size_t message_size = HEADER_SIZE + body_size;
    u_short message_type = DHT_RPC_STORE;
    Message message(message_size);

    build_DHT_header(message, message_size, message_type);
    build_RPC_header(message, rpc_id);

    u_short network_order_TTL = htons(time_to_live);
    write_body(message, RPC_SUB_HEADER_SIZE, reinterpret_cast<unsigned char*>(&network_order_TTL), 2);
    write_body(message, RPC_SUB_HEADER_SIZE + 2, key.data(), KEY_SIZE);
    write_body(message, RPC_SUB_HEADER_SIZE + 2 + KEY_SIZE, value.data(), value.size());

    logTrace("Sending DHT RPC store");
    send_DHT_message(epollfd, socketfd, message);
    return true;
}

bool handle_DHT_RPC_store(const socket_t socketfd, const u_short body_size) {
    if (body_size <= RPC_SUB_HEADER_SIZE + 2 + KEY_SIZE) {
        return false;
    }
    const Message& message = connection_map.at(socketfd).receive_bytes;
    const u_short value_size = body_size - (RPC_SUB_HEADER_SIZE + 2 + KEY_SIZE);

    const Key rpc_id = read_rpc_header(message, connection_map.at(socketfd).client_addr);

    u_short network_order_TTL;
    read_body(message, RPC_SUB_HEADER_SIZE, reinterpret_cast<unsigned char*>(&network_order_TTL), 2);
    int time_to_live = ntohs(network_order_TTL);
    Key key;
    read_body(message, RPC_SUB_HEADER_SIZE + 2, key.data(), KEY_SIZE);
    Value value{};
    value.resize(value_size);

    read_body(message, RPC_SUB_HEADER_SIZE + 2 + KEY_SIZE, value.data(), value_size);

    if (time_to_live > MAX_LIFETIME_SEC || time_to_live < MIN_LIFETIME_SEC) {
        // default time to live, as value is out of lifetime bounds
        time_to_live = DEFAULT_LIFETIME_SEC;
    }

    save_to_storage(key, std::chrono::seconds(time_to_live), value);

    return forge_DHT_RPC_store_reply(socketfd, main_epollfd, rpc_id, key, value);
}

bool forge_DHT_RPC_store_reply(int epollfd, socket_t socketfd, Key rpc_id, Key &key, Value &value) {
    size_t body_size = RPC_SUB_HEADER_SIZE + KEY_SIZE + value.size();;
    size_t message_size = HEADER_SIZE + body_size;
    u_short message_type = DHT_RPC_STORE_REPLY;
    Message message(message_size);

    build_DHT_header(message, message_size, message_type);
    build_RPC_header(message, rpc_id);

    write_body(message, RPC_SUB_HEADER_SIZE, key.data(), KEY_SIZE);
    write_body(message, RPC_SUB_HEADER_SIZE + KEY_SIZE, value.data(), value.size());

    logTrace("Sending DHT RPC store reply");
    send_DHT_message(epollfd, socketfd, message);
    return true;
}

bool handle_DHT_RPC_store_reply(const socket_t socketfd, const u_short body_size) {
    if (body_size <= RPC_SUB_HEADER_SIZE + KEY_SIZE) {
        return false;
    }
    const Message& message = connection_map.at(socketfd).receive_bytes;
    if (!check_rpc_id(message, dht_map.at(socketfd).rpc_id)) {
        return false;
    }

    Value sent_value;
    size_t bytes_before_key = HEADER_SIZE + RPC_SUB_HEADER_SIZE + 4;
    size_t bytes_before_value = bytes_before_key + KEY_SIZE;
    auto& sent_message = connection_map.at(socketfd).send_bytes;

    Key sent_key;
    read_body(sent_message, bytes_before_key, sent_key.data(), KEY_SIZE);
    size_t value_size = sent_message.size() - bytes_before_value;
    if (value_size > 0) {
        sent_value.resize(value_size);
        read_body(sent_message, bytes_before_value, sent_value.data(), value_size);
    }

    Value saved_value;
    bytes_before_value = HEADER_SIZE + RPC_SUB_HEADER_SIZE + KEY_SIZE;;
    value_size = message.size() - bytes_before_value;
    if (value_size > 0) {
        saved_value.resize(value_size);
        read_body(message, bytes_before_value, saved_value.data(), value_size);
    }

    if (!std::ranges::equal(sent_value, saved_value)) {
        logWarn("The value received for key {} differs from the value sent.", key_to_string(sent_key));
    }
    return true;
}

void forge_DHT_RPC_find_node(socket_t socketfd, NodeID target_node_id) {
    Key rpc_id = generate_random_nodeID();
    dht_map.at(socketfd).rpc_id = rpc_id;

    size_t body_size = RPC_SUB_HEADER_SIZE + KEY_SIZE;
    size_t message_size = HEADER_SIZE + body_size;
    u_short message_type = DHT_RPC_FIND_NODE;
    Message message(message_size);

    build_DHT_header(message, message_size, message_type);
    build_RPC_header(message, rpc_id);

    write_body(message, RPC_SUB_HEADER_SIZE, target_node_id.data(), NODE_ID_SIZE);

    logTrace("Sending DHT RPC find node");
    send_DHT_message(socketfd, message);
}


bool handle_DHT_RPC_find_node(const socket_t socketfd, const u_short body_size) {
    if (body_size != RPC_SUB_HEADER_SIZE + NODE_ID_SIZE) {
        return false;
    }
    const Message& message = connection_map.at(socketfd).receive_bytes;

    Key rpc_id = read_rpc_header(message, connection_map.at(socketfd).client_addr);

    NodeID target_node_id;
    read_body(message, RPC_SUB_HEADER_SIZE, target_node_id.data(), NODE_ID_SIZE);

    // find the closest nodes, then return them:
    auto closest_nodes = routing_table.find_closest_nodes(target_node_id);
    logInfo("Found {} nodes and returning them", closest_nodes.size());
    return forge_DHT_RPC_find_node_reply(socketfd, main_epollfd, rpc_id, closest_nodes);
}

bool forge_DHT_RPC_find_node_reply(int epollfd, socket_t socketfd, Key rpc_id, std::vector<Node> closest_nodes) {
    size_t body_size = RPC_SUB_HEADER_SIZE + closest_nodes.size() * NODE_SIZE;
    size_t message_size = HEADER_SIZE + body_size;
    u_short message_type = DHT_RPC_FIND_NODE_REPLY;
    Message message(message_size);

    build_DHT_header(message, message_size, message_type);
    build_RPC_header(message, rpc_id);

    for (size_t i = 0; i < closest_nodes.size(); i++) {
        auto& node = closest_nodes.at(i);
        write_body(message, RPC_SUB_HEADER_SIZE + i*NODE_SIZE, node.addr.s6_addr, 16);
        u_short port_network_order = htons(node.port);
        write_body(message, RPC_SUB_HEADER_SIZE + i*NODE_SIZE + 16, reinterpret_cast<unsigned char*>(&port_network_order), 2);
        write_body(message, RPC_SUB_HEADER_SIZE + i*NODE_SIZE + 16 + 2, node.id.data(), 32);
    }

    logTrace("Sending Find node reply");
    send_DHT_message(epollfd, socketfd, message);
    return true;
}


bool all_peer_request_finished(NodeLookup* node_lookup) {
    return std::ranges::all_of(node_lookup->peer_request_finished,
                               [](auto responded) { return responded.second; });
}

bool handle_DHT_RPC_find_node_reply(int epollfd, const socket_t socketfd, const u_short body_size) {
    if ((body_size - RPC_SUB_HEADER_SIZE) % NODE_SIZE != 0) {
        return false;
    }
    auto& dht_info =  dht_map.at(socketfd); // TODO: segfault
    if (dht_info.expected_p2p_reply != DHT_RPC_FIND_NODE_REPLY) {
        logTrace("handle_DHT_RPC_find_node_reply: received FIND NODE REPLY without request.");
        return false;
    }

    const size_t num_nodes = (body_size - RPC_SUB_HEADER_SIZE) / NODE_SIZE;
    const Message& message = connection_map.at(socketfd).receive_bytes;

    if (!check_rpc_id(message, dht_info.rpc_id)) {
        return false;
    }

    std::unordered_set<Node> received_closest_nodes{0}; // TODO could include us and invalid nodes

    for (int i = 0; i < num_nodes; i++) {
        Node node{};
        read_body(message, RPC_SUB_HEADER_SIZE + i*NODE_SIZE, node.addr.s6_addr, 16);
        read_body(message, RPC_SUB_HEADER_SIZE + i*NODE_SIZE + 16, reinterpret_cast<unsigned char*>(&node.port), 2);
        node.port = ntohs(node.port);
        read_body(message, RPC_SUB_HEADER_SIZE + i*NODE_SIZE + 16 + 2, node.id.data(), 32);

        routing_table.try_add_peer(node);
        received_closest_nodes.insert(node);
    }

    logTrace("Got back {} node{} from RPC find node reply", received_closest_nodes.size(), (received_closest_nodes.size() != 1 ? "s" : ""));

    // what definitely already happened: send find node request to contact first peer

    switch(dht_info.operation_type) {
        case OperationType::NODE_LOOKUP_FOR_NETWORK_EXPANSION:
            switch(dht_info.node_lookup->node_lookup_status) {
                case NodeLookupStatus::AWAITING_FIRST_REPLY:
                    logTrace("handle_DHT_RPC_find_node_reply: Got reply to initial FIND_NODE request. Adding new nodes to routing_table");
                    dht_info.node_lookup->received_nodes = std::unordered_set<Node>{K*ALPHA};
                    dht_info.node_lookup->node_lookup_status = NodeLookupStatus::AWAITING_PEER_REPLIES;
                    dht_info.node_lookup->known_stale_nodes = std::unordered_set<Node>{}; //based on received ones in ASYNC TIMEOUT function. remember to decrement node_count_before_refresh oÄ, think of 0 case (size_t)
                    dht_info.node_lookup->peer_request_finished = std::unordered_map<socket_t, bool>{};
                    dht_info.node_lookup->peer_request_finished[socketfd] = true;
                    dht_info.node_lookup->node_count_before_refresh = routing_table.count();
                    logTrace("handle_DHT_RPC_find_node_reply: routing_table currently has {} nodes before adding the ones we just got", dht_info.node_lookup->node_count_before_refresh);
                    for (auto& node : received_closest_nodes) {
                        if (!routing_table.has_same_addr_or_id(node) && node.is_valid_node()) {
                            dht_info.node_lookup->received_nodes.insert(node);
                            routing_table.try_add_peer(node);
                        }
                    }

                    for(auto& bucket : routing_table.get_bucket_list()) {
                        logTrace("handle_DHT_RPC_find_node_reply: starting node refresh");
                        // send request about random key of every bucket to the closest nodes
                        Key random_key = generate_random_nodeID(bucket.get_start(), bucket.get_end());
                        for (auto& peer_node : routing_table.find_closest_nodes(random_key)) {
                            socket_t peer_socketfd = init_connect_ssl(epollfd, peer_node.addr, peer_node.port, ConnectionType::P2P);
                            tear_down_connection(epollfd, init_connect_ssl);
                            // ssl init
                            dht_map[peer_socketfd] = DHTInfo {
                                        {NODE_LOOKUP_FOR_NETWORK_EXPANSION},
                                        {DHT_RPC_FIND_NODE_REPLY},
                                        dht_info.node_lookup
                                    };
                            dht_info.node_lookup->peer_request_finished[peer_socketfd] = false;
                            forge_DHT_RPC_find_node(peer_socketfd, random_key);
                        }
                        logTrace("handle_DHT_RPC_find_node_reply: node refresh requests all sent. Waiting for replies...");
                    }
                break;
                case NodeLookupStatus::AWAITING_PEER_REPLIES:
                    for (auto& node : received_closest_nodes) {
                        if (!routing_table.has_same_addr_or_id(node) && node.is_valid_node() &&
                                !dht_info.node_lookup->known_stale_nodes.contains(node)) {
                            dht_info.node_lookup->received_nodes.insert(node);
                            routing_table.try_add_peer(node);
                        }
                    }
                    // if all returned:
                    if (all_peer_request_finished(dht_info.node_lookup)) {
                        // if routing_table.count() > previous node count:
                        if (routing_table.count() > dht_info.node_lookup->node_count_before_refresh) {
                            // repeat procedure
                            for(auto& bucket : routing_table.get_bucket_list()) {
                                // start node refresh -> send request about random key of every bucket to the closest nodes
                                Key random_key = generate_random_nodeID(bucket.get_start(), bucket.get_end());
                                for (auto& peer_node : routing_table.find_closest_nodes(random_key)) {
                                    socket_t peer_socketfd = init_connect_ssl(epollfd, peer_node.addr, peer_node.port, ConnectionType::P2P);
                                    tear_down_connection(epollfd, init_connect_ssl);
                                    // ssl init
                                    dht_map[peer_socketfd] = DHTInfo {
                                                        {NODE_LOOKUP_FOR_NETWORK_EXPANSION},
                                                        {DHT_RPC_FIND_NODE_REPLY},
                                                        dht_info.node_lookup
                                                    };
                                    dht_info.node_lookup->peer_request_finished[peer_socketfd] = false;
                                    forge_DHT_RPC_find_node(peer_socketfd, random_key);
                                }
                            }
                        }
                        // else:
                         /*
                        bool found_new_nodes = false;
                        new_k_closest_nodes = std::unordered_set<Node>{};

                        for (const auto& node : sorted_closest_nodes) {
                            if (!protocol_map[socketfd].node_lookup->previous_k_closest_nodes.contains(node)) {
                                found_new_nodes = true;
                            }
                            new_k_closest_nodes.insert(node);
                            if (new_k_closest_nodes.size() >= number_of_nodes) {
                                break;
                            }
                        }
                        protocol_map[socketfd].node_lookup->previous_k_closest_nodes = new_k_closest_nodes;
                        if (!found_new_nodes) {
                            break;
                        }
                    }
                    if (sorted_closest_nodes.size() > number_of_nodes) {
                        logInfo("Lookup completed. Found {} closest nodes. Resizing to {}", sorted_closest_nodes.size(), number_of_nodes);
                        sorted_closest_nodes.resize(number_of_nodes);
                    } else {
                        logInfo("Lookup completed. Found {} out of {} closest nodes that were looked for.", sorted_closest_nodes.size(), number_of_nodes);
                    }
                    */
                    // if we did not get any more closest nodes:
                    /*
                    switch(protocol_map[socketfd].node_lookup->reason) {
                        case NETWORK_EXPANSION:
                            // test if we gathered more nodes than last time, if yes, repeat process
                            // if no, say network expansion completed with x nodes and return.
                        case STORE:
                            // call forge_DHT_store to closest nodes
                        case: FIND_VALUE:
                            // call forge_DHT_find_value
                    }
                    */
                    }
                    else {}


                break;
            }
        break;

    }
    // send out request to all the nodes that are not us/former server on our device and that are valid

    // add to protocol_map[socketfd].node_lookup->returned_closest_nodes
    // add to protocol_map[socketfd].node_lookup->responded_socketfds.push_back(socketfd)

    // then, test whether all have responded yet, either here or in main by checking
    // protocol_map[socketfd].node_lookup->responded_socketfds.size() == protocol_map[socketfd].node_lookup->requested_socketfds.size()
    //



    return true;
}

bool forge_DHT_RPC_find_value(int epollfd, socket_t socketfd, Key &key) {
    Key rpc_id = generate_random_nodeID();
    dht_map.at(socketfd).rpc_id = rpc_id;

    size_t body_size = RPC_SUB_HEADER_SIZE + KEY_SIZE;
    size_t message_size = HEADER_SIZE + body_size;
    u_short message_type = DHT_RPC_STORE;
    Message message(message_size);

    build_DHT_header(message, message_size, message_type);
    build_RPC_header(message, rpc_id);

    write_body(message, RPC_SUB_HEADER_SIZE, key.data(), KEY_SIZE);

    logTrace("Sending DHT RPC find value");
    send_DHT_message(epollfd, socketfd, message);
    return true;
}

bool handle_DHT_RPC_find_value(const socket_t socketfd, const u_short body_size) {
    if (body_size != RPC_SUB_HEADER_SIZE + KEY_SIZE) {
        return false;
    }
    logInfo("Was asked to get value via find value request");
    const Message &message = connection_map.at(socketfd).receive_bytes;

    Key rpc_id = read_rpc_header(message, connection_map.at(socketfd).client_addr);
    Key key;
    read_body(message, RPC_SUB_HEADER_SIZE, key.data(), KEY_SIZE);

    auto val_ptr = get_from_storage(key);
    if (val_ptr) {
        return forge_DHT_RPC_find_value_reply(socketfd, main_epollfd, rpc_id, key, *val_ptr);
    } else {
        auto closest_nodes = routing_table.find_closest_nodes(key);
        return forge_DHT_RPC_find_node_reply(socketfd, main_epollfd, rpc_id, closest_nodes);
    }
}

bool forge_DHT_RPC_find_value_reply(int epollfd, socket_t socketfd, Key rpc_id, const Key &key, const Value &value) {
    u_short message_type = DHT_RPC_FIND_VALUE_REPLY;
    size_t body_size = RPC_SUB_HEADER_SIZE + KEY_SIZE + value.size();
    size_t message_size = HEADER_SIZE + body_size;
    Message message(message_size);

    build_DHT_header(message, message_size, message_type);
    build_RPC_header(message, rpc_id);

    write_body(message, RPC_SUB_HEADER_SIZE, key.data(), KEY_SIZE);
    write_body(message, RPC_SUB_HEADER_SIZE + KEY_SIZE, value.data(), value.size());

    logTrace("Sending DHT RPC find value reply");
    send_DHT_message(epollfd, socketfd, message);
    return true;
}

bool handle_DHT_RPC_find_value_reply(const socket_t socketfd, const u_short body_size) {
    // If we don't expect this on this socketfd, protocol_map[socketfd].node_lookup == nullptr -> return false
    if (body_size <= RPC_SUB_HEADER_SIZE + KEY_SIZE) {
        return false;
    }
    const u_short value_size = body_size - (RPC_SUB_HEADER_SIZE + KEY_SIZE);
    const Message& message = connection_map.at(socketfd).receive_bytes;

    if (!check_rpc_id(message, dht_map.at(socketfd).rpc_id)) {
        return false;
    }
    Key key;
    read_body(message, RPC_SUB_HEADER_SIZE, key.data(), KEY_SIZE);
    Value value{};
    value.resize(value_size);
    read_body(message, RPC_SUB_HEADER_SIZE + KEY_SIZE, value.data(), body_size - (RPC_SUB_HEADER_SIZE + KEY_SIZE));



    //-> gather in protocol_map[socketfd].value_lookup->returned_values etc
}

bool forge_DHT_error(int epollfd, socket_t socketfd, ErrorType error) {
    size_t message_size = HEADER_SIZE + 2;
    Message message(message_size);

    build_DHT_header(message, message_size, DHT_ERROR);
    u_short network_order_error = htons(error);
    write_body(message, 0, reinterpret_cast<unsigned char*>(&network_order_error), 2);

    logTrace("Sending DHT error");
    send_DHT_message(epollfd, socketfd, message);
    return true;
}


bool handle_DHT_error(const socket_t socketfd, const u_short body_size) {
    if (body_size != 2) {
        return false;
    }
    const Message &message = connection_map.at(socketfd).receive_bytes;

    u_short error_type = 0;
    read_body(message, 0, reinterpret_cast<unsigned char *>(error_type), 2);
    error_type = ntohs(error_type);
    const auto addr_string = ip_to_string(connection_map.at(socketfd).client_addr) +
                             ":" + std::to_string(connection_map.at(socketfd).client_port);
    switch (error_type) {
        case ErrorType::DHT_NOT_FOUND:
            logError("Received DHT_NOT_FOUND error by {}", addr_string);
        break;
        case ErrorType::DHT_BAD_REQUEST:
            logError("Sent out bad request to {}", addr_string);
        break;
        case ErrorType::DHT_SERVER_ERROR:
            logError("Had internal server error with {}", addr_string);
        break;
        default:
            logError("Got invalid server error by {}", addr_string);
    }
    return true;
}

// Message Parsing

bool parse_header(const ConnectionInfo &connection_info, u_short &message_size, u_short &dht_type){
    const Message &connection_buffer = connection_info.receive_bytes;
    if (connection_buffer.size() < HEADER_SIZE) {
        return false;
    }
    message_size = 0;
    dht_type = 0;

    message_size += connection_buffer[0];
    message_size <<= 8;
    message_size += connection_buffer[1];
    /*The message is expected to not even contain a key.
    All messages that adhere to protocol require a key sent.*/
    if(message_size < KEY_SIZE){
        return false;
    }

    dht_type += connection_buffer[2];
    dht_type <<= 8;
    dht_type += connection_buffer[3];
    /*The dht_type that was transmitted is not in the range of expected types*/
    if(!is_valid_DHT_type(dht_type)){
        return false;
    }
    return true;
}



bool parse_API_request(socket_t socketfd, const u_short body_size, const ModuleApiType module_api_type){
    switch (module_api_type){
        {
        case DHT_PUT:
            {
            handle_DHT_put(socketfd, body_size);
        break;
            }
        case DHT_GET:
            {
            handle_DHT_get(socketfd, body_size);
        break;
            }
        case DHT_SUCCESS:
            {
            handle_DHT_success(socketfd, body_size);
        break;
            }
        case DHT_FAILURE:
            {
            handle_DHT_failure(socketfd, body_size);
        break;
            }

        default:
            break;
        }
    }
    return true;
}

bool parse_P2P_request(int epollfd, socket_t socketfd, const u_short body_size, const P2PType p2p_type) { // returns wether socketfd should be closed
    try {
        switch (p2p_type) {
            case DHT_RPC_PING:
                return handle_DHT_RPC_ping(epollfd, socketfd, body_size);
            case DHT_RPC_STORE:
                return handle_DHT_RPC_store(socketfd, body_size);
            case DHT_RPC_FIND_NODE:
                return handle_DHT_RPC_find_node(socketfd, body_size);
            case DHT_RPC_FIND_VALUE:
                return handle_DHT_RPC_find_value(socketfd, body_size);
            case DHT_RPC_PING_REPLY:
                return handle_DHT_RPC_ping_reply(socketfd, body_size);
            case DHT_RPC_STORE_REPLY:
                return handle_DHT_RPC_store_reply(socketfd, body_size);
            case DHT_RPC_FIND_NODE_REPLY:
                return handle_DHT_RPC_find_node_reply(epollfd, socketfd, body_size);
            case DHT_RPC_FIND_VALUE_REPLY:
                return handle_DHT_RPC_find_value_reply(socketfd, body_size);
            case DHT_ERROR:
                return handle_DHT_error(socketfd, body_size);
        }
    } catch (std::exception& _) {
        forge_DHT_error(epollfd, socketfd, DHT_SERVER_ERROR);
        return true;
    }
    return true;
}

// Connection Processing

ProcessingStatus try_processing(int epollfd, socket_t curfd){
    //retreive information for element to process:
    ConnectionInfo &connection_info = connection_map.at(curfd);
    auto &connection_buffer = connection_info.receive_bytes;
    size_t byte_count_to_process = connection_buffer.size();
    if(connection_buffer.empty()){
        /* i.e.: we got work to process (epoll event happened), the message buffer
        is empty, but all bytes of the kernel buffer were exhausted (server side).*/
        return ProcessingStatus::ERROR;
    }
    if(connection_buffer.size() < HEADER_SIZE){
        return ProcessingStatus::WAIT_FOR_COMPLETE_MESSAGE_HEADER;
    }
        //Parse header:
        u_short message_size = -1;
        u_short dht_type = -1;

        bool header_success = parse_header(connection_info, message_size, dht_type);
        if (not header_success){
            return ProcessingStatus::ERROR;
        }

        //Header was successfully parsed. Check if entire message is present:
        if(byte_count_to_process < message_size){
            return ProcessingStatus::WAIT_FOR_COMPLETE_MESSAGE_BODY;
        }
        //Header was fully parsed and entire message is present. Do the "heavy lifting", parse received request semantically:

    bool valid_request;

    if (connection_info.connection_type == ConnectionType::MODULE_API) {
        ModuleApiType module_api_type;
        if (is_valid_module_API_type(dht_type)) {
            module_api_type = static_cast<ModuleApiType>(dht_type);
        } else {
            logWarn("Tried to send invalid request to Module API Server. Aborting.");
            return ProcessingStatus::ERROR;
        }

        valid_request = parse_API_request(curfd, message_size-HEADER_SIZE, module_api_type);
    } else if (connection_info.connection_type == ConnectionType::P2P) {
        P2PType p2p_type;
        if (is_valid_P2P_type(dht_type)) {
            p2p_type = static_cast<P2PType>(dht_type);
        } else {
            logWarn("Tried to send invalid request to P2P Server. Aborting.");
            return ProcessingStatus::ERROR;
        }
        valid_request = parse_P2P_request(epollfd, curfd, message_size-HEADER_SIZE, p2p_type);
        if (!valid_request) {
            forge_DHT_error(curfd, main_epollfd, DHT_BAD_REQUEST);
        }
    } else {
        logError("No ConnectionType registered for client. Aborting.");
        return ProcessingStatus::ERROR;
    }
    if (byte_count_to_process > message_size) {
        logTrace("Found more messages on connection_buffer");
        connection_buffer.erase(connection_buffer.begin(), connection_buffer.begin() + message_size);
        return MORE_TO_READ;
    }
    if (valid_request) {
        logTrace("Processed valid request");
        return ProcessingStatus::PROCESSED;
    } else {
        logError("Unknown Error with request.");
        return ProcessingStatus::ERROR;
    }
}


void accept_new_connection(int epollfd, const epoll_event &cur_event, ConnectionType connection_type) {
    sockaddr_in6 client_addr{};
    socklen_t client_addr_len = sizeof(client_addr);
    socket_t socketfd = accept4(cur_event.data.fd, reinterpret_cast<sockaddr*>(&client_addr), &client_addr_len, SOCK_NONBLOCK);
    if (socketfd == -1) {
        logError("Socket accept error: {}", strerror(errno));
        return;
    }

    ConnectionInfo connection_info{};
    u_short client_port = ntohs(client_addr.sin6_port);

    connection_info.connection_type = connection_type;
    connection_info.role = ConnectionRole::SERVER; //We are accepting, so we are server.
    connection_info.client_addr = client_addr.sin6_addr;
    connection_info.client_port = client_port;

    logDebug("Accepted socket connection from {}:{}", ip_to_string(client_addr.sin6_addr), client_port);

    if(connection_type == ConnectionType::P2P){

        logDebug("Setting up SSL for incoming client connection (we are server)");

        SSL* ssl = SSL_new(SSLConfig::server_ctx);
        connection_info.ssl = ssl;

        if(!ssl){
            logError("Failure Server: SSL object null pointer");
            return;
        }
        SSL_set_fd(ssl, socketfd);

        #ifdef SSL_VERBOSE
        SSLUtils::check_ssl_blocking_mode(ssl);
        #endif

        logDebug("Supplying length-prefixed Server-Certificate over insecure TCP channel");

        connection_info.ssl_stat = SSLStatus::HANDSHAKE_SERVER_WRITE_CERT;

        //Always write to internal buffer. Do not give up control by directly writing out socketfd.
        write_charptr_to_sendbuf(connection_info, SSLConfig::length_prefixed_cert_str, sizeof(uint32_t) + SSLConfig::cert_len);

        //Transmit certificate unencrypted/ unauthenticated. Plaintext.
        auto [is_socket_still_up, everything_was_sent] = flush_sendbuf(socketfd,connection_info,epollfd);
        if(!is_socket_still_up){
            //Connection got torn down due to error(s) on certificate transmission. Abort accepting.
            return;
        }
        if(everything_was_sent){
            connection_info.ssl_stat = SSLUtils::try_ssl_accept(ssl);
            if(connection_info.ssl_stat == SSLStatus::FATAL_ERROR_ACCEPT_CONNECT){
                logError("Fatal error occured on SSL accept. TCP connection was closed.");
                SSL_free(ssl);
                close(socketfd);
                return;
            }
        }
    }

    //SSL accept was either successful or is pending (aka. we need to give the client more time).
    //Pending means, the client needs to read/write more data from/to our socket.
    //Proceed normally, but before transmitting future data, check for ssl status.
    auto epollEvent = epoll_event{};
    epollEvent.events = EPOLLIN | EPOLLOUT | EPOLLERR;
    epollEvent.data.fd = socketfd;
    epoll_ctl(epollfd, EPOLL_CTL_ADD, socketfd, &epollEvent);
    connection_map.insert_or_assign(socketfd, connection_info);
}

//Do heavy lifting certificate storage logic
CertificateStatus receive_certificate_as_client(int epollfd, socket_t peer_socketfd, ConnectionInfo &connection_info_emplaced){
    if(connection_info_emplaced.role != ConnectionRole::CLIENT){
        logDebug("received_certificate_as_client: Tried to receive certificate as SERVER. Tearing down connection");
        tear_down_connection(epollfd,peer_socketfd);
        return CertificateStatus::ERRORED_CERTIFICATE;
    }
    unsigned char * foreign_cert_str = nullptr;
    uint32_t cert_len{0};
    bool socket_still_alive = receive_prefixed_sendbuf_in_charptr(epollfd, peer_socketfd, connection_info_emplaced, foreign_cert_str, cert_len);

    if(!foreign_cert_str && socket_still_alive){
        return CertificateStatus::CERTIFICATE_NOT_FULLY_PRESENT;
    }

    if(!socket_still_alive){
        free(foreign_cert_str);
        return CertificateStatus::ERRORED_CERTIFICATE;
    }


    X509 * foreign_certificate = SSLUtils::load_cert_from_char(foreign_cert_str,cert_len);
    free(foreign_cert_str);


    //Save foreign cert str
    unsigned char received_id[KEY_SIZE];
    if(!SSLUtils::extract_custom_id(foreign_certificate,received_id)){
        logError("received_certificate_as_client: Failed to extract IPv6 from certificate.");
        return CertificateStatus::ERRORED_CERTIFICATE;
    }


    std::string hex_id = Utils::bin_to_hex(received_id, KEY_SIZE);
    logDebug("received_certificate_as_client: Hex ID received in certificate is: {}", hex_id);

    std::string ipv6_str{};
    if(!SSLUtils::extract_ipv6_from_cert(foreign_certificate,ipv6_str)){
        logError("received_certificate_as_client: Failed to extract IPv6 from certificate.");
        return CertificateStatus::ERRORED_CERTIFICATE;
    }
    if (SSLConfig::cert_map.contains(hex_id)) {
        logInfo("received_certificate_as_client: Kademlia ID already recognized.");
        //Compare certificates
        if(SSLUtils::compare_x509_cert_with_pem(foreign_certificate, SSLConfig::cert_map.find(hex_id)->second.second)){
            //Compare yielded equality:
            return CertificateStatus::EXPECTED_CERTIFICATE;
        }
        //Compare yielded difference. --> RPC_Ping old connection partner
        //TODO: Maybe leave out because of time reasons. For now, assume that peer is not reachable
        return CertificateStatus::KNOWN_CERTIFICATE_CONTENT_MISMATCH;
    }

    logInfo("received_certificate_as_client: The certificate is new or the predecessor of the kademlia was unreachable with our saved certificate");

    // Else, meaning the certificate is new or the predecessor of the kademlia was unreachable with our saved certificate:
    // Add the new certificate to the map
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(bio, foreign_certificate);
    int cert_len_to_save = BIO_pending(bio);
    char* cert_pem = (char*)malloc(cert_len_to_save + 1);
    BIO_read(bio, cert_pem, cert_len_to_save);
    cert_pem[cert_len_to_save] = '\0';
    BIO_free(bio);

    SSLConfig::cert_map[hex_id] = std::pair{htons(connection_info_emplaced.client_port),std::string(cert_pem)};
    free(cert_pem);

    if (X509_STORE_add_cert(SSLConfig::client_cert_store, foreign_certificate) != 1) {
        logError("Failed to add certificate to trusted store.");

        SSLConfig::cert_map.erase(hex_id);
        return CertificateStatus::ERRORED_CERTIFICATE;
    }
    logInfo("received_certificate_as_client: Found new valid certificate; Returning.");
    PEM_write_X509(stdout,foreign_certificate);
    return CertificateStatus::NEW_VALID_CERTIFICATE;
}


//Return value bool: socket_still_up
bool handle_custom_ssl_protocol(int epollfd, socket_t socketfd, ConnectionInfo &connection_info){
    if(connection_info.role == ConnectionRole::SERVER){
        logTrace("handle_custom_ssl_protocol: SERVER entered.---------------------------");
        auto [is_socket_still_up, everything_was_sent] = std::make_tuple(true, false);
        switch (connection_info.ssl_stat)
        {
            //Server still needs to finish SSL handshake for the next few cases:

            case SSLStatus::HANDSHAKE_SERVER_WRITE_CERT:
                //length prefixed ssl certificate is buffered since accept_new_connection. Simply flush it
                std::tie(is_socket_still_up, everything_was_sent) = flush_sendbuf(socketfd,connection_info,epollfd);
                if(!is_socket_still_up){
                    //Connection got torn down due to error(s) on certificate transmission. Abort accepting.
                    logTrace("handle_custom_ssl_protocol: left due to error(s) on certificate transmission. ---------------------------");
                    return false;
                }
                if(everything_was_sent){
                    connection_info.ssl_stat = SSLUtils::try_ssl_accept(connection_info.ssl);
                    if(connection_info.ssl_stat == SSLStatus::FATAL_ERROR_ACCEPT_CONNECT){
                        tear_down_connection(epollfd,socketfd);
                        logTrace("handle_custom_ssl_protocol: left because try_ssl_accept returned fatal error. ---------------------------");
                        return false;
                    }
                    //We retried ssl_accept, but this time we guaranteed progressed ssl_stat to at least AWAITING_ACCEPT
                    logTrace("handle_custom_ssl_protocol: left. We retried ssl_accept ---------------------------");
                    return true;
                }
                logTrace("handle_custom_ssl_protocol: left. Socket is still up but not everything was sent ---------------------------");
                return true;
            case SSLStatus::PENDING_ACCEPT_READ:
            case SSLStatus::PENDING_ACCEPT_WRITE:
                connection_info.ssl_stat = SSLUtils::try_ssl_accept(connection_info.ssl);
                logTrace("handle_custom_ssl_protocol: left after try_ssl_accept. ---------------------------");
                return true;
            case SSLStatus::FATAL_ERROR_ACCEPT_CONNECT:
                tear_down_connection(epollfd,socketfd);
                logTrace("handle_custom_ssl_protocol: left because try_ssl_accept returned fatal error.. ---------------------------");
                return false;

            //Server as already finished handshake (SSLStatus::ACCEPTED)->
            default:
                break;
        }
        //If we exit out of the switch (i.e. without returning), our event occured on a perfectly fine SSL-using connection.
        //Skip after the next large else case to proceed with normal socketfd input handeling. :)
    }
    else{
        logTrace("handle_custom_ssl_protocol: CLIENT entered.---------------------------");
        bool is_socket_still_up{};
        CertificateStatus cs{};
        switch (connection_info.ssl_stat)
        {
            //Client still needs to finish SSL handshake for the next few cases

            case SSLStatus::HANDSHAKE_CLIENT_READ_CERT:
                //length prefixed ssl certificate is buffered on serverside since accept_new_connection. Simply read flush it
                is_socket_still_up = flush_recvbuf(socketfd,connection_info,epollfd);
                if(!is_socket_still_up){
                    //Connection got torn down due to error(s) on certificate reception. Abort connecting.
                    logTrace("handle_custom_ssl_protocol: left. Connection got torn down due to error(s) on certificate reception---------------------------");
                    return false;
                }
                cs = receive_certificate_as_client(epollfd,socketfd,connection_info);
                //Perform heavy lifting (certificate validation, persistent storage)
                if(cs == CertificateStatus::NEW_VALID_CERTIFICATE || cs == CertificateStatus::EXPECTED_CERTIFICATE){
                    connection_info.ssl_stat = SSLUtils::try_ssl_connect(connection_info.ssl);
                    logTrace("handle_custom_ssl_protocol: left. NEW_VALID_CERTIFICATE || EXPECTED_CERTIFICATE -> {}---------------------------", connection_info.ssl_stat);
                    return true;
                }
                if(cs == CertificateStatus::ERRORED_CERTIFICATE || cs == CertificateStatus::KNOWN_CERTIFICATE_CONTENT_MISMATCH){
                    tear_down_connection(epollfd,socketfd);
                    logTrace("handle_custom_ssl_protocol: left. ERRORED_CERTIFICATE || KNOWN_CERTIFICATE_CONTENT_MISMATCH---------------------------");
                    return false;
                }
                //Certificate is not fully present yet. Return true, try again later.
            logTrace("handle_custom_ssl_protocol: left. Certificate is not fully present yet. Return true, try again later---------------------------");
                return true;
            case SSLStatus::PENDING_CONNECT_READ:
            case SSLStatus::PENDING_CONNECT_WRITE:
                connection_info.ssl_stat = SSLUtils::try_ssl_connect(connection_info.ssl);
                logTrace("handle_custom_ssl_protocol: left. Tried to ssl_connect again---------------------------");
                return true;
            case SSLStatus::FATAL_ERROR_ACCEPT_CONNECT:
                tear_down_connection(epollfd,socketfd);
                logTrace("handle_custom_ssl_protocol: left. FATAL_ERROR_ACCEPT_CONNECT---------------------------");
                return false;
            //Client as already finished handshake (SSLStatus::CONNECTED)->
            default:
                break;
        }
    }
    //TODO: THIS COULD BE GAMECHANGING
    /*
    if(connection_info.ssl_stat > 0 )
    {
        epoll_event eevent{};
        eevent.data.fd = socketfd;
        eevent.events = EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLET;
        epoll_ctl(epollfd,EPOLL_CTL_MOD,socketfd, &eevent);
    }
    */
    logTrace("handle_custom_ssl_protocol: left. ---------------------------");
    return true; //valid ssl connection
}




bool handle_EPOLLOUT(int epollfd, const epoll_event &current_event){
    //Check connection type
    //TODO: currently for debugging
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    socket_t socketfd = current_event.data.fd;
    if (!connection_map.contains(socketfd)) {
        tear_down_connection(main_epollfd, socketfd);
        logError("handle_EPOLLOUT: Notifying socket not in connection map. This should never happen. Tore down connection");
        return false;
    }


    ConnectionInfo &connection_info = connection_map.at(socketfd);

    if(connection_info.connection_type == ConnectionType::MODULE_API){
        flush_sendbuf(socketfd,connection_info,epollfd);
        return true; //Return early to distinguish from following ConnectionType::P2P
    }

    if(!handle_custom_ssl_protocol(epollfd,socketfd,connection_info)){
        logError("handle_EPOLLOUT: handle_custom_ssl_protocol return invalid socket, so tore down connection.");
        return false;
    }
    logTrace("handle_EPOLLOUT: handle_custom_ssl_protocol has possibly advanced our SSL state to: {}",connection_info.ssl_stat);

    //flush send_buffer.
    auto [socket_still_up, was_everything_sent ]  = flush_sendbuf(socketfd,connection_info,epollfd);
    if (was_everything_sent) {
        logTrace("The sendbuffer buffer is empty and there's nothing to send anymore.");
    }
    return socket_still_up;
}

bool read_EPOLLIN(int epollfd, const epoll_event& current_event){
    socket_t socketfd = current_event.data.fd;
    if (!connection_map.contains(socketfd)) {
        //Should never happen.
        logTrace("Connection map didn't contain socket anymore");
        tear_down_connection(main_epollfd, socketfd);
        return false;
    }
    ConnectionInfo &connection_info = connection_map.at(socketfd);

    if(connection_info.connection_type == ConnectionType::MODULE_API){
        flush_recvbuf(socketfd,connection_info,epollfd);
        return true; //Return early to distinguish from following ConnectionType::P2P
    }

    if(!handle_custom_ssl_protocol(epollfd,socketfd,connection_info)){
        return false; //Socket was torn down by us.
    }
    logTrace("read_EPOLLIN: handle_custom_ssl_protocol has possibly advanced our SSL state to: {}",connection_info.ssl_stat);

    return flush_recvbuf(socketfd, connection_info, epollfd);
}

bool handle_EPOLLIN(int epollfd, const epoll_event& current_event) { // returns whether the socketfd is still valid and should be kept open
    socket_t socketfd = current_event.data.fd;
    if (!read_EPOLLIN(epollfd, current_event)) {
        logDebug("read_EPOLLIN returned a socket referring to a torn down connection.");
        return false;
    }
    if (recv_buffer_empty(connection_map.at(socketfd))) {
        logTrace("handle_EPOLLIN was called with an empty receive-buffer. This is expected during SSL_accept/connect");
        logTrace("handle_EPOLLIN returned normally");
        return true;
    }
    logDebug("handle_EPOLLIN: interpreted remaining bytes on receivebuf as user data (aka. actual request(s))");
    //Requests can even be multiple, lying conecutively in our recvbuf. The following do while loop tries to process all
    //requests that are fully present (all except for possibly the last, incomplete request)
    ProcessingStatus processing_status;
    do {
        processing_status = try_processing(epollfd, socketfd);
    } while (processing_status == MORE_TO_READ);
    logDebug("handle_EPOLLIN: try_processing of DHT requests finished, possibly multiple requests were processed.");
    if (processing_status == ProcessingStatus::ERROR) {
        tear_down_connection(epollfd, socketfd);
        logDebug("handle_EPOLLIN: Error occured during try_processing of DHT requests. Tore down connection.");
        return false;
    }
    logTrace("handle_EPOLLIN returned normally");
    return true;
}


std::unordered_set<Node> perform_maintenance() {
    int epollfd = epoll_create1(0);
    if (epollfd == -1) {
        logError("Error creating epollfd. Aborting maintenance.");
        return {};
    }
    logInfo("Performing maintenance...");
    epoll_event epollEvent;
    std::unordered_set<Node> stale_nodes;
    int expected_answers = 0;
    auto pinged_socketfds_map = std::unordered_map<socket_t, Node>{};
    for (auto& bucket : routing_table.get_bucket_list()) {
        for (auto& node : bucket.get_peers()) {
            socket_t peer_socketfd = setup_connect_socket(epollfd, node.addr, node.port, ConnectionType::P2P);
            if (peer_socketfd != -1) {
                if (!ensure_tls_blocking(peer_socketfd)) {
                    logTrace("perform_maintenance: Couldn't build TLS. Tearing down connection.");
                    tear_down_connection(epollfd, peer_socketfd);
                    stale_nodes.insert(node);
                    continue;
                }
                epollEvent = epoll_event{};
                epollEvent.events = EPOLLIN;
                epollEvent.data.fd = peer_socketfd;
                if (epoll_ctl(epollfd, EPOLL_CTL_ADD, peer_socketfd, &epollEvent) == -1) {
                    stale_nodes.insert(node);
                    continue;
                };
                forge_DHT_RPC_ping(peer_socketfd, epollfd);
                logTrace("Sent ping to {}:{}", ip_to_string(node.addr), node.port);
                auto [is_socket_still_up ,everything_was_sent] = flush_sendbuf(peer_socketfd, connection_map.at(peer_socketfd), epollfd);
                if (is_socket_still_up && everything_was_sent) {
                    pinged_socketfds_map[peer_socketfd] = node;
                    expected_answers++;
                } else {
                    stale_nodes.insert(node);
                }
            } else {
                stale_nodes.insert(node);
            }
        }
    }

    logTrace("perform_maintenance: Sent pings, now waiting on answers...");

    std::unordered_set<socket_t> successfully_pinged_socketfds{};
    auto handle_answer = [&](socket_t sockfd, u_short body_size) {
        return handle_DHT_RPC_ping_reply(sockfd, body_size, &successfully_pinged_socketfds);
    };
    //int received_answers = process_answers_on_epollin(epollfd, P2PType::DHT_RPC_PING_REPLY, handle_answer, expected_answers);


    for (auto& [sockfd, node] : pinged_socketfds_map) {
        if (!successfully_pinged_socketfds.contains(sockfd)) {
            stale_nodes.insert(node);
        }
    }
    logInfo("Finished maintenance and found {}/{} stale nodes. Removed them.", stale_nodes.size(), routing_table.count());
    for (auto& stale_node : stale_nodes) {
        routing_table.remove(stale_node);
    }
    return stale_nodes;
}


// Network/Socket functions

int add_to_epoll(int epollfd, socket_t serversocketfd) {
    epoll_event epollEvent = epoll_event{};
    epollEvent.events = EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLET;
    epollEvent.data.fd = serversocketfd;
    return epoll_ctl(epollfd, EPOLL_CTL_ADD, serversocketfd, &epollEvent);
}

socket_t setup_server_socket(u_short port) {
    static constexpr int ONE = 1;

    socket_t serversocketfd = socket(AF_INET6, SOCK_STREAM, 0);
    if (serversocketfd < 0) {
        logError("Socket creation failed.");
        return -1;
    }

    // Setting SO_REUSEADDR to avoid issues with TIME_WAIT
    setsockopt(serversocketfd, SOL_SOCKET, SO_REUSEADDR, &ONE, sizeof(ONE));
    setsockopt(serversocketfd, SOL_SOCKET, SO_KEEPALIVE, &ONE, sizeof(ONE));

    sockaddr_in6 sock_addr{};
    sock_addr.sin6_family = AF_INET6;
    sock_addr.sin6_port = htons(port);
    sock_addr.sin6_addr = in6addr_any;

    if (bind(serversocketfd, reinterpret_cast<sockaddr *>(&sock_addr), sizeof(sock_addr)) < 0) {
        logError("Failed to bind port {}. Error: {}", port, strerror(errno));
        close(serversocketfd);
        return -1;
    }

    if (listen(serversocketfd, 128) != 0) {
        logError("Failed to listen on port {}. Error: {}", port, strerror(errno));
        close(serversocketfd);
        return -1;
    }

    logInfo("Listening on port {}", port);
    return serversocketfd;
}

socket_t setup_connect_socket(int epollfd, const in6_addr& address, u_int16_t port, const ConnectionType connection_type) {
    socket_t peer_socketfd = socket(AF_INET6, SOCK_STREAM, 0);
    if (peer_socketfd == -1) {
        logError("setup_connect_socket: Failed to create client socket on port {}.",port);
        return -1;
    }

    sockaddr_in6 addr{};
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(port);
    addr.sin6_addr = address;

    static constexpr int ONE = 1;
    setsockopt(peer_socketfd, SOL_SOCKET, SO_KEEPALIVE, &ONE, sizeof(ONE));

    ConnectionInfo connection_info{};
    connection_info.connection_type = connection_type;
    connection_info.role = ConnectionRole::CLIENT;
    connection_info.client_addr = address;
    connection_info.client_port = port;

    //TODO: Maybe unfortunate, does only init the 3-way handshake, peer could not have accepted yet.
    logTrace("setup_connect_socket: connect() call...", port);
    if (connect(peer_socketfd, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) == -1) {
        logError("setup_connect_socket: Failed to connect() to peer at {}:{}: {}", ip_to_string(address), port, strerror(errno));
        close(peer_socketfd);
        return -1;
    }

    //Implement connect state, if errno is EAGAIN, retry connect()
    logTrace("setup_connect_socket: connect()ed socket to {}:{}",ip_to_string(connection_info.client_addr),connection_info.client_port);

    set_socket_blocking(peer_socketfd, false);

    connection_map[peer_socketfd] = connection_info;
    auto &connection_info_emplaced = connection_map.at(peer_socketfd);
    logTrace("setup_connect_socket: added newly connected peer to global connection_map.");

    //Inject SSL-Code:
    if(connection_type == ConnectionType::P2P){
        logDebug("setup_connect_socket: Setting up SSL for outgoing client connection (we are client)");

        SSL* ssl = SSL_new(SSLConfig::client_ctx);
        connection_info_emplaced.ssl = ssl;
        connection_info_emplaced.ssl_stat = SSLStatus::HANDSHAKE_CLIENT_READ_CERT;
        logTrace("setup_connect_socket: Client SSLStatus of connection has been initialized with HANDSHAKE_CLIENT_READ_CERT");
        if(!ssl){
            tear_down_connection(epollfd,peer_socketfd);
            logError("setup_connect_socket: Failure, SSL object is null pointer. Tore down connection and aborted connect()");
            return -1;
        }
        SSL_set_fd(ssl, peer_socketfd);

        logTrace("setup_connect_socket: SSL object's blocking mode is: {}", SSLUtils::check_ssl_blocking_mode_to_string(ssl));

        logDebug("setup_connect_socket: Receiving length-prefixed Server-Certificate over insecure TCP channel");

        // Do heavy lifting certificate storage logic
        CertificateStatus cert_stat =  receive_certificate_as_client(epollfd, peer_socketfd, connection_info_emplaced);
        if(cert_stat == CertificateStatus::ERRORED_CERTIFICATE || cert_stat == CertificateStatus::KNOWN_CERTIFICATE_CONTENT_MISMATCH){
            //Abort the connection. Could be a malicious Peer! Abort, abort!
            tear_down_connection(epollfd,peer_socketfd);
            logWarn("setup_connect_socket: Receiving certificate from server was faulty, e.g. syntactically/ corrupted OR attemt to spoof Identity of well-known peer");
            return -1;
        }
        if(cert_stat == CertificateStatus::CERTIFICATE_NOT_FULLY_PRESENT){
            logTrace("setup_connect_socket: Received certificate is not fully present yet. Wait for more bytes.");
            return peer_socketfd; //fd is valid, but wait for more bytes.
        }
        logTrace("setup_connect_socket: Received certificate is in a valid state. Now, try_ssl_connect()");
        //Else: cert_stat is either NEW_VALID_CERTIFICATE  or EXPECTED_CERTIFICATE, continue with protocol.
        //New certificate saved or recognized previously trusted certificate.
        //Advance to at least SSLStatus::AWAITING_ACCEPT :)

        connection_info_emplaced.ssl_stat = SSLUtils::try_ssl_connect(ssl);
        if (connection_info_emplaced.ssl_stat == SSLStatus::FATAL_ERROR_ACCEPT_CONNECT) {
            tear_down_connection(epollfd,peer_socketfd);
            logError("setup_connect_socket: try_ssl_connect() failed fatally, tore down the connection");
            return -1;
        }
        logTrace("setup_connect_socket: SSL State transitioned to at least SSLStatus::AWAITING_CONNECT, SSLStatus value is {}",connection_info_emplaced.ssl_stat);
    }
    return peer_socketfd;
}

//SSL functions:
void prepare_SSL_Config(/*in_port_t host_p2p_port*/){

    SSLConfig::id = routing_table.get_local_node().id;

    /*
    //Create certificate map file. File name is "cert_map_s_<P2PPort>.txt".
    //This way, no race condition to file names, as the ports are unique.
    std::string port_string = std::to_string(host_p2p_port);
    SSLConfig::certmap_filename = "cert_map_s_" + port_string + ".txt";
    SSLConfig::cert_map = CertUtils::load_certificate_map(SSLConfig::certmap_filename);*/

    //1. Init SSL library
    SSL_library_init();
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();


    //Generate Key-pair for signing certificates and DHKE
    SSLConfig::pkey = KeyUtils::generate_rsa_key();
    if (!SSLConfig::pkey) {
        logError("Failed to generate RSA key pair");
        exit(EXIT_FAILURE);
    }

    logInfo("Generated Kademlia Node ID: {}", Utils::to_hex_string(SSLConfig::id.data(), 32));

    //Retrieve own IPv6 ip to include in certificate:

    if(!NetworkUtils::getIPv6(SSLConfig::ipv6_buf,sizeof(SSLConfig::ipv6_buf))){
        logError("Failed to retrieve own IPv6 address");
        EVP_PKEY_free(SSLConfig::pkey);
        exit(EXIT_FAILURE);
    }

    //Generate self-signed certificate

    SSLConfig::cert = CertUtils::create_self_signed_cert(SSLConfig::pkey, SSLConfig::ipv6_buf, std::string(SSLConfig::id.begin(), SSLConfig::id.end()));
    if(!SSLConfig::cert){
        logError("Failed to generate self-signed X509 certificate");
        EVP_PKEY_free(SSLConfig::pkey);
        exit(EXIT_FAILURE);
    }
    PEM_write_X509(stdout,SSLConfig::cert);

    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(bio, SSLConfig::cert);
    int cert_len = BIO_pending(bio);
    SSLConfig::cert_len = cert_len;
    uint32_t net_length = htonl(cert_len);  // Convert length to network byte order

    //Allocate [<lengthprefix><certificate>] bytes.    [ ] <-- describes the extent of malloc.
    SSLConfig::length_prefixed_cert_str = (unsigned char*)malloc(sizeof(net_length) + SSLConfig::cert_len);

    //Save the <lengthprefix>
    std::memcpy(SSLConfig::length_prefixed_cert_str, &net_length, sizeof(net_length));

    //Save the <certificate> after the <lengthprefix>
    BIO_read(bio, SSLConfig::length_prefixed_cert_str + sizeof(net_length), SSLConfig::cert_len);
    BIO_free(bio);

    /*TODO: @Marius, still necessary to save everything persistently? We could also just keep them in variables
     * (as done currently). Saving to file only serves redundancy (e.g. post-crash/-exit private key recovery).
    */

    // Save the private key and certificate to files
    /*
    KeyUtils::save_private_key(SSLConfig::pkey, "private_key_" + port_string + ".pem");
    KeyUtils::save_public_key(SSLConfig::pkey, "public_key_" + port_string + ".pem"); //Optional, could be derived
    CertUtils::save_certificate(SSLConfig::cert, "certificate_" + port_string + ".pem");
    */

    //Setup SSL context (globally)
    SSLConfig::server_ctx = SSLUtils::create_context(true);
    SSL_CTX_use_certificate(SSLConfig::server_ctx, SSLConfig::cert);
    SSL_CTX_use_PrivateKey(SSLConfig::server_ctx, SSLConfig::pkey);

    SSLConfig::client_ctx = SSLUtils::create_context(false);
    SSLConfig::client_cert_store = SSL_CTX_get_cert_store(SSLConfig::client_ctx);

}

void clean_up_SSL_Config(){
    //Ordered clean up according to namespace SSLConfig.
    EVP_PKEY_free(SSLConfig::pkey);
    X509_free(SSLConfig::cert);
    free(SSLConfig::length_prefixed_cert_str);
    SSL_CTX_free(SSLConfig::server_ctx);
    SSL_CTX_free(SSLConfig::client_ctx);

}

//TODO: Test if purger stop works.
void sig_c_handler(int signal){
    if(signal == SIGINT || signal == SIGTERM){
        if(purger.joinable())
        {
            logDebug("sig_c_handler: Purger needs to be joined... initiating cv notify_all");
            {
                std::lock_guard<std::mutex> lk(stop_purger_cv_mutex);
                stop_purger = true;
                stop_purger_cv.notify_all();
            }
            purger.join();
            logDebug("sig_c_handler: Purger joined.");
        }
        clean_up_SSL_Config();
        logDebug("sig_c_handler: Cleaned up ssl config");
        logInfo("sig_c_handler: Cleaned up ssl config");
        exit(0);
    }
}

socket_t set_socket_blocking(socket_t peer_socketfd, bool blocking) {
    int flags = fcntl(peer_socketfd, F_GETFL, 0);
    if (flags == -1) return -1;
    if (blocking) {
        flags &= ~O_NONBLOCK;
    } else {
        flags |= O_NONBLOCK;
    }
    if (fcntl(peer_socketfd, F_SETFL, flags) == -1) return -1;
    return peer_socketfd;
}

void force_close_socket(int sockfd) {
    struct linger linger_option = {1, 0};  // Enable SO_LINGER with a timeout of 0
    if (setsockopt(sockfd, SOL_SOCKET, SO_LINGER, &linger_option, sizeof(linger_option)) < 0) {
        logError("setsockopt(SO_LINGER) failed");
        return;
    }

    if (close(sockfd) < 0) {
        logError("close failed");
        return;
    } else {
        logDebug("Socket forcefully closed.");
        return;
    }
}

template<typename Function, typename... Args>
bool run_with_timeout(Function&& func, std::chrono::seconds timeout, Args&&... args) {
    std::condition_variable cv;
    std::mutex mtx;
    bool done = false;

    std::thread task_thread([&]() {
        std::forward<Function>(func)(std::forward<Args>(args)...);

        {
            std::lock_guard<std::mutex> lock(mtx);
            done = true;
        }
        cv.notify_one();
    });

    std::unique_lock<std::mutex> lock(mtx);
    if (cv.wait_for(lock, timeout, [&]() { return done; })) {
        task_thread.join();
        return true;
    } else {
        task_thread.detach();
        return false;
    }
}

bool ensure_tls_blocking(socket_t peer_socketfd, int timeout_ms) { // only to be used as client
    logTrace("setup_tls_blocking: called setup_tls_blocking with local peer filedescriptor {}", peer_socketfd);
    set_socket_blocking(peer_socketfd, false);


    std::vector<epoll_event> epoll_events{1}; //Is only the peer we want to join to
    auto start_time = std::chrono::steady_clock::now();
    if (!connection_map.contains(peer_socketfd)) {
        return false;
    }

    int epollfd = epoll_create1(0);
    //add_epoll(epollfd, peer_socketfd, EPOLLIN | EPOLLOUT);

    auto& connection_info = connection_map.at(peer_socketfd);
    int active_polling_rate_ms = 10;
    int max_tries = timeout_ms / active_polling_rate_ms;
    int current_tries = 0;
    while (true) { // event count never 0 because epollout.
        switch(connection_info.ssl_stat) {

            case CONNECTED:
                logDebug("setup_tls_blocking: Setup TLS Connection established.");
                logTrace("setup_tls_blocking: returning successfully.");
            return true;
            case PENDING_CONNECT_READ:
                //epollfd = mod_epoll(epollfd, peer_socketfd, EPOLLIN);
            break;
            case PENDING_CONNECT_WRITE:
                //epollfd = mod_epoll(epollfd, peer_socketfd, EPOLLOUT);
            break;
            case HANDSHAKE_CLIENT_READ_CERT:
            break;
            case FATAL_ERROR_ACCEPT_CONNECT:
                logTrace("Fatal error on TLS Connection ACCEPT/CONNECT");
                tear_down_connection(epollfd, peer_socketfd);
                return false;
            default:
                return false;

        }

        int event_count = epoll_wait(epollfd, epoll_events.data(), std::ssize(epoll_events), timeout_ms);  // dangerous cast
        logTrace("ensure_tls_blocking: new epoll event. Current SSL state: {}", connection_info.ssl_stat);
        if (event_count == -1) {
            if (errno == EINTR) { // for debugging purposes
                continue;
            }
            //TODO: @Marius event_count == 0?
            logError("Couldn't build TLS tunnel: {}", strerror(errno));
            return false;
        }

        if(event_count == 0)
        {
            //TODO
        }


        if (current_tries > max_tries) { //TODO: MAYBE USE FOR INSTEAD OF WHILE TRUE
            logTrace("ensure_tls_blocking: Had more tries than max_tries so returned. Tearing down connection.");
            return false;
        }

        if (!handle_custom_ssl_protocol(epollfd, peer_socketfd, connection_info) ) {
            logTrace("ensure_tls_blocking: handle_custom_ssl_protocol returned false.");
            return false;
        }

        logTrace("ensure_tls_blocking: handle_custom_ssl_protocol has possibly advanced our SSL state to: {}",connection_info.ssl_stat);

        if (connection_info.ssl_stat == CONNECTED || connection_info.ssl_stat == ACCEPTED) {
            logDebug("setup_tls_blocking: Setup TLS Connection established.");
            logTrace("setup_tls_blocking: returning successfully.");
            return true;
        }
        current_tries++;
        std::this_thread::sleep_for(std::chrono::milliseconds(active_polling_rate_ms));
    }
}

bool connect_to_network(int epollfd, struct in6_addr peer_address, u_short peer_port) {
    logTrace("connect_to_network: Entered. Peer to connect to is {}:{}", ip_to_string(peer_address), peer_port);

    socket_t peer_socketfd = init_connect_ssl(peer_address, peer_port);

    if (peer_socketfd == -1) {
        return false;
    }
    if (add_to_epoll(epollfd, peer_socketfd) == -1) {
        return false;
    }

    connection_map[peer_socketfd] = {ConnectionType::P2P};

    NodeLookup node_lookup {
        {NodeLookupStatus::AWAITING_FIRST_REPLY}
    };

    dht_map[peer_socketfd] = DHTInfo {
        {OperationType::NODE_LOOKUP_FOR_NETWORK_EXPANSION},
        {P2PType::DHT_RPC_FIND_VALUE_REPLY},
        &node_lookup
    };

    forge_DHT_RPC_find_node(peer_socketfd, routing_table.get_local_node().id);
    return true;
}

std::optional<std::shared_ptr<spdlog::logger>> setup_Logger(spdlog::level::level_enum loglevel)
{

    try
    {
        std::filesystem::create_directories("logs");

        auto stdout_logger = spdlog::stdout_color_mt("dht_server");
        spdlog::set_default_logger(stdout_logger);
        spdlog::set_level(loglevel);

        spdlog::debug("Logger initialized successfully.");
        //"Trace" is the most verbose (Includes all logging statements, floods logging)
        //"Critical" is the least verbose (basically always logged, rare output)
        return stdout_logger;
    }catch(const spdlog::spdlog_ex &ex)
    {
        std::cerr << "Logger initialization failed: " << ex.what() << std::endl;
        return std::nullopt;
    }
}

//New functions for server-sided state machine progress (automaton logic)

//TCP Handshake only, returns socket and ConenctionInfo filled with metadata.
std::pair<socket_t,ConnectionInfo&> accept_connection(const epoll_event &current_event, ConnectionType connection_type)
{
    sockaddr_in6 client_addr{};
    socklen_t client_addr_len = sizeof(client_addr);
    ConnectionInfo connection_info{};

    socket_t socketfd = accept4(current_event.data.fd, reinterpret_cast<sockaddr*>(&client_addr),
                                &client_addr_len, SOCK_NONBLOCK);
    //TODO: Debug if this works:
    if(socketfd == -1){
        if(errno == EAGAIN || errno == EWOULDBLOCK){
            return {socketfd,connection_info};
        }
    }

    u_short client_port = ntohs(client_addr.sin6_port);
    connection_info.connection_type = connection_type;
    connection_info.role = ConnectionRole::SERVER; //We are accepting, so we are server.
    connection_info.client_addr = client_addr.sin6_addr;
    connection_info.client_port = client_port;

    logDebug("Accepted socket connection from {}:{}", ip_to_string(client_addr.sin6_addr), client_port);

    return {socketfd, connection_info};
}


std::pair<socket_t,ConnectionInfo&> connect_connection(const in6_addr& address, u_int16_t port, const ConnectionType connection_type)
{
    ConnectionInfo connection_info{};
    socket_t peer_socketfd = socket(AF_INET6, SOCK_STREAM | O_NONBLOCK, 0);
    if (peer_socketfd == -1) {
        logError("connect_connection: Failed to create client socket on port {}.",port);
        return {-1,connection_info};
    }

    sockaddr_in6 addr{};
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(port);
    addr.sin6_addr = address;

    static constexpr int ONE = 1;
    setsockopt(peer_socketfd, SOL_SOCKET, SO_KEEPALIVE, &ONE, sizeof(ONE));

    connection_info.connection_type = connection_type;
    connection_info.role = ConnectionRole::CLIENT;
    connection_info.client_addr = address;
    connection_info.client_port = port;
    connection_info.ssl_stat = TCP_PENDING;

    logTrace("connect_connection: connect() call...", port);
    if (connect(peer_socketfd, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) == -1) {
        if(errno == EAGAIN)
        {
            //No problem, we stay in TCP_PENDING and finish the handshake later (EPOLL)
            return {peer_socketfd,connection_info};
        }
        logError("connect_connection: Nonblocking connect to {}:{} failed fatally. Errno: {}", ip_to_string(address), port, strerror(errno));
        close(peer_socketfd);
        return {-1,connection_info};
    }
    connection_info.ssl_stat = HANDSHAKE_CLIENT_READ_CERT;
    return {peer_socketfd,connection_info};

}

SSL* setup_SSL_for_connection(socket_t socketfd, bool am_i_server)
{
    logDebug("setup_SSL_for_connection: Setting up SSL for new connection. {}", am_i_server? "We are server." : "We are client.");
    SSL* ssl;
    if(am_i_server){
        ssl = SSL_new(SSLConfig::server_ctx);
    }else{
        ssl = SSL_new(SSLConfig::client_ctx);
    }

    if(!ssl){
        logError("Failure SSL object: SSL object null pointer");
        return nullptr;
    }
    SSL_set_fd(ssl, socketfd);

    /*
     *#ifdef SSL_VERBOSE
     *SSLUtils::check_ssl_blocking_mode(ssl);
     *#endif
     */

    return ssl;
}



FlushResult flush_write_connInfo_with_SSL_New(SSL* ssl, Message& send_buf)
{
    ssize_t bytes_flushed;
    do{
        bytes_flushed = SSL_write(ssl,send_buf.data(),send_buf.size());
        if(bytes_flushed <= 0){
            int err = SSL_get_error(ssl, bytes_flushed);
            if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
                // Retry SSL_write() later.
                logDebug("flush_write_connInfo_with_SSL: SSL write error, try again later");
                return FLUSH_AGAIN;
            }
            logError("flush_write_connInfo_with_SSL: Other SSL write error: {}.", err);

            return FLUSH_FATAL;
        }
        //Partial written, advance buffer accordingly.
        send_buf.erase(std::begin(send_buf),std::begin(send_buf) + bytes_flushed);

    } while(bytes_flushed > 0 && send_buf.size() > 0);

    return EVERYTHING_WAS_FLUSHED;
}

FlushResult flush_write_connInfo_without_SSL_New(socket_t socketfd, Message& send_buf)
{
    ssize_t bytes_flushed;

    do{
        bytes_flushed = write(socketfd,send_buf.data(),send_buf.size());

        if(bytes_flushed == -1){
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // Retry write() later.
                logDebug("flush_write_connInfo_without_SSL: Socket write error, try again later");
                return FLUSH_AGAIN;
            }
            logError("flush_write_connInfo_without_SSL: Fatal socket write error.");
            return FLUSH_FATAL;

        }
        //Partial written, advance buffer accordingly.
        send_buf.erase(std::begin(send_buf),std::begin(send_buf) + bytes_flushed);
    } while(bytes_flushed > 0 && !send_buf.empty());

    return EVERYTHING_WAS_FLUSHED;
}


FlushResult flush_sendbuf_New(socket_t socketfd, ConnectionInfo & connection_info)
{
    if(send_buffer_empty(connection_info)){
        return FlushResult::EVERYTHING_WAS_FLUSHED;
    }

    if(connection_info.connection_type == ConnectionType::MODULE_API){
        //Easy flush, simply write without respecting ssl.
        return flush_write_connInfo_without_SSL_New(socketfd,connection_info.send_bytes);
    }

    //We are in a ConnectionType::P2P
    if(SSLUtils::isAliveSSL(connection_info.ssl_stat)){
        return flush_write_connInfo_with_SSL_New(connection_info.ssl,connection_info.send_bytes);
    }
    return flush_write_connInfo_without_SSL_New(socketfd,connection_info.send_bytes);
}



//Returns: Can socket still be ordinarily used
bool flush_read_buffer_with_SSL_New (SSL* ssl, Message& read_buf)
{
    int bytes_flushed;

    std::vector<unsigned char> temp_buffer(4096); // Temporary buffer for reading

    do{
        ERR_clear_error();
        bytes_flushed = SSL_read(ssl,temp_buffer.data(),temp_buffer.size());

        if(bytes_flushed <= 0){
            int err = SSL_get_error(ssl,bytes_flushed);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                // We should try reading or writing later, nothing to tear down
                return true; // Socket is still up
            }
            logDebug("flush_read_buffer_with_SSL: SSL read returned <= 0, error is: {} ", SSL_get_error(ssl, bytes_flushed));
            return false; //Socket is down
        }
        //Append bytes to recvbuf
        read_buf.insert(std::end(read_buf),std::begin(temp_buffer),std::begin(temp_buffer) + bytes_flushed);
        temp_buffer.erase(std::begin(temp_buffer),std::begin(temp_buffer) + bytes_flushed);
    }while (bytes_flushed>0);

    return true; //Dead branch
}

//Returns: Can socket still be ordinarily used
bool flush_read_buffer_without_SSL_New(const socket_t socketfd, Message& read_buf)
{
    ssize_t bytes_flushed;

    std::vector<unsigned char> temp_buffer(4096); // Temporary buffer for reading

    do{
        bytes_flushed = read(socketfd, temp_buffer.data(), temp_buffer.size());

        if(bytes_flushed > 0){
            //Append the bytes read to the read_buf
            read_buf.insert(std::end(read_buf),std::begin(temp_buffer),std::begin(temp_buffer) + bytes_flushed);
            temp_buffer.erase(std::begin(temp_buffer),std::begin(temp_buffer) + bytes_flushed);
        } else if (bytes_flushed == -1){
            if(errno == EAGAIN || errno == EWOULDBLOCK){
                // We should try reading later
                return true; // Socket is still up
            }

            // An error occurred, tear down the connection
            logDebug("flush_read_buffer_without_SSL: An error occured during send without SSL. Tearing down connection.");
            return false; // Socket is down

        } else if(bytes_flushed == 0){
            // Connection was closed by the peer
            logDebug("flush_read_buffer_without_SSL: Connection was closed by peer on send without SSL. Tearing down connection.");
            return false; // Socket is down
        }
    } while (bytes_flushed > 0);

    return true; //Socket is still up
}


//Returns: Can socket still be ordinarily used
bool flush_recvbuf_New(socket_t socketfd, ConnectionInfo & connection_info){

    if(connection_info.connection_type == ConnectionType::MODULE_API){
        // Easy flush, simply read without respecting SSL
        return flush_read_buffer_without_SSL_New(socketfd, connection_info.receive_bytes);
    }

    //We are in a ConnectionType::P2P
    if(SSLUtils::isAliveSSL(connection_info.ssl_stat)){
        return flush_read_buffer_with_SSL_New(connection_info.ssl, connection_info.receive_bytes);
    }

    // Else: SSL is not active (yet). P2P-Connections enforce TLS, so this will happen soon.
    // Server & Client read without SSL encryption
    return flush_read_buffer_without_SSL_New(socketfd, connection_info.receive_bytes);
}



/*
 *Client callstack for connect:
 *[,] = connect_connection()
 *ssl = setup_ssl_for_connection(,false)
 *con_info.ssl = ssl;
 *etc...
 *
 */

socket_t init_tcp_connect_ssl(int epollfd, const in6_addr& address, u_int16_t port, const ConnectionType connection_type)
{
    logTrace("init_connect_ssl called.");
    auto &[socketfd,connection_info] = connect_connection(address, port, connection_type);

    //TODO, maybe move this to the next connect function in line.
    SSL* ssl = setup_SSL_for_connection(socketfd,false);
    connection_info.ssl = ssl;

    connection_map[socketfd] = connection_info;
    logTrace("init_connect_ssl: added newly connecting peer to global connection_map.");

    add_to_epoll(epollfd,socketfd);
    return socketfd;
}

bool retry_tcp_connect_ssl(socket_t socketfd, ConnectionInfo connection_info)
{
    sockaddr_in6 addr{};
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(connection_info.client_port);
    addr.sin6_addr = connection_info.client_addr;

    logTrace("retry_tcp_connect_ssl: connect() call...", connection_info.client_port);
    if (connect(socketfd, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) == -1) {
        if(errno == EAGAIN)
        {
            //No problem, we stay in TCP_PENDING and finish the handshake later (EPOLL)
            return true;
        }
        logError("retry_tcp_connect_ssl: Nonblocking connect to {}:{} failed fatally. Errno: {}", ip_to_string(addr.sin6_addr), connection_info.client_port, strerror(errno));
        close(socketfd);
        return false;
    }
    connection_info.ssl_stat = HANDSHAKE_CLIENT_READ_CERT; //Let EPOLLIN notify us next :)
    return true;

}


//MANDATORY: ssl_stat must be transitioned to SSLStatus::HANDSHAKE_CLIENT_READ_CERT before calling this function
bool init_connect_ssl(int epollfd, socket_t socketfd, ConnectionInfo &connection_info)
{
    SSL *ssl = connection_info.ssl;
    CertificateStatus cert_stat = receive_certificate_as_client(epollfd, socketfd, connection_info);
    if(cert_stat == CertificateStatus::ERRORED_CERTIFICATE || cert_stat == CertificateStatus::KNOWN_CERTIFICATE_CONTENT_MISMATCH){
        //Abort the connection. Could be a malicious Peer! Abort, abort!
        logWarn("proceed_connect_ssl: Receiving certificate from server was faulty, e.g. syntactically/ corrupted OR attemt to spoof Identity of well-known peer");
        return false;
    }
    if(cert_stat == CertificateStatus::CERTIFICATE_NOT_FULLY_PRESENT){
        logTrace("proceed_connect_ssl: Received certificate is not fully present yet. Wait for more bytes.");
        return true; //fd is valid, but wait for more bytes.
    }
    logTrace("proceed_connect_ssl: Received certificate is in a valid state. Now, try_ssl_connect()");
    //Else: cert_stat is either NEW_VALID_CERTIFICATE  or EXPECTED_CERTIFICATE, continue with protocol.
    //New certificate saved or recognized previously trusted certificate.
    //Advance to at least SSLStatus::AWAITING_ACCEPT :)

    connection_info.ssl_stat = SSLUtils::try_ssl_connect(ssl);
    if (connection_info.ssl_stat == SSLStatus::FATAL_ERROR_ACCEPT_CONNECT) {
        logError("proceed_connect_ssl: try_ssl_connect() failed fatally, tear down the connection");
        return false;
    }
    logTrace("proceed_connect_ssl: SSL State transitioned to {}",connection_info.ssl_stat);
    return true;
}

bool init_accept_ssl(int epollfd, const epoll_event& current_event, ConnectionType connection_type)
{
    logTrace("fully_accept called.");
    auto &[socketfd,connection_info] = accept_connection(current_event, ConnectionType::P2P);
    SSL* ssl = setup_SSL_for_connection(socketfd, true);
    connection_info.ssl = ssl;
    connection_info.ssl_stat = SSLStatus::HANDSHAKE_SERVER_WRITE_CERT;
    connection_map.emplace(socketfd, connection_info);
    //Provide certificate to requesting peer
    write_charptr_to_sendbuf(connection_info, SSLConfig::length_prefixed_cert_str, sizeof(uint32_t) + SSLConfig::cert_len);
    FlushResult flushRes = flush_sendbuf_New(socketfd,connection_info);
    //Advance SSL state depending on the flush-out result
    if(flushRes == FLUSH_FATAL){
        SSL_free(ssl);
        close(socketfd);
        connection_map.erase(socketfd);
        return false;
    }

    add_to_epoll(epollfd,socketfd);
    //TODO: epoll_ctl could return -1, errno set.

    if(flushRes == FLUSH_AGAIN)
    {
        //EPOLLOUT will notify us
        return true;
    }
    //EVERYTHING_FLUSHED:
    SSLStatus tried_accept = SSLUtils::try_ssl_accept(ssl);
    connection_map.at(socketfd).ssl_stat = tried_accept;
    if(tried_accept == SSLStatus::FATAL_ERROR_ACCEPT_CONNECT){
        logError("fully_accept: Fatal error occurred on SSL accept. TCP connection was closed.");
        SSL_free(ssl);
        close(socketfd);
        connection_map.erase(socketfd);
        return false;
    }
    //SSL Connection setup (put certificate in sendbuffer and flush once)
    //Further, use EPOLLET for callback when (partial) rest of message can be sent
    logDebug("fully_accept: Accepted new connection on listening P2P socket");
}






//






#ifndef TESTING1
int main(int argc, char const *argv[])
    {
        /* Ports/Arguments:
         * 1. host ip (if using ipv4, currently only compatible with network local IP address to not have a problem with NAT, e.g. 192.168.0.x)
         * 2. host port for module API server
         * 2. host port for p2p server
         * 3. to join existing network: pass peer ip and port for p2p contact point
        */
        //Setup logger:
        auto loglevel = spdlog::level::info;
        auto loggerOpt = setup_Logger(loglevel);
        if(!loggerOpt.has_value())
        {
            return 1;
        }

        std::string host_address_string = {};

        struct in6_addr host_address{};
        u_short host_module_port = ServerConfig::MODULE_API_PORT;
        u_short host_p2p_port = ServerConfig::P2P_PORT;

        // Peer to connect to as first contact
        u_short peer_port = 0;
        std::string peer_address_string = {};
        struct in6_addr peer_address{};

        bool should_connect_to_network = true;

        std::string help_description = "Run a DHT peer with local storage.\n\n"
                    "Multiple API clients can connect to this same instance.\n"
                    "To connect to an existing network, provide the ip address and port of a peer, otherwise a new network will be created.\n";
        std::string examples = "\nExample usages:\n\n"
                        "Start new p2p network on '192.168.0.42:7402':\n"
                        "\tdht_server -a 192.168.0.42 -m 7401 -p 7402\n"
                        "Connect to p2p network on '192.168.0.42:7402' from '192.168.0.69:7404', accepting requests on port 7403:\n"
                        "\tdht_server -a 192.168.0.69 -m 7403 -p 7404 -A 192.168.0.42 -P 7402\n"
                        "\n"
                        "To test the server on your local machine, you can create test nodes with:\n"
                        "\tdht_server -a ::1 -m 7401 -p 7402\n"
                        "\tdht_server -a ::1 -m 7403 -p 7404 -A ::1 -P 7402\n"
                        "\tdht_server -a ::1 -m 7405 -p 7406 -A ::1 -P 7402\n"
                        "\tdht_server -a  ::1 -m 7407 -p 7408 -A ::1 -P 7402\n";

        progOpt::options_description desc{};
        try {
            desc.add_options()("help,h", "Help screen")
            // Argument parsing:
            // Use boost::program_options for parsing:
            ("host-address,a", progOpt::value<std::string>(&host_address_string), "Bind server to this address")
            ("module-port,m", progOpt::value<u_short>(&host_module_port), "Bind module api server to this port")
            ("p2p-port,p", progOpt::value<u_short>(&host_p2p_port), "Bind p2p server to this port")
            ("peer-address,A", progOpt::value<std::string>(&peer_address_string), "Try to connect to existing p2p network node at this address")
            ("peer-port,P", progOpt::value<u_short>(&peer_port), "Try to connect to existing p2p network node at this port")
            ("unreg", "Unrecognized options");

            progOpt::positional_options_description pos_desc;
            pos_desc.add("host-address", 1);
            pos_desc.add("module-port", 1);
            pos_desc.add("p2p-port", 1);
            pos_desc.add("peer-address", 1);
            pos_desc.add("peer-port", 1);

            progOpt::command_line_parser parser{argc, argv};
            parser.options(desc)
                //.allow_unregistered()
                .positional(pos_desc)
                .style(progOpt::command_line_style::default_style | progOpt::command_line_style::allow_slash_for_short);
            progOpt::parsed_options parsed_options = parser.run();

            progOpt::variables_map vm;
            progOpt::store(parsed_options, vm);
            progOpt::notify(vm);

            if (vm.contains("help"))
            {
                std::string desc_string = (std::ostringstream() << desc).str();
                logInfo("{}{}{}\n", help_description, desc_string, examples);
                return 0;
            }

            if (vm.contains("unreg")) {
                std::string desc_string = (std::ostringstream() << desc).str();
                logCritical("Unrecognized options");
                logInfo("{}{}{}\n", help_description, desc_string, examples);
                return 1;
            }

            if (host_module_port == host_p2p_port) {
                logCritical("host_module_port and p2p_port are the same");
                return -1;
            }
            logInfo("Modules reach this server on {}:{}", host_address_string, host_module_port);
            logInfo("We communicate with peers on {}:{}", host_address_string, host_p2p_port);
            if (system(("ping -c1 -s1 " + host_address_string + "  > /dev/null 2>&1").c_str()) != 0) {
                logWarn("Warning: failed to ping host.");
            }

            if (vm.contains("peer-address") && vm.contains("peer-port")) {
                logInfo("Trying to connect to existing Network Node {}:{}",peer_address_string,peer_port);
                if (!convert_to_ipv6(peer_address_string, peer_address)) {
                    logCritical("Failed to convert ip address string to in_addr6 Type. Please provide a syntactically correct IP address (v4 or v6) for the peer");
                    return 1;
                }
                if (system(("ping -c1 -s1 " + peer_address_string + "  > /dev/null 2>&1").c_str()) != 0) {
                    logWarn("Warning: Failed to ping peer");
                }
            } else {
                logInfo("Setting up a new network as no join-contact was supplied.");
                should_connect_to_network = false;
            }

        // Parsing complete
    }
    catch (std::exception& _)
    {
        // passed invalid arguments, e.g. ip to port or similar
        std::string desc_string = (std::ostringstream() << desc).str();
        logCritical("Passed invalid commandline arguments.");
        logInfo("{}{}{}\n", help_description, desc_string, examples);
        return -1;
    }

    if (!convert_to_ipv6(host_address_string, host_address)) {
        logCritical("Please provide a syntactically correct host IP address");
        return 1;
    }


    // TODO:
    // switch: either
    // 1. join existing network -> we need an ip/ip list which we can ask
    // 2. create new network
    // finally: in both cases, to create a network, we need a way to exchange triples
    // first: setup RPC messages, to make "joining" possible by sending a "FIND_NODE" to the contact
    // then, for case 1 we need Node A to send FIND_NODE to node B that receives a triple from A or how does A present itself to B?

    routing_table = RoutingTable(host_address, host_p2p_port);
    logTrace("Routing table set up");

    // Ignore SIGPIPE (if socketfd gets closed by remote peer, we might accidentally write to a broken pipe)
    signal(SIGPIPE, SIG_IGN);
    std::signal(SIGINT,sig_c_handler);
    std::signal(SIGTERM,sig_c_handler);

    // Open port for local API traffic from modules
    socket_t module_api_socketfd = setup_server_socket(host_module_port);
    logTrace("Setup listening module api socket");
    main_epollfd = epoll_create1(0);
    logTrace("Setup main epoll file descriptor");
    main_epollfd = add_to_epoll(main_epollfd, module_api_socketfd);
    socket_t p2p_socketfd = setup_server_socket(host_p2p_port);
    logTrace("Setup listening p2p socket");
    main_epollfd = add_to_epoll(main_epollfd, p2p_socketfd);
    std::vector<epoll_event> epoll_events{64};



    if (main_epollfd == -1 || module_api_socketfd == -1 || p2p_socketfd == -1) {
        logCritical("Error creating sockets");
        return 1;
    }

    logDebug("Setup all initial sockets, epollfds. Awaiting connections / requests");

    //Generate everything necessary for SSL. See ssl.cpp/ssl.h
    //TODO: Persistent storage of certificate map necessary? I doubt it. Argument only passed for filename uniqueness.
    prepare_SSL_Config(/*host_p2p_port*/);

    logDebug("Prepared the \"SSLConfig::\" (context, self-signed certificate,...) for all future P2P-data transmissions ");

    if(should_connect_to_network) {
        // TODO joern -> epollfd und setup connect trennen, should only return socket
        if (!connect_to_network(main_epollfd, peer_address, peer_port)) {
            return -1;
        }
    logInfo("Connection to existing network (provided peer) was successful");
    }
    //Start to periodically purge local_storage:

    constexpr std::chrono::seconds purging_period{MIN_LIFETIME_SEC/2};
    purger = std::thread(purge_local_storage,purging_period);

    logDebug("Started local_storage purging thread. Thread will purge periodically, sleep {} seconds in between", static_cast<int>(purging_period.count()));
    logDebug("Entering main epoll event loop");

    // event loop
    logInfo("Server running...");
    bool server_is_running = true;
    while (server_is_running) {
        int event_count = epoll_wait(main_epollfd, epoll_events.data(), std::ssize(epoll_events), -1);  // dangerous cast
        // TODO: @Marius ADD SERVER MAINTENANCE. peer-ttl (k-bucket
        // maintenance) internal management clean up local_storage for all keys,
        // std::erase if ttl is outdated

        if (event_count == -1) {
            if (errno == EINTR) { // for debugging purposes
                continue;
            }
            logCritical("Error in epoll_wait: {}. Shutting down server...", strerror(errno));
            server_is_running = false;
            break;
        }
        for (int i = 0; i < event_count; ++i) {
            const epoll_event &current_event = epoll_events[i];
            if(current_event.events & EPOLLERR)
            {
                //Unexpected Ctrl+C or sth (ungracefully closed)
                //Purge everything, close fd, remove of connection map (essentially tear_down_connection)
            }

            if (current_event.data.fd == module_api_socketfd) {
                //TODO: ONLY LISTEN ON PORTS AFTER INIT PHASE
                //TCP Handshake only
                auto &[socketfd,connection_info] = accept_connection(current_event, ConnectionType::MODULE_API);
                //Set metadata
                connection_map.emplace(socketfd, connection_info);
                logDebug("Accepted new connection on listening MODULE_API socket");

            } else if (current_event.data.fd == p2p_socketfd) {
                //TODO: Ask Master, inline or extract?
                //TCP Handshake only
                socket_t newly_accepted_socketfd = init_accept_ssl(main_epollfd,current_event,ConnectionType::P2P);

            } else {
                bool socket_still_valid = true;
                if (!connection_map.contains(current_event.data.fd)) {
                    logError("Tried to operate on a socket that's not connected anymore or not saved in our connections.");
                    continue;
                }
                // handle client processing of existing sessions
                if (current_event.events & EPOLLIN)
                {
                    //1. Lookup all metadata for switch metadata.state
                    //2. Flush read everything as user data (connectionInfo (for ssl encrypted or not)).
                    //2. OR Flush read everything as tls protocol data: Follow TLS/SSL Handshake protocol by try_ssl_accept/connect().
                    //3. Handle application-layer receive-buffer data (depending on state)
                    //4. Write stuff into user-sendbuf dependent on preceeding received data
                    //5. Try flush out everything (depending on ssl protocol state)
                    //Note:  SSL ACCEPT OR CONNECT WILL FLUSH ALL BYTES FROM KERNEL SIDE.
                    //-->handler function for each different state
                    logTrace("New EPOLLIN event. handle_EPOLLIN call...");
                    socket_still_valid = handle_EPOLLIN(main_epollfd,current_event);
                }
                if (socket_still_valid && current_event.events & EPOLLOUT){
                    //Retrieve all metadata for switch metadata.state
                    //Flush write all tls protocol data: Follow TLS/SSL Handshake protocol by try_ssl_accept/connect().


                    socket_still_valid = handle_EPOLLOUT(main_epollfd,current_event);
                }
                if (socket_still_valid && current_event.events & EPOLLERR){
                    tear_down_connection(main_epollfd,current_event.data.fd);
                    logTrace("New EPOLLERR event, tore down connection");
                }
            }
        }

        //Do some async tasks, enqueue them as output parameter for handle functions:

        //Array of triples:
        //timestamp now = chrono::now()
        //for all where timestamp <= now , exec. function with args.
        //[<timestep,std::function(function pointer), arguments>]
        //[<timestep,function pointer, arguments>]
        //[<timestep,function pointer, arguments>]
        //Maybe std::variant, effectively union. Could be tricky

        //build minimum over all remaining tasks and define next timeout

        //WORK ON ALL ASYNC TASKS THAT ARE READY
    }

    logInfo("Server terminating. {}", server_is_running);
    sig_c_handler(SIGTERM);
    return 0;
}
#endif