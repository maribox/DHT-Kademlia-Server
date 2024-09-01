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

#define VERBOSE

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
Boost provides one, seemingly a bit hard to setup, but anyways:
https://www.boost.org/doc/libs/1_82_0/libs/log/doc/html/index.html
*/


std::unordered_map<socket_t,ConnectionInfo> connection_map;
static constexpr size_t MAX_LIFETIME_SEC = 20*60; // 20 minutes in seconds
static constexpr size_t MIN_LIFETIME_SEC = 3*60;  //  3 minutes in seconds
static constexpr size_t DEFAULT_LIFETIME_SEC = 5*60; // 5 minutes in seconds

static constexpr size_t MAX_REPLICATION = 30;
static constexpr size_t MIN_REPLICATION = 3;
static constexpr size_t DEFAULT_REPLICATION = 20; // should be same to K


std::map<Key,std::pair<std::chrono::time_point<std::chrono::system_clock>, Value>> local_storage{};

RoutingTable routing_table;

int main_epollfd;

// Utility functions

// operator< for use in set.
// assume that nodes cannot switch ip/port combo when in the network.
bool operator<(const Node& lhs, const Node& rhs) {
    return lhs.id < rhs.id;
}

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

template <>
struct std::hash<Value>
{
    // Code taken and adapted from https://stackoverflow.com/a/72073933/14236974
    std::size_t operator()(const std::vector<unsigned char>& vec) const noexcept {
        std::size_t seed = vec.size();
        for (auto x : vec) {
            x = ((x >> 4) ^ x) * 0x45d9f3b;
            x = ((x >> 4) ^ x) * 0x45d9f3b;
            x = (x >> 4) ^ x;
            seed ^= x + 0x9e3779b9 + (seed << 6) + (seed >> 2);
        }

        return seed;
    }
};

bool convert_to_ipv6(const std::string& address_string, struct in6_addr& address) {
    struct in_addr ipv4_addr;
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
            //std::cout << "Converted address "  << address_string  << " to " << address_converted << std::endl;
        } catch (...) {
            std::cerr << "Converted address " << address_string  << " but couldn't format." << std::endl;
        }
        return true;
    }
    return false;  // Invalid address
}

// TODO: Maybe overwrite << for key_t?
std::string key_to_string(const Key &key) {
    std::string str{};

    for (auto it = key.cbegin() ; it < key.end(); it++) {
        str += *it;
    }
    return str;
}

std::string ip_to_string(const in6_addr& ip) {
    char ip_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ip, ip_str, sizeof(ip_str));
    return std::string(ip_str);
}

bool send_buffer_empty(ConnectionInfo &connection_info){
    return connection_info.send_bytes.size() == 0;
}

bool recv_buffer_empty(ConnectionInfo &connection_info){
    return connection_info.receive_bytes.size() == 0;
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



// SSL

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

        #ifdef VERBOSE
            std::cout << "Tore down connection running over port: " << connection_info.client_port << "." << std::endl;
        #endif

    }else{
        //Should be a dead branch:
        #ifdef VERBOSE
        std::cout << "Supposedly dead control flow branch reached in tear_down_connection(...)" << std::endl;
        #endif
        close(socketfd);
    }
}


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
                std::cerr << "SSL write error, try again later" << std::endl;
                is_socket_still_up = true;
                was_everything_sent = false;
                return ret;
            } else {
                tear_down_connection(epollfd,socketfd);
                std::cerr << "Other SSL write error. Tore down connection." << std::endl;
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
                std::cerr << "Socket write error, try again later" << std::endl;
                is_socket_still_up = true;
                was_everything_sent = false;
                return ret;
            } else {
                tear_down_connection(epollfd,socketfd);
                std::cerr << "Other socket write error. Tore down connection." << std::endl;
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
std::pair<bool,bool> flush_sendbuf(socket_t socketfd, ConnectionInfo & connection_info, int epollfd){
    auto &sendbuf = connection_info.send_bytes;
    if(sendbuf.size() == 0){
        return {true,true};
    }

    std::pair<bool,bool> ret;
    ret = {true,false}; //Default return: Socket up, but not everything sent yet.
    auto &[is_socket_still_up,was_everything_sent] = ret;

    SSL* ssl = connection_info.ssl;

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
        bytes_flushed = SSL_read(ssl,temp_buffer.data(),temp_buffer.size());

        if(bytes_flushed > 0){
            //Append bytes to recvbuf
            recvbuf.insert(std::end(recvbuf),std::begin(temp_buffer),std::begin(temp_buffer) + bytes_flushed);
            recvbuf.erase(std::begin(temp_buffer),std::begin(temp_buffer) + bytes_flushed);
        } else if (bytes_flushed == 0){
            // Connection was closed by the peer
            tear_down_connection(epollfd, socketfd);
            return false; // Socket is down
        } else{
            int err = SSL_get_error(ssl,bytes_flushed);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                // We should try reading or writing later, nothing to tear down
                return true; // Socket is still up
            }
            //An error occurred, tear down the connection
            tear_down_connection(epollfd,socketfd);
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
            recvbuf.erase(std::begin(temp_buffer),std::begin(temp_buffer) + bytes_flushed);
        } else if (bytes_flushed == -1){
            if(errno == EAGAIN || errno == EWOULDBLOCK){
                // We should try reading later
                return true; // Socket is still up
            }else{
                // An error occurred, tear down the connection
                tear_down_connection(epollfd, socketfd);
                return false; // Socket is down
            }
        }else if(bytes_flushed == 0){
            // Connection was closed by the peer
            tear_down_connection(epollfd, socketfd);
            return false; // Socket is down
        }
    } while (bytes_flushed > 0);

    return true; //Socket is still up
}


//Flushes the kernel-side socket-buffer into the connection_info receive_bytes buffer.
//Returns if the socket is still valid (connection is not torn down).
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

//Returns true if the socket is still active. If the return parameter foreign_cert_str is not nullptr, data was correctly extracted.
bool receive_prefixed_sendbuf_in_charptr(const int epollfd, const socket_t socketfd, ConnectionInfo& connection_info,
                                         unsigned char * foreign_length_prefixed_cert_str, uint32_t &length){
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
    uint32_t data_length = ntohl(net_length);
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
            local_storage.erase(it);
            return nullptr; // Log lookup-miss.
        }       
        return &value; // Log lookup-hit.
}

void save_to_storage(const Key &key, std::chrono::seconds ttl, Value &val)
{
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
    write_body(message, 0, node_id.data(), NODE_ID_SIZE);
    write_body(message, NODE_ID_SIZE, reinterpret_cast<unsigned char*>(&network_order_port), 2);
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

    // TODO: might take too much effort/be wrong to just add -> maybe look if it's already there first?
    auto peer = Node{peer_ip, sender_port, sender_node_id};
    if (!routing_table.contains(peer)) {
        std::cout << "Got contacted by new peer reachable at " << ip_to_string(peer.addr) << ":" << sender_port << std::endl;
        routing_table.add_peer(peer);
    }

    return rpc_id;
}

void write_body(Message& message, size_t body_offset, const unsigned char* data, size_t data_size) {
    std::copy_n(data, data_size, message.data() + HEADER_SIZE + body_offset);
}

void read_body(const Message& message, size_t body_offset, unsigned char* data, size_t data_size) {
    std::copy_n(message.data() + HEADER_SIZE + body_offset, data_size, data);
}

bool forge_DHT_message(socket_t socket, Message &message, int epollfd) {
    int sent = 0;
    if (message.size() > 0) {
        //TODO: BUG! WRONG! WRITE INTO CONNECT INFO STRUCT. Let epoll handle it
        //TODO: Abstract mem copying to std::vector of connect info struct in writer method
        sent = write(socket, message.data(), message.size());
    }
    // if write wasn't completed yet, rest will be sent with epoll wait
    if (sent == -1) {
        std::cerr << "Error sending message, aborting." << std::endl;
        return false;
    }

    if (epollfd == -1) {
        epollfd = main_epollfd;
    }

    epoll_event event{};
    event.events = EPOLLIN | EPOLLOUT;
    event.data.fd = socket;
    epoll_ctl(epollfd, EPOLL_CTL_MOD, socket, &event);

    return true;
}

bool check_rpc_id(const Message &message, const Key correct_rpc_id) {
    Key rpc_id;
    read_body(message, NODE_ID_SIZE + 2, rpc_id.data(), 32);
    if (rpc_id != correct_rpc_id) {
        std::cerr << "Got message with invalid rpc-id!" << std::endl;
        return false;
    }
    return true;
}

// Module API functions handling+construction functions

bool forge_DHT_put(socket_t socket, Key &key, Value &value) {
    return true;
}


std::vector<Node> blocking_node_lookup(Key &key) {
    std::vector<Node> closest_nodes = routing_table.find_closest_nodes(key);
    std::set<Node> returned_nodes{};
    std::mutex returned_nodes_mutex;
    int epollfd = epoll_create1(0);
    std::vector<epoll_event> epoll_events{64};
    std::vector<Node> k_closest_nodes(K);


    std::cout << "Trying to find neighbours of a key starting with '"
            << std::hex << key[0] << key[1] << "'... " << std::dec << std::endl;

    while (true) {
        // here, closest_nodes will be sorted by distance to key
        bool found_difference_to_last_iteration = false;
        for (int i = 0; i < std::min(K, closest_nodes.size()); i++) {
            if (k_closest_nodes[i] != closest_nodes[i]) {
                k_closest_nodes[i] = closest_nodes[i];
                found_difference_to_last_iteration = true;
            }
        }
        if (found_difference_to_last_iteration) {
            break;
        }

        int responses_left = 0;

        if (closest_nodes.size() > ALPHA) {
            closest_nodes.resize(ALPHA);
        }

        for (auto& node: closest_nodes) {
            if (node.port != 0 && node != routing_table.get_local_node()) {
                socket_t sockfd = setup_connect_socket(epollfd, node.addr, node.port, ConnectionType::P2P);
                setup_epollin(epollfd, sockfd);
                forge_DHT_RPC_find_node(sockfd, key);
                responses_left++;
            }
        }
        while(responses_left > 0) {
            int event_count = epoll_wait(epollfd, epoll_events.data(), std::ssize(epoll_events), 5000);
            if (event_count != -1) {
                for (int i = 0; i < event_count; i++) {
                    auto current_event = epoll_events[i];
                    if (!(current_event.events & EPOLLIN)) {
                        continue;
                    }
                    handle_EPOLLIN(epollfd, current_event);

                    socket_t sockfd = epoll_events[i].data.fd;
                    auto& connection_info = connection_map[sockfd];

                    u_short body_size = -1;
                    u_short dht_type = -1;

                    bool header_success = parse_header(connection_info, body_size, dht_type);
                    if (header_success && dht_type == P2PType::DHT_RPC_FIND_NODE_REPLY) {
                        handle_DHT_RPC_find_node_reply(sockfd, body_size, &returned_nodes, &returned_nodes_mutex);

                        responses_left--;
                        // potential error source when multiple responses from same source (shouldn't happen, but could)
                        close(sockfd);
                        connection_map.erase(sockfd);
                    }
                }
            }
        }

        std::sort(closest_nodes.begin(), closest_nodes.end(),
                  [key](const Node& node_1, const Node& node_2){return RoutingTable::node_distance(node_1.id, key) < RoutingTable::node_distance(node_2.id, key);}
        );
    }

    std::cout << "Lookup completed. Found " << closest_nodes.size() << " closest nodes." << std::endl;
    return closest_nodes;
}

void crawl_blocking_and_store(Key &key, Value &value, int time_to_live, int replication) {
    auto k_closest_nodes = blocking_node_lookup(key);

    // TODO: involve replication
    for (auto& node : k_closest_nodes) {
        if (node.port == 0) {
            continue;
        }

        if (node == routing_table.get_local_node()) {
            std::cout << "Stored key '" << key_to_string(key) << "' with value '" << value.data() << "' to own storage" << std::endl;
            save_to_storage(key, std::chrono::seconds(time_to_live), value);
            continue;
        }

        socket_t sockfd = -1;
        /* Commented out for compilation. setup_connect_socket now needs an epoll instance... 
        *socket_t sockfd = setup_connect_socket(node.addr, node.port, ConnectionType::P2P);
        */
        if (sockfd != -1) {
            forge_DHT_RPC_store(sockfd, time_to_live, replication, key, value);
        }
    }
}



bool handle_DHT_put(socket_t socket, u_short body_size) {
    const Message& message = connection_map[socket].receive_bytes;
    int value_size = body_size - (4 + KEY_SIZE);

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

    Key key{};
    read_body(message, 4, key.data(), KEY_SIZE);
    Value value{};
    value.resize(value_size);
    read_body(message, 4 + KEY_SIZE, value.data(), value_size);



    std::thread([key, value, time_to_live, replication]() mutable {
        crawl_blocking_and_store(key, value, time_to_live, replication);
    }).detach();
    return true;
}

bool forge_DHT_get(socket_t socket, Key &key) {
    return true;
}

void crawl_blocking_and_return(Key &key, socket_t socket) {
    auto k_closest_nodes = blocking_node_lookup(key);

    auto found_values = std::vector<Value*>{};
    for (auto& node : k_closest_nodes) {
        if (node.port == 0) {
            continue;
        }

        if (node == routing_table.get_local_node()) {
            std::cout << "Trying to get key '" << key_to_string(key) << "' from own storage" << std::endl;
            auto value = get_from_storage(key);
            if (value) {
                found_values.push_back(value);
            }
            continue;
        }

        socket_t sockfd = -1;
        /* Commented out for compilation. setup_connect_socket now needs an epoll instance... 
        *socket_t sockfd = setup_connect_socket(node.addr, node.port, ConnectionType::P2P);
        */
        if (sockfd != -1) {
            forge_DHT_RPC_find_value(sockfd, key);
        }
    }

    std::map<Value, int> frequency;
    for (auto& value : found_values) {
        frequency[*value]++;
    }

    if (found_values.size() > 0) {
        //TODO: Was changed to auto& but yielded error. Reinvestigate
        auto most_frequent_element = std::max_element(frequency.begin(), frequency.end(),
                                  [](const std::pair<Value, int>& a, const std::pair<Value, int>& b) {
                                      return a.second < b.second;
                                  })->first;
        forge_DHT_success(socket, key, most_frequent_element);
    } else {
        forge_DHT_failure(socket, key);
    }
}

bool handle_DHT_get(socket_t socket, u_short body_size) {
    if (body_size != KEY_SIZE) {
        return false;
    }
    const Message& message = connection_map[socket].receive_bytes;
    Key key;
    read_body(message, 0, key.data(), KEY_SIZE);

    std::thread([key, socket]() mutable {
        crawl_blocking_and_return(key, socket);
    }).detach();
    return true;
}

bool forge_DHT_success(socket_t socket, const Key &key, const Value &value) {
    size_t message_size = HEADER_SIZE + KEY_SIZE + value.size();
    Message message(message_size);

    build_DHT_header(message, message_size, DHT_SUCCESS);
    write_body(message, 0, key.data(), KEY_SIZE);
    write_body(message, KEY_SIZE, value.data(), value.size());

    return forge_DHT_message(socket, message);
}

bool handle_DHT_success(socket_t socket, u_short body_size) {
    return false;
}

bool forge_DHT_failure(socket_t socket, Key &key) {
    size_t message_size = HEADER_SIZE + KEY_SIZE;
    Message message(message_size);

    build_DHT_header(message, message_size, DHT_FAILURE);
    write_body(message, 0, key.data(), KEY_SIZE);

    return forge_DHT_message(socket, message);
}

bool handle_DHT_failure(socket_t socket, u_short body_size) {
    return false;
}


// P2P/RPC handling+construction functions

bool forge_DHT_RPC_ping(socket_t socket) {
    // TODO: assumes connectionMap contains socket
    Key rpc_id = generate_random_nodeID();
    connection_map.at(socket).rpc_id = rpc_id;

    size_t body_size = RPC_SUB_HEADER_SIZE;
    size_t message_size = HEADER_SIZE  + body_size;
    u_short message_type = DHT_RPC_PING;
    Message message(message_size);

    build_DHT_header(message, message_size, message_type);
    build_RPC_header(message, rpc_id);

    return forge_DHT_message(socket, message);
}

bool handle_DHT_RPC_ping(const socket_t socket, const u_short body_size) {
    const Message& message = connection_map[socket].receive_bytes;
    Key rpc_id = read_rpc_header(message, connection_map[socket].client_addr);
    forge_DHT_RPC_ping_reply(socket, rpc_id);
    return true;
}

bool forge_DHT_RPC_ping_reply(socket_t socket, Key rpc_id) {
    return true;
}

// TODO: following functions even necessary? Should answers be waited upon in the respective switch-cases?
bool handle_DHT_RPC_ping_reply(const socket_t socket, const u_short body_size) {
    const Message& message = connection_map[socket].receive_bytes;
    if (!check_rpc_id(message, connection_map[socket].rpc_id)) {
        return false;
    }
    return true;
}

bool forge_DHT_RPC_store(socket_t socket, u_short time_to_live, int replication, Key &key, Value &value) {
    Key rpc_id = generate_random_nodeID();
    connection_map.at(socket).rpc_id = rpc_id;

    size_t body_size = RPC_SUB_HEADER_SIZE + KEY_SIZE + value.size();;
    size_t message_size = HEADER_SIZE + body_size;
    u_short message_type = DHT_RPC_STORE;
    Message message(message_size);

    build_DHT_header(message, message_size, message_type);
    build_RPC_header(message, rpc_id);

    u_short network_order_TTL = htons(time_to_live);
    write_body(message, RPC_SUB_HEADER_SIZE, reinterpret_cast<unsigned char*>(&network_order_TTL), 2);
    unsigned char replication_data = static_cast<unsigned char>(replication & 0xFF);
    write_body(message, RPC_SUB_HEADER_SIZE + 2, &replication_data, 1);
    write_body(message, RPC_SUB_HEADER_SIZE + 4, key.data(), KEY_SIZE);
    write_body(message, RPC_SUB_HEADER_SIZE + 4 + KEY_SIZE, value.data(), value.size());

    return forge_DHT_message(socket, message);
}

bool handle_DHT_RPC_store(const socket_t socket, const u_short body_size) {
    if (body_size <= RPC_SUB_HEADER_SIZE + 4 + KEY_SIZE) {
        return false;
    }
    const Message& message = connection_map[socket].receive_bytes;
    int value_size = body_size - (RPC_SUB_HEADER_SIZE + 4 + KEY_SIZE);

    Key rpc_id = read_rpc_header(message, connection_map[socket].client_addr);

    u_short network_order_TTL;
    read_body(message, RPC_SUB_HEADER_SIZE, reinterpret_cast<unsigned char*>(&network_order_TTL), 2);
    int time_to_live = ntohs(network_order_TTL);
    unsigned char replication_data;
    read_body(message, RPC_SUB_HEADER_SIZE + 2, &replication_data, 1);
    int replication = static_cast<int>(replication_data);
    Key key;
    read_body(message, RPC_SUB_HEADER_SIZE + 4, key.data(), KEY_SIZE);
    Value value{};
    value.resize(value_size);
    read_body(message, RPC_SUB_HEADER_SIZE + 4 + KEY_SIZE, value.data(), value_size);

    if (time_to_live > MAX_LIFETIME_SEC || time_to_live < MIN_LIFETIME_SEC) {
        // default time to live, as value is out of lifetime bounds
        time_to_live = DEFAULT_LIFETIME_SEC;
    }

    save_to_storage(key, std::chrono::seconds(time_to_live), value);

    return forge_DHT_RPC_store_reply(socket, rpc_id, key, value);
}

bool forge_DHT_RPC_store_reply(socket_t socket, Key rpc_id, Key &key, Value &value) {
    size_t body_size = RPC_SUB_HEADER_SIZE + KEY_SIZE + value.size();;
    size_t message_size = HEADER_SIZE + body_size;
    u_short message_type = DHT_RPC_STORE_REPLY;
    Message message(message_size);

    build_DHT_header(message, message_size, message_type);
    build_RPC_header(message, rpc_id);

    write_body(message, RPC_SUB_HEADER_SIZE, key.data(), KEY_SIZE);
    write_body(message, RPC_SUB_HEADER_SIZE + KEY_SIZE, value.data(), value.size());

    return forge_DHT_message(socket, message);
}

bool handle_DHT_RPC_store_reply(const socket_t socket, const u_short body_size) {
    if (body_size <= RPC_SUB_HEADER_SIZE + KEY_SIZE) {
        return false;
    }
    const Message& message = connection_map[socket].receive_bytes;
    if (!check_rpc_id(message, connection_map[socket].rpc_id)) {
        return false;
    }
    // TODO: maybe check if returned value is same as sent
    return true;
}

bool forge_DHT_RPC_find_node(socket_t socket, NodeID target_node_id) {
    Key rpc_id = generate_random_nodeID();
    connection_map.at(socket).rpc_id = rpc_id;

    size_t body_size = RPC_SUB_HEADER_SIZE + KEY_SIZE;
    size_t message_size = HEADER_SIZE + body_size;
    u_short message_type = DHT_RPC_FIND_NODE;
    Message message(message_size);

    build_DHT_header(message, message_size, message_type);
    build_RPC_header(message, rpc_id);

    write_body(message, RPC_SUB_HEADER_SIZE, target_node_id.data(), NODE_ID_SIZE);

    return forge_DHT_message(socket, message);
}

bool handle_DHT_RPC_find_node(const socket_t socket, const u_short body_size) {
    if (body_size != RPC_SUB_HEADER_SIZE + NODE_ID_SIZE) {
        return false;
    }
    const Message& message = connection_map[socket].receive_bytes;

    Key rpc_id = read_rpc_header(message, connection_map[socket].client_addr);

    NodeID target_node_id;
    read_body(message, RPC_SUB_HEADER_SIZE, target_node_id.data(), NODE_ID_SIZE);

    // find closest nodes, then return them:
    auto closest_nodes = routing_table.find_closest_nodes(target_node_id);

    return forge_DHT_RPC_find_node_reply(socket, rpc_id, closest_nodes);
}

bool forge_DHT_RPC_find_node_reply(socket_t socket, Key rpc_id,  std::vector<Node> closest_nodes) {
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

    return forge_DHT_message(socket, message);
}


bool handle_DHT_RPC_find_node_reply(const socket_t socket, const u_short body_size, std::set<Node>* closest_nodes_ptr, std::mutex* returned_nodes_mutex_ptr) {
    if ((body_size - RPC_SUB_HEADER_SIZE) % NODE_SIZE != 0) {
        return false;
    }
    int num_nodes = (body_size - RPC_SUB_HEADER_SIZE) / NODE_SIZE;

    const Message& message = connection_map[socket].receive_bytes;
    if (!check_rpc_id(message, connection_map[socket].rpc_id)) {
        return false;
    }

    bool created_closest_nodes = false;
    if (!closest_nodes_ptr) {
        closest_nodes_ptr = new std::set<Node>();
        created_closest_nodes = true;
    }

    for (int i = 0; i < num_nodes; i++) {
        Node node{};

        read_body(message, RPC_SUB_HEADER_SIZE + i*NODE_SIZE, node.addr.s6_addr, 16);
        read_body(message, RPC_SUB_HEADER_SIZE + i*NODE_SIZE + 16, reinterpret_cast<unsigned char*>(&node.port), 2);
        node.port = ntohs(node.port);
        read_body(message, RPC_SUB_HEADER_SIZE + i*NODE_SIZE + 16 + 2, node.id.data(), 32);
        if (returned_nodes_mutex_ptr) {
            std::lock_guard<std::mutex> lock(*returned_nodes_mutex_ptr);
        }
        closest_nodes_ptr->insert(node);
        if (node.id != routing_table.get_local_node().id) {
            routing_table.add_peer(node);
        }
    }
    std::cout << "Got back " << closest_nodes_ptr->size() << " nodes." << std::endl;

    if (created_closest_nodes) {
        delete(closest_nodes_ptr);
    }

    return true;
}

bool forge_DHT_RPC_find_value(socket_t socket, Key &key) {
    Key rpc_id = generate_random_nodeID();
    connection_map.at(socket).rpc_id = rpc_id;

    size_t body_size = RPC_SUB_HEADER_SIZE + KEY_SIZE;
    size_t message_size = HEADER_SIZE + body_size;
    u_short message_type = DHT_RPC_STORE;
    Message message(message_size);

    build_DHT_header(message, message_size, message_type);
    build_RPC_header(message, rpc_id);

    write_body(message, RPC_SUB_HEADER_SIZE, key.data(), KEY_SIZE);

    return forge_DHT_message(socket, message);
}

bool handle_DHT_RPC_find_value(const socket_t socket, const u_short body_size) {
    if (body_size != RPC_SUB_HEADER_SIZE + KEY_SIZE) {
        return false;
    }
    const Message &message = connection_map[socket].receive_bytes;

    Key rpc_id = read_rpc_header(message, connection_map[socket].client_addr);
    Key key;
    read_body(message, RPC_SUB_HEADER_SIZE, key.data(), KEY_SIZE);

    auto val_ptr = get_from_storage(key);
    if (val_ptr) {
        return forge_DHT_RPC_find_value_reply(socket, rpc_id, key, *val_ptr);
    } else {
        // TODO: What if we're closest and don't have value -> return FAILURE
        auto closest_nodes = routing_table.find_closest_nodes(key);
        return forge_DHT_RPC_find_node_reply(socket, rpc_id, closest_nodes);
    }
}

bool forge_DHT_RPC_find_value_reply(socket_t socket, Key rpc_id, const Key &key, const Value &value) {
    u_short message_type = DHT_RPC_FIND_VALUE_REPLY;
    size_t body_size = RPC_SUB_HEADER_SIZE + KEY_SIZE + value.size();
    size_t message_size = HEADER_SIZE + body_size;
    Message message(message_size);

    build_DHT_header(message, message_size, message_type);
    build_RPC_header(message, rpc_id);

    write_body(message, RPC_SUB_HEADER_SIZE, key.data(), KEY_SIZE);
    write_body(message, RPC_SUB_HEADER_SIZE + KEY_SIZE, value.data(), value.size());

    return forge_DHT_message(socket, message);
}

bool handle_DHT_RPC_find_value_reply(const socket_t socket, const u_short body_size) {
    if (body_size <= RPC_SUB_HEADER_SIZE + KEY_SIZE) {
        return false;
    }
    const int value_size = body_size - (RPC_SUB_HEADER_SIZE + KEY_SIZE);
    const Message& message = connection_map[socket].receive_bytes;

    if (!check_rpc_id(message, connection_map[socket].rpc_id)) {
        return false;
    }

    Key key;
    read_body(message, RPC_SUB_HEADER_SIZE, key.data(), KEY_SIZE);
    Value value{};
    value.resize(value_size);
    read_body(message, RPC_SUB_HEADER_SIZE + KEY_SIZE, value.data(), body_size - (RPC_SUB_HEADER_SIZE + KEY_SIZE));

    forge_DHT_success(socket, key, value);

    return true;
}

bool forge_DHT_error(socket_t socket, ErrorType error) {
    return true;
}


bool handle_DHT_error(const socket_t socket, const u_short body_size) {
    const size_t error_type_offset = HEADER_SIZE;
    // TODO: extract error type, switch case based on that
    return true;
}

// Message Parsing

bool parse_header(const ConnectionInfo &connection_info, u_short &message_size, u_short &dht_type){
    const Message &connection_buffer = connection_info.receive_bytes;
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



bool parse_API_request(socket_t socket, const u_short body_size, const ModuleApiType module_api_type){
    switch (module_api_type){
        {
        case DHT_PUT:
            {
            handle_DHT_put(socket, body_size);
        break;
            }
        case DHT_GET:
            {
            handle_DHT_get(socket, body_size);
        break;
            }
        case DHT_SUCCESS:
            {
            handle_DHT_success(socket, body_size);
        break;
            // Close connection (was only for relaying!)
            }
        case DHT_FAILURE:
            {
            handle_DHT_failure(socket, body_size);
        break;
            }

        default:
            break;
        }
    }
    return true;
}

bool parse_P2P_request(socket_t socket, const u_short body_size, const P2PType p2p_type) { // returns wether socket should be closed
    switch (p2p_type) {
        case DHT_RPC_PING:
            return handle_DHT_RPC_ping(socket, body_size);
        break;
        case DHT_RPC_STORE:
            return handle_DHT_RPC_store(socket, body_size);
        break;
        case DHT_RPC_FIND_NODE:
            return handle_DHT_RPC_find_node(socket, body_size);
        break;
        case DHT_RPC_FIND_VALUE:
            return handle_DHT_RPC_find_value(socket, body_size);
        break;
        case DHT_RPC_PING_REPLY:
            return handle_DHT_RPC_ping_reply(socket, body_size);
        break;
        case DHT_RPC_STORE_REPLY:
            return handle_DHT_RPC_store_reply(socket, body_size);
        break;
        case DHT_RPC_FIND_NODE_REPLY:
            return handle_DHT_RPC_find_node_reply(socket, body_size);
        break;
        case DHT_RPC_FIND_VALUE_REPLY:
            return handle_DHT_RPC_find_value_reply(socket, body_size);
        break;
        case DHT_ERROR:
            return handle_DHT_error(socket, body_size);
        break;
    }
    return true;
}

// Connection Processing

ProcessingStatus try_processing(socket_t curfd){
    //retreive information for element to process:
    ConnectionInfo &connection_info = connection_map.at(curfd);
    auto &connection_buffer = connection_info.receive_bytes;
    size_t byteCountToProcess = connection_buffer.size();
    if(connection_buffer.size() == 0){
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
        if(byteCountToProcess < message_size){
            return ProcessingStatus::WAIT_FOR_COMPLETE_MESSAGE_BODY;
        }
        //Header was fully parsed and entire message is present. Do the "heavy lifting", parse received request semantically:

    bool request_successful = false;
    bool keep_socket_open = false;

    if (connection_info.connection_type == ConnectionType::MODULE_API) {
        ModuleApiType module_api_type;
        if (is_valid_module_API_type(dht_type)) {
            module_api_type = static_cast<ModuleApiType>(dht_type);
        } else {
            std::cerr << "Tried to send invalid request to Module API Server. Aborting." << std::endl;
            return ProcessingStatus::ERROR;
        }
        if (module_api_type ==DHT_GET) {
            keep_socket_open = true;
        }
        // TODO: Pass socket instead of connection info
        request_successful = parse_API_request(curfd, message_size-HEADER_SIZE, module_api_type);
    } else if (connection_info.connection_type == ConnectionType::P2P) {
        P2PType p2p_type;
        if (is_valid_P2P_type(dht_type)) {
            p2p_type = static_cast<P2PType>(dht_type);
        } else {
            std::cerr << "Tried to send invalid request to P2P Server. Aborting." << std::endl;
            return ProcessingStatus::ERROR;
        }
        request_successful = parse_P2P_request(curfd, message_size-HEADER_SIZE, p2p_type);
    } else {
        std::cerr << "No ConnectionType registered for client. Aborting." << std::endl;
        return ProcessingStatus::ERROR;
    }
    if (request_successful && keep_socket_open) {
        return ProcessingStatus::PROCESSED_AND_OPEN;
    } else if (request_successful && !keep_socket_open) {
        return ProcessingStatus::PROCESSED_AND_CLOSE;
    } else {
        std::cerr << "Unknown Error with request." << std::endl;
        return ProcessingStatus::ERROR;
    }
}


void accept_new_connection(int epollfd, epoll_event &cur_event, ConnectionType connection_type) {
    sockaddr_in6 client_addr{};
    socklen_t client_addr_len = sizeof(client_addr);
    socket_t socketfd = accept4(cur_event.data.fd, reinterpret_cast<sockaddr*>(&client_addr), &client_addr_len, SOCK_NONBLOCK);
    if (socketfd == -1) {
        std::cerr << "Socket accept error: " << strerror(errno) << std::endl;
        return;
    }

    ConnectionInfo connection_info{};
    u_short client_port = ntohs(client_addr.sin6_port);

    connection_info.connection_type = connection_type;
    connection_info.role = ConnectionRole::SERVER; //We are accepting, so we are server.
    connection_info.client_addr = client_addr.sin6_addr;
    connection_info.client_port = client_port;
    

    #ifdef VERBOSE
    std::cout << "Accepted socket connection from " << ip_to_string(client_addr.sin6_addr) << ":" << client_port << std::endl;
    #endif


    if(connection_type == ConnectionType::P2P){
        
        #ifdef VERBOSE
        std::cout << "Setting up SSL for incoming client connection (we are server)" << std::endl; 
        #endif

        SSL* ssl = SSL_new(SSLConfig::server_ctx);
        connection_info.ssl = ssl;
        
        if(!ssl){
            std::cerr << "Failure Server: SSL object null pointer" << std::endl;
            return;
        }
        SSL_set_fd(ssl, socketfd);

        #ifdef VERBOSE
        SSLUtils::check_ssl_blocking_mode(ssl);
        #endif

        #ifdef VERBOSE
        std::cout << "Supplying length-prefixed Server-Certificate over insecure TCP channel" << std::endl;
        #endif

        connection_info.ssl_stat = SSLStatus::HANDSHAKE_SERVER_WRITE_CERT;
        
        //Always write to internal buffer. Do not give up control by directly writing out socketfd.
        write_charptr_to_sendbuf(connection_info,SSLConfig::length_prefixed_cert_str,SSLConfig::cert_len);

        //Transmit certificate unencrypted/ unauthenticated. Plaintext.
        auto [is_socket_still_up, everything_was_sent] = flush_sendbuf(socketfd,connection_info,epollfd);
        if(!is_socket_still_up){
            //Connection got torn down due to error(s) on certificate transmission. Abort accepting.
            return;
        }
        if(everything_was_sent){
            connection_info.ssl_stat = SSLUtils::try_ssl_accept(ssl);
            if(connection_info.ssl_stat == SSLStatus::FATAL_ERROR_ACCEPT_CONNECT){
                std::cerr << "Fatal error occured on SSL accept. TCP connection was closed." << std::endl;
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


void handle_EPOLLOUT(int epollfd, socket_t notifying_socket){
    ConnectionInfo connection_info = connection_map.at(notifying_socket);
    if(connection_info.send_bytes.size() == 0){
        epoll_event event{};
        event.events = EPOLLIN;
        event.data.fd = notifying_socket;
        epoll_ctl(epollfd, EPOLL_CTL_MOD, notifying_socket, &event);
        return;
    }

    //TODO:
    
}

void remove_client(int epollfd, int curfd) {
    epoll_ctl(epollfd, EPOLL_CTL_DEL, curfd, nullptr);
    close(curfd);
    connection_map.erase(curfd);
}

bool handle_EPOLLIN(int epollfd, epoll_event current_event){
    socket_t socketfd = current_event.data.fd;
    if (!connection_map.contains(socketfd)) {
        //Should never happen.
        tear_down_connection(main_epollfd, socketfd);
        return false;
    }
    ConnectionInfo &connection_info = connection_map.at(socketfd);

    if(connection_info.connection_type == ConnectionType::MODULE_API){
        //TODO: loop read into recv buf.

        return true; //Return early to distinguish from following ConnectionType::P2P
    }

    //Two large switches:
    //First: Event on the Server part of an SSL connection: Acts adhearing to protocol, and progresses SSLState. Final Goal: ACCEPTED.
    //
    if(connection_info.role == ConnectionRole::SERVER){
        
        auto [is_socket_still_up, everything_was_sent] = std::make_tuple(true, false);
        switch (connection_info.ssl_stat)
        {
            //Server still needs to finish SSL handshake for the next few cases:


            case SSLStatus::HANDSHAKE_SERVER_WRITE_CERT:
                //length prefixed ssl certificate is buffered since accept_new_connection. Simply flush it    
                std::tie(is_socket_still_up, everything_was_sent) = flush_sendbuf(socketfd,connection_info,epollfd);
                if(!is_socket_still_up){
                    //Connection got torn down due to error(s) on certificate transmission. Abort accepting.
                    return false;
                }
                if(everything_was_sent){
                    connection_info.ssl_stat = SSLUtils::try_ssl_accept(connection_info.ssl);
                    if(connection_info.ssl_stat == SSLStatus::FATAL_ERROR_ACCEPT_CONNECT){
                        tear_down_connection(epollfd,socketfd);
                        return false;
                    }
                    //We retried ssl_accept, but this time we guaranteed progressed ssl_stat to at least AWAITING_ACCEPT
                    return true;
                }
                return true;
            case SSLStatus::AWAITING_ACCEPT:
                connection_info.ssl_stat = SSLUtils::try_ssl_accept(connection_info.ssl);
                return true;
            case SSLStatus::FATAL_ERROR_ACCEPT_CONNECT:
                tear_down_connection(epollfd,socketfd);
                return false;

            //Server as already finished handshake (SSLStatus::ACCEPTED)->
            default:
                break;
        }
        //If we exit out of the switch (i.e. without returning), our event occured on a perfectly fine SSL-using connection.
        //Skip after the next large else case to proceed with normal socket input handeling. :)
    }
    else{
        bool is_socket_still_up{};
        switch (connection_info.ssl_stat)
        {
            //Client still needs to finish SSL handshake for the next few cases

            case SSLStatus::HANDSHAKE_CLIENT_READ_CERT:
                //length prefixed ssl certificate is buffered on serverside since accept_new_connection. Simply read flush it    
                is_socket_still_up = flush_recvbuf(socketfd,connection_info,epollfd);
                if(!is_socket_still_up){
                    //Connection got torn down due to error(s) on certificate reception. Abort connecting.
                    return false;
                }

                //TODO: Perform heavy lifting (certificate validation, persistent storage)
                return true;
            case SSLStatus::AWAITING_CONNECT:
                connection_info.ssl_stat = SSLUtils::try_ssl_connect(connection_info.ssl);
                return true;
            case SSLStatus::FATAL_ERROR_ACCEPT_CONNECT:
                tear_down_connection(epollfd,socketfd);
                return false;
            //Client as already finished handshake (SSLStatus::CONNECTED)->
            default:
                break;
        }

    }
    
    std::cout << "Received new request." << std::endl;
    std::array<unsigned char, 4096> recv_buf{};
    int bytes_read_this_time = 0;
    
    auto &connection_buffer = connection_map.at(socketfd).receive_bytes;
    while (true) {
        // This loop is used in order to pull all bytes that
        // reside already on this machine in the kernel socket buffer.
        // once this exausts, we try processing.
        auto bytes_read = read(socketfd, recv_buf.data(), recv_buf.size());
        bytes_read_this_time += bytes_read;

        // If read -> 0: Partner has closed
        //      -> If we read data here, we need to process it
        //      -> If we didn't read data here, that means we already processed what was send last time we were here
        // If read -> -1 && errno == EWOULDBLOCK: Partner has not closed but no more data
        // (probably expects an answer -> try processing)
        if ( bytes_read == 0 && bytes_read_this_time != 0 ||
            (bytes_read == -1 && errno == EWOULDBLOCK) ) {
            ProcessingStatus processing_status = try_processing(socketfd);
            std::cout << "Processing finished: " << processing_status
                    << std::endl;
            if (processing_status == ProcessingStatus::ERROR) {
                std::cerr << "Had error with processing. Closing channel to e.g. unreachable peer." << std::endl;
                remove_client(epollfd, socketfd);
                return false;
            } else if (processing_status == ProcessingStatus::PROCESSED_AND_CLOSE) {
                remove_client(epollfd, socketfd);
                return false;
            }
            return true;
        } else if (bytes_read_this_time == 0 || bytes_read == -1 ) {
            remove_client(epollfd, socketfd);
            return false;
        }
        connection_buffer.insert(connection_buffer.end(), recv_buf.begin(),
                                    recv_buf.begin() + bytes_read);

        std::cout << std::string_view(reinterpret_cast<const char *>(recv_buf.data()), bytes_read) << "\n";
    }

}


// Network/Socket functions

int setup_epollin(int epollfd, socket_t serversocket) {
    auto epollEvent = epoll_event{};
    epollEvent.events = EPOLLIN;
    epollEvent.data.fd = serversocket;
    epoll_ctl(epollfd, EPOLL_CTL_ADD, serversocket, &epollEvent);
    return epollfd;
}

socket_t setup_server_socket(u_short port) {
    static constexpr int ONE = 1;
    socket_t serversocket = socket(AF_INET6, SOCK_STREAM, 0);

    setsockopt(serversocket, SOL_SOCKET, SO_REUSEPORT, &ONE, sizeof(ONE));
    setsockopt(serversocket, SOL_SOCKET, SO_KEEPALIVE, &ONE, sizeof(ONE));

    sockaddr_in6 sock_addr;
    sock_addr.sin6_family = AF_INET6;
    sock_addr.sin6_port = htons(port);
    sock_addr.sin6_addr = in6addr_any;
    if (bind(serversocket, reinterpret_cast<sockaddr *>(&sock_addr),sizeof(sock_addr)) < 0) {
        std::cerr << "Failed to bind port " << port << ". Try to pass a different port." << std::endl;
    }
    listen(serversocket, 128);
    return serversocket;
}

socket_t setup_connect_socket(int epollfd, const in6_addr& address, u_int16_t port, const ConnectionType connection_type) {
    socket_t peer_socket = socket(AF_INET6, SOCK_STREAM, 0);
    if (peer_socket == -1) {
        std::cerr << "Failed to create client socket on port " << port << "." << std::endl;
        return -1;
    }

    sockaddr_in6 addr{};
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(port);
    addr.sin6_addr = address;

    static constexpr int ONE = 1;
    setsockopt(peer_socket, SOL_SOCKET, SO_KEEPALIVE, &ONE, sizeof(ONE));

    ConnectionInfo connection_info{};
    connection_info.connection_type = connection_type;
    connection_info.role = ConnectionRole::CLIENT;
    connection_info.client_addr = address;
    connection_info.client_port = addr.sin6_port;

    if (connect(peer_socket, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) == -1) {
        std::cerr << "Couldn't connect to peer." << std::endl;
        close(peer_socket);
        return -1;
    }
    #ifdef VERBOSE
    std::cout << "Connected socket to " << ip_to_string(connection_info.client_addr) << ":" << connection_info.client_port << std::endl;
    #endif



    int flags = fcntl(peer_socket, F_GETFL, 0);
    if (!(flags & O_NONBLOCK)) {
        flags |= O_NONBLOCK;
    }
    fcntl(peer_socket, F_SETFL, flags);

    connection_map[peer_socket] = connection_info;
    auto &connection_info_emplaced = connection_map[peer_socket];

    //Inject SSL-Code.
    if(connection_type == ConnectionType::P2P){
        #ifdef VERBOSE
        std::cout << "Setting up SSL for outgoing client connection (we are client)" << std::endl; 
        #endif

        SSL* ssl = SSL_new(SSLConfig::client_ctx);
        connection_info_emplaced.ssl = ssl;
        connection_info_emplaced.ssl_stat = SSLStatus::HANDSHAKE_CLIENT_READ_CERT;

        if(!ssl){
            std::cerr << "Failure Client: SSL object null pointer" << std::endl;
            tear_down_connection(epollfd,peer_socket);
            return -1;
        }
        SSL_set_fd(ssl, peer_socket);

        #ifdef VERBOSE
        SSLUtils::check_ssl_blocking_mode(ssl);
        #endif

        #ifdef VERBOSE
        std::cout << "Receiving length-prefixed Server-Certificate over insecure TCP channel" << std::endl;
        #endif


        unsigned char * foreign_cert_str = nullptr;
        uint32_t cert_len{0};
        //Do heavy lifting certificate storage logic
        bool socket_still_alive = receive_prefixed_sendbuf_in_charptr(epollfd, peer_socket, connection_info_emplaced, foreign_cert_str, cert_len);
        if(!socket_still_alive){
            tear_down_connection(epollfd,peer_socket);
            return -1;
        }
        if(!foreign_cert_str){
            return peer_socket;
        }

        X509 * foreign_certificate = SSLUtils::load_cert_from_char(foreign_cert_str,cert_len);
        free(foreign_cert_str);


        //Save foreign cert str
        unsigned char received_id[KEY_SIZE];
        if(!SSLUtils::extract_custom_id(foreign_certificate,received_id)){
            std::cerr << "Failed to extract IPv6 from certificate." << std::endl;
        }

        
        std::string hex_id = Utils::bin_to_hex(received_id, KEY_SIZE);
        #ifdef VERBOSE
        std::cout << "Hex ID received in certificate is:" << hex_id << std::endl;
        #endif

        std::string ipv6_str{};
        if(!SSLUtils::extract_ipv6_from_cert(foreign_certificate,ipv6_str)){
            std::cerr << "Failed to extract IPv6 from certificate." << std::endl;
        }
        if (SSLConfig::cert_map.find(hex_id) != SSLConfig::cert_map.end()) {
            std::cout << "Certificate already recognized." << std::endl;
            //TODO compare certificates
            //Reject, if not matching and original peer is still reachable. --> RPC_Ping.
        }
        else{
            // Add the new certificate to the map
            BIO *bio = BIO_new(BIO_s_mem());
            PEM_write_bio_X509(bio, foreign_certificate);
            int cert_len = BIO_pending(bio);
            char* cert_pem = (char*)malloc(cert_len + 1);
            BIO_read(bio, cert_pem, cert_len);
            cert_pem[cert_len] = '\0';
            BIO_free(bio);

            SSLConfig::cert_map[hex_id] = std::pair{addr.sin6_port,std::string(cert_pem)};
            free(cert_pem);
        }
        
        if (X509_STORE_add_cert(SSLConfig::client_cert_store, foreign_certificate) != 1) {
            std::cerr << "Failed to add certificate to trusted store." << std::endl;
            // Handle error or exit as needed
        }

        SSLStatus ssl_stat = SSLUtils::try_ssl_connect(ssl);
        connection_info_emplaced.ssl_stat = ssl_stat;
        if (ssl_stat == SSLStatus::FATAL_ERROR_ACCEPT_CONNECT) {
            tear_down_connection(epollfd,peer_socket);
            return -1;
        }
    }
    
    return peer_socket;
}

//SSL functions:

void prepare_SSL_Config(in_port_t host_p2p_port){
    
    SSLConfig::id = routing_table.get_local_node().id;

    //Create certificate map file. File name is "cert_map_s_<P2PPort>.txt".
    //This way, no race condition to file names, as the ports are unique.
    std::string port_string = std::to_string(host_p2p_port);
    SSLConfig::certmap_filename = "cert_map_s_" + port_string + ".txt";
    SSLConfig::cert_map = CertUtils::load_certificate_map(SSLConfig::certmap_filename);

    //1. Init SSL library
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    
    //Generate Key-pair for signing certificates and DHKE
    SSLConfig::pkey = KeyUtils::generate_rsa_key();
    if (!SSLConfig::pkey) {
        std::cerr << "Failed to generate RSA key pair" << std::endl;
        exit(EXIT_FAILURE);
    }

    #ifdef VERBOSE
    std::cout << "Generated Kademlia-ID as hex: ";
    Utils::print_hex(SSLConfig::id.data(), 32);
    #endif

    //Retrieve own IPv6 ip to include in certificate:

    if(!NetworkUtils::getIPv6(SSLConfig::ipv6_buf,sizeof(SSLConfig::ipv6_buf))){
        std::cerr << "Failed to retrieve own IPv6 address" << std::endl;
        EVP_PKEY_free(SSLConfig::pkey);
        exit(EXIT_FAILURE);
    }

    //Generate self-signed certificate

    SSLConfig::cert = CertUtils::create_self_signed_cert(SSLConfig::pkey, SSLConfig::ipv6_buf,reinterpret_cast<const char*>(SSLConfig::id.data()));
    if(!SSLConfig::cert){
        std::cerr << "Failed to generate self-signed X509 certificate" << std::endl;
        EVP_PKEY_free(SSLConfig::pkey);
        exit(EXIT_FAILURE);
    }
    

    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(bio, SSLConfig::cert);
    int cert_len = BIO_pending(bio);
    uint32_t net_length = htonl(cert_len);  // Convert length to network byte order

    //Allocate [<lengthprefix><certificate>] bytes.    [ ] <-- describes the extent of malloc.
    SSLConfig::length_prefixed_cert_str = (unsigned char*)malloc(sizeof(net_length) + cert_len);

    //Save the <lengthprefix>
    std::memcpy(SSLConfig::length_prefixed_cert_str, &net_length, sizeof(net_length));

    //Save the <certificate> after the <lengthprefix>
    BIO_read(bio, SSLConfig::length_prefixed_cert_str + sizeof(net_length), cert_len);
    BIO_free(bio);

    // Save the private key and certificate to files
    KeyUtils::save_private_key(SSLConfig::pkey, "private_key_" + port_string + ".pem");
    KeyUtils::save_public_key(SSLConfig::pkey, "public_key_" + port_string + ".pem"); //Optional, could be derived
    CertUtils::save_certificate(SSLConfig::cert, "certificate_" + port_string + ".pem");

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


void sig_c_handler(int signal){
    if(signal == SIGINT){
        clean_up_SSL_Config();
        exit(0);
    }
}

#ifndef TESTING
    int main(int argc, char const *argv[])
    {
        /* Ports/Arguments:
         * 1. host ip (if using ipv4, currently only compatible with network local IP address to not have a problem with NAT, e.g. 192.168.0.x)
         * 2. host port for module API server
         * 2. host port for p2p server
         * 3. to join existing network: pass peer ip and port for p2p contact point
        */


        std::string host_address_string = {};
        struct in6_addr host_address{};
        u_short host_module_port = ServerConfig::MODULE_API_PORT;
        u_short host_p2p_port = ServerConfig::P2P_PORT;

        // Peer to connect to as first contact
        u_short peer_port = 0;
        std::string peer_address_string = {};
        struct in6_addr peer_address{};

        bool connect_to_existing_network = true;

        std::string help_description = "Run a DHT peer with local storage.\n\n"
                    "Multiple API clients can connect to this same instance.\n"
                    "To connect to an existing network, provide the ip address and port of a peer, otherwise a new network will be created.";
        std::string options_description = "dht_server [-h|--help] | [-a|--host-address <host-address>] [-m|--module-port <module-port>] "
                    "[-p|--p2p-port <p2p-port>] [[-A|--peer-address <peer-address>] [-P|--peer-port <peer-port>]]\n\n"
                    "Example usages:\n"
                    "Start new p2p network on 192.168.0.42:7402\n"
                    "\tdht_server -a 192.168.0.42 -m 7401 -p 7402\n"
                    "Connect to p2p network on 192.168.0.42:7402 from 192.168.0.69:7404, accepting requests on port 7403\n"
                    "\tdht_server -a 192.168.0.69 -m 7403 -p 7404 -A 192.168.0.42 -P 7402\n";

        try
        {
            // Argument parsing:
            // Use boost::program_options for parsing:
            progOpt::options_description desc{help_description + options_description};
            desc.add_options()("help,h", "Help screen")
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

            if (vm.count("help"))
            {
                std::cout << desc << "\n";
                return 0;
            }

            if (vm.count("unreg")) {
                std::cout << options_description << "\n";
                return 1;
            }

            if (host_module_port == host_p2p_port) {
                std::cerr << "Cannot setup Module API server and P2P server on the same port (" << host_module_port << "). Exiting." << std::endl;
                return -1;
            }
            std::cout << "Modules reach this server on " << host_address_string << ":" << host_module_port << std::endl;
            std::cout << "We communicate with peers on " << host_address_string << ":" << host_p2p_port << std::endl;
            if (system(("ping -c1 -s1 " + host_address_string + "  > /dev/null 2>&1").c_str()) != 0) {
                std::cerr << "Warning: Failed to ping host." << std::endl;
            }

            if (vm.count("peer-address") && vm.count("peer-port")) {
            std::cout << "Trying to connect to existing Network Node " << peer_address_string << ":" << peer_port << std::endl;
                if (!convert_to_ipv6(peer_address_string, peer_address)) {
                    std::cerr << "Please provide a syntactically correct IP address (v4 or v6) for the peer";
                    return 1;
                }
                if (system(("ping -c1 -s1 " + peer_address_string + "  > /dev/null 2>&1").c_str()) != 0) {
                    std::cerr << "Warning: Failed to ping peer." << std::endl;
                }
            } else {
                std::cout << "Since no peer to connect to was supplied, setting up new network..." << std::endl;
                connect_to_existing_network = false;
            }

        // Parsing complete
    }
    catch (std::exception excep)
    {
        // passed invalid arguments, e.g. ip to port or similar
        std::cerr << "Passed invalid arguments. Keep to correct formatting, format IPv4 addresses as 192.168.0.42 and ports separated by space." << std::endl;
        std::cout << options_description << "\n";
        return -1;
    }

    if (!convert_to_ipv6(host_address_string, host_address)) {
        std::cerr << "Please provide a syntactically correct IP address (v4 or v6) for the host\n";
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
    



    // Ignore SIGPIPE (if socket gets closed by remote peer, we might accidentally write to a broken pipe)
    signal(SIGPIPE, SIG_IGN);
    std::signal(SIGINT,sig_c_handler);

    // Open port for local API traffic from modules
    socket_t module_api_socket = setup_server_socket(host_module_port);
    main_epollfd = epoll_create1(0);
    main_epollfd = setup_epollin(main_epollfd, module_api_socket);
    socket_t p2p_socket = setup_server_socket(host_p2p_port);
    main_epollfd = setup_epollin(main_epollfd, p2p_socket);
    std::vector<epoll_event> epoll_events{64};

    if (main_epollfd == -1 || module_api_socket == -1 || p2p_socket == -1) {
        std::cerr << "Error creating sockets. Aborting." << std::endl;
        return 1;
    }

    //Generate everything necessary for SSL. See ssl.cpp/ssl.h

    prepare_SSL_Config(host_p2p_port);


    std::cout << "Server running... " << std::endl;
    bool server_is_running = true;
    if(connect_to_existing_network) {
        // TODO: connect to existing network
        // TODO: setup socket + add to connection_map, then call:
        std::cout << "Sending Find Node Request..." << std::endl;
        socket_t peer_socket = setup_connect_socket(main_epollfd, peer_address, peer_port, ConnectionType::P2P);

        setup_epollin(main_epollfd, peer_socket);
        if (peer_socket == -1) {
            std::cerr << "Error creating socket. Aborting." << std::endl;
            return -1;
        }

        forge_DHT_RPC_find_node(peer_socket, routing_table.get_local_node().id);
        // 1. Send FIND_NODE RPC about our own node to peer (TODO: Don't immediately put our triple in peer's bucket list or else it won't return closer peers but us?)
        // 3. If response includes our own, we have no closer nodes, otherwise we get closer nodes to us
        // 4. Iterate over ever closer nodes
        // 5. Meanwhile, populate K_Buckets with ever closer nodes
        // 6. For Nodes farther away, do "refreshing" of random NodeID's in the respective ranges
        //    (choose closest nodes and send them find_node rpcs with the randomly generated NodeID's in said range)

    }

    // event loop

    while (server_is_running) {
        int event_count = epoll_wait(main_epollfd, epoll_events.data(), std::ssize(epoll_events), -1);  // dangerous cast
        // TODO: ADD SERVER MAINTAINENCE. purge storage (ttl), peer-ttl (k-bucket
        // maintainence) internal management clean up local_storage for all keys,
        // std::erase if ttl is outdated

        if (event_count == -1) {
            if (errno == EINTR) { // for debugging purposes
                continue;
            }
            std::cout << "epoll had the error " << errno << std::endl;
            server_is_running = false;
            break;
        }
        for (int i = 0; i < event_count; ++i) {
            const epoll_event &current_event = epoll_events[i];
            if (current_event.data.fd == module_api_socket) {
                accept_new_connection(main_epollfd, current_event, ConnectionType::MODULE_API);
            } else if (current_event.data.fd == p2p_socket) {
                accept_new_connection(main_epollfd, current_event, ConnectionType::P2P);
            } else {
                bool socket_still_valid = true;
                // handle client processing of existing sessions
                if (current_event.events & EPOLLIN)
                    socket_still_valid = handle_EPOLLIN(main_epollfd,current_event);
                if (socket_still_valid && current_event.events & EPOLLOUT)
                    handle_EPOLLOUT(main_epollfd,current_event.data.fd);
                if (socket_still_valid && current_event.events & EPOLLERR){
                    tear_down_connection(main_epollfd,current_event.data.fd);
                }
            }
        }
    }

    std::cout << "Server terminating. " << server_is_running << std::endl;
    return 0;
}
#endif