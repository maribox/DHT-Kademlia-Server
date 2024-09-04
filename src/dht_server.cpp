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
static constexpr size_t MAX_LIFETIME_SEC = 20*60; // 20 minutes in seconds
static constexpr size_t MIN_LIFETIME_SEC = 3*60;  //  3 minutes in seconds
static constexpr size_t DEFAULT_LIFETIME_SEC = 5*60; // 5 minutes in seconds

static constexpr size_t MAX_REPLICATION = 30;
static constexpr size_t MIN_REPLICATION = 3;
static constexpr size_t DEFAULT_REPLICATION = 20; // should be same to K


std::map<Key,std::pair<std::chrono::time_point<std::chrono::system_clock>, Value>> local_storage{};
std::mutex storage_lock;

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
            //std::cout << "Converted address "  << address_string  << " to " << address_converted << std::endl;
        } catch (...) {
            std::cerr << "Converted address " << address_string  << " but couldn't format." << std::endl;
        }
        return true;
    }
    return false;  // Invalid address
}

std::string key_to_string(const Key &key) {
    std::string str{};

    for (auto it = key.cbegin() ; it < key.cend(); it++) {
        str += static_cast<char>(*it);
    }
    return str;
}

std::string ip_to_string(const in6_addr& ip) {
    char ip_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ip, ip_str, sizeof(ip_str));
    return {ip_str};
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

//Returns the number of deleted elements.
size_t purge_local_storage(){
        while(true){
        {
            {
                std::lock_guard<std::mutex> lock (storage_lock);
                    auto time_to_purge = std::chrono::system_clock::now();
                    for(auto &[key,time_value_pair] : local_storage){
                        auto &[time,value] = time_value_pair;
                        if(time >= time_to_purge){
                            continue;
                        }
                        local_storage.erase(key);
                    }
            }
            std::this_thread::sleep_for(std::chrono::seconds(MIN_LIFETIME_SEC/2));
        }
    }
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

        #ifdef TCP_VERBOSE
            std::cout << "Tore down connection running over port: " << connection_info.client_port << "." << std::endl;
        #endif

    }else{
        //Should be a dead branch:
        #ifdef TCP_VERBOSE
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
        bytes_flushed = SSL_read(ssl,temp_buffer.data(),temp_buffer.size());

        if(bytes_flushed > 0){
            //Append bytes to recvbuf
            recvbuf.insert(std::end(recvbuf),std::begin(temp_buffer),std::begin(temp_buffer) + bytes_flushed);
            temp_buffer.erase(std::begin(temp_buffer),std::begin(temp_buffer) + bytes_flushed);
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
            temp_buffer.erase(std::begin(temp_buffer),std::begin(temp_buffer) + bytes_flushed);
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
        #ifdef KADEMLIA_VERBOSE
        std::cout << "Got contacted by new peer reachable at " << ip_to_string(peer.addr) << ":" << sender_port << std::endl;
        #endif
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

void send_DHT_message(socket_t socketfd, const Message &message, int epollfd) {
    if (!message.empty()) {
        write_vector_to_sendbuf(connection_map[socketfd], message);
    }
    // will be sent with next epoll wait

    if (epollfd == -1) {
        epollfd = main_epollfd;
    }
    /*
    epoll_event event{};
    event.events = EPOLLIN | EPOLLOUT;
    event.data.fd = socketfd;
    epoll_ctl(epollfd, EPOLL_CTL_MOD, socketfd, &event);
    */
}

bool check_rpc_id(const Message &message, const Key &correct_rpc_id) {
    Key rpc_id;
    read_body(message, NODE_ID_SIZE + 2, rpc_id.data(), 32);
    if (rpc_id != correct_rpc_id) {
        std::cerr << "Got message with invalid rpc-id!" << std::endl;
        return false;
    }
    return true;
}

// crawling

bool process_answers(int epollfd, P2PType expected_type, std::function<bool(socket_t, u_short)> handle_answer, size_t expected_responses = 1) {
    std::vector<epoll_event> epoll_events{64};

    while(expected_responses > 0) {
        int event_count = epoll_wait(epollfd, epoll_events.data(), std::ssize(epoll_events), 5000);
        if (event_count != -1) {
            for (int i = 0; i < event_count; i++) {
                auto current_event = epoll_events[i];
                if (!(current_event.events & EPOLLIN)) {
                    continue;
                }
                if (!read_EPOLLIN(epollfd, current_event)) {
                    continue;
                }

                socket_t sockfd = epoll_events[i].data.fd;
                if (!connection_map.contains(sockfd)) {
                    continue;
                }
                auto& connection_info = connection_map[sockfd];

                u_short message_size = -1;
                u_short dht_type = -1;

                bool header_success = parse_header(connection_info, message_size, dht_type);
                if (header_success && dht_type == expected_type) {
                    if (!handle_answer(sockfd, message_size - HEADER_SIZE)) {
                        continue;
                    }

                    expected_responses--;
                    // potential error source when multiple responses from same source (shouldn't happen, but could)
                    close(sockfd);
                    connection_map.erase(sockfd);
                }
            }
        } else {
            return false;
        }
    }
    return true;
}

std::vector<Node> blocking_node_lookup(Key &key, size_t number_of_nodes) {
    std::vector<Node> closest_nodes = routing_table.find_closest_nodes(key);
    std::set<Node> returned_nodes{};
    int epollfd = epoll_create1(0);
    std::set<Node> previous_k_closest_nodes{};


    //std::cout << "Trying to find neighbours of a key starting with '"
    //        << std::hex << key[0] << key[1] << "'... " << std::dec << std::endl;

    while (true) {
        // TODO
        bool found_new_nodes = false;

        for (const auto& node : closest_nodes) {
            if (!previous_k_closest_nodes.contains(node)) {
                found_new_nodes = true;
                previous_k_closest_nodes.insert(node);
                if (previous_k_closest_nodes.size() >= K) {
                    break;
                }
            }
        }
        if (!found_new_nodes) {
            break;
        }

        int expected_answers = 0;

        if (closest_nodes.size() > ALPHA) {
            closest_nodes.resize(ALPHA);
        }

        for (auto& node: closest_nodes) {
            if (node.port != 0 && node != routing_table.get_local_node()) {
                socket_t peer_socket = setup_connect_socket(epollfd, node.addr, node.port, ConnectionType::P2P);
                if (peer_socket != -1) {
                    setup_epollin(epollfd, peer_socket);
                    if (!ensure_tls_blocking(peer_socket)) {
                        routing_table.remove(node);
                        continue;
                    }
                    auto sent = forge_DHT_RPC_find_node(peer_socket, epollfd, key);
                    auto [is_socket_still_up ,everything_was_sent] = flush_sendbuf(peer_socket, connection_map[peer_socket], epollfd);
                    if (is_socket_still_up && everything_was_sent) {
                        expected_answers++;
                    } else {
                        routing_table.remove(node);
                    }
                } else {
                    routing_table.remove(node);
                }
            }
        }


        auto handle_answer = [&](socket_t sockfd, u_short message_size) {
            return handle_DHT_RPC_find_node_reply(sockfd, message_size, &returned_nodes);
        };

        process_answers(epollfd, P2PType::DHT_RPC_FIND_NODE_REPLY, handle_answer, expected_answers);

        for (const auto& node : returned_nodes) { // add new nodes to closest nodes
            if (std::ranges::find(closest_nodes, node) == closest_nodes.end()) {
                closest_nodes.push_back(node);
            }
        }

        returned_nodes.clear();

        std::ranges::sort(closest_nodes,
                          [key](const Node& node_1, const Node& node_2){return RoutingTable::node_distance(node_1.id, key) < RoutingTable::node_distance(node_2.id, key);}
        );
    }

    //std::cout << "Lookup completed. Found " << closest_nodes.size() << " closest nodes." << std::endl;
    return closest_nodes;
}

void crawl_blocking_and_store(Key &key, Value &value, const int time_to_live, int replication) {
    auto k_closest_nodes = blocking_node_lookup(key, replication);

    for (auto& node : k_closest_nodes) {
        if (node.port == 0) {
            continue;
        }

        if (node == routing_table.get_local_node()) {
            #ifdef KADEMLIA_VERBOSE
            std::cout << "Stored key '" << key_to_string(key) << "' with value '" << value.data() << "' to own storage" << std::endl;
            #endif
            save_to_storage(key, std::chrono::seconds(time_to_live), value);
            continue;
        }

        socket_t sockfd = -1;
        /* Commented out for compilation. setup_connect_socket now needs an epoll instance...
        *socket_t sockfd = setup_connect_socket(node.addr, node.port, ConnectionType::P2P);
        */
        if (sockfd != -1) {
            forge_DHT_RPC_store(sockfd, main_epollfd, time_to_live, key, value);
        }
    }
}

void crawl_blocking_and_return(Key &key, socket_t socket) {
    auto k_closest_nodes = blocking_node_lookup(key);

    auto found_values = std::vector<Value>{};
    int epollfd = epoll_create1(0);
    size_t expected_answers = 0;
    for (auto& node : k_closest_nodes) {
        if (node.port == 0) {
            continue;
        }

        if (node == routing_table.get_local_node()) {
            #ifdef KADEMLIA_VERBOSE
            std::cout << "Trying to get key '" << key_to_string(key) << "' from own storage" << std::endl;
            #endif
            if (const Value* value = get_from_storage(key)) {
                found_values.push_back(*value);
            }
            continue;
        }

        #ifdef KADEMLIA_VERBOSE
        std::cout << "sending request to other node" << std::endl;
        #endif

        socket_t sockfd = setup_connect_socket(epollfd, node.addr, node.port, {ConnectionType::P2P});
        socket_t peer_socket = setup_connect_socket(epollfd, node.addr, node.port, ConnectionType::P2P);
        if (peer_socket != -1) {
            setup_epollin(epollfd, peer_socket);
            if (!ensure_tls_blocking(peer_socket)) {
                routing_table.remove(node);
                continue;
            }
            auto sent = forge_DHT_RPC_find_node(peer_socket, epollfd, key);
            auto [is_socket_still_up ,everything_was_sent] = flush_sendbuf(peer_socket, connection_map[peer_socket], epollfd);
            if (is_socket_still_up && everything_was_sent) {
                expected_answers++;
            } else {
                routing_table.remove(node);
            }
        } else {
            routing_table.remove(node);
        }
    }

    auto handle_answer = [&](socket_t sockfd, u_short message_size) {
        return handle_DHT_RPC_find_value_reply(sockfd, message_size, &found_values);
    };

    process_answers(epollfd, P2PType::DHT_RPC_FIND_VALUE_REPLY, handle_answer, expected_answers);

    std::map<Value, int> frequency;
    for (auto& value : found_values) {
        frequency[value]++;
    }

    if (!found_values.empty()) {
        auto most_frequent_element = std::ranges::max_element(frequency,
                                                    [](const std::pair<Value, int>& a, const std::pair<Value, int>& b) {
                                                                  return a.second < b.second;
                                                              })->first;
        forge_DHT_success(socket, main_epollfd, key, most_frequent_element);
    } else {
        forge_DHT_failure(socket, main_epollfd, key);
    }
}

// Module API functions handling+construction functions

bool forge_DHT_put(socket_t socket, Key &key, Value &value) {
    return true;
}

bool handle_DHT_put(socket_t socket, u_short body_size) {
    const Message& message = connection_map[socket].receive_bytes;
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

    std::thread([key, value, time_to_live, replication]() mutable {
        crawl_blocking_and_store(key, value, time_to_live, replication);
    }).detach();
    return true;
}

bool forge_DHT_get(socket_t socket, Key &key) {
    return true;
}

bool handle_DHT_get(socket_t socket, u_short body_size) {
    if (body_size != KEY_SIZE) {
        return false;
    }
    const Message& message = connection_map[socket].receive_bytes;
    Key key;
    read_body(message, 0, key.data(), KEY_SIZE);
    #ifdef KADEMLIA_VERBOSE
    std::cout << "Got request to get key " << key_to_string(key) << std::endl;
    #endif
    std::thread([key, socket]() mutable {
        crawl_blocking_and_return(key, socket);
    }).detach();
    return true;
}

bool forge_DHT_success(socket_t socket, int epollfd, const Key &key, const Value &value) {
    size_t message_size = HEADER_SIZE + KEY_SIZE + value.size();
    Message message(message_size);

    build_DHT_header(message, message_size, DHT_SUCCESS);
    write_body(message, 0, key.data(), KEY_SIZE);
    write_body(message, KEY_SIZE, value.data(), value.size());
    //TODO: Pass epollfds to methods that write.
    send_DHT_message(socket, message, epollfd);
    return true;
}

bool handle_DHT_success(socket_t socket, u_short body_size) {
    return false;
}

bool forge_DHT_failure(socket_t socket, int epollfd, Key &key) {
    size_t message_size = HEADER_SIZE + KEY_SIZE;
    Message message(message_size);

    build_DHT_header(message, message_size, DHT_FAILURE);
    write_body(message, 0, key.data(), KEY_SIZE);

    send_DHT_message(socket, message, epollfd);
    return true;
}

bool handle_DHT_failure(socket_t socket, u_short body_size) {
    return false;
}


// P2P/RPC handling+construction functions

bool forge_DHT_RPC_ping(socket_t socket, int epollfd) {
    Key rpc_id = generate_random_nodeID();
    connection_map.at(socket).rpc_id = rpc_id;

    size_t body_size = RPC_SUB_HEADER_SIZE;
    size_t message_size = HEADER_SIZE  + body_size;
    u_short message_type = DHT_RPC_PING;
    Message message(message_size);

    build_DHT_header(message, message_size, message_type);
    build_RPC_header(message, rpc_id);

    send_DHT_message(socket, message, epollfd);
    return true;
}

bool handle_DHT_RPC_ping(const socket_t socket, int epollfd, const u_short body_size) {
    const Message& message = connection_map[socket].receive_bytes;
    Key rpc_id = read_rpc_header(message, connection_map[socket].client_addr);
    forge_DHT_RPC_ping_reply(socket, epollfd, rpc_id);
    return true;
}

bool forge_DHT_RPC_ping_reply(socket_t socket, int epollfd, Key rpc_id) {
    size_t body_size = RPC_SUB_HEADER_SIZE;
    size_t message_size = HEADER_SIZE + body_size;
    u_short message_type = DHT_RPC_PING_REPLY;
    Message message(message_size);

    build_DHT_header(message, message_size, message_type);
    build_RPC_header(message, rpc_id);

    send_DHT_message(socket, message, epollfd);
    return true;
}

bool handle_DHT_RPC_ping_reply(const socket_t socket, const u_short body_size, std::set<socket_t>* successfully_pinged_sockets) {
    const Message& message = connection_map[socket].receive_bytes;
    if (!check_rpc_id(message, connection_map[socket].rpc_id)) {
        return false;
    }
    if (successfully_pinged_sockets) {
        successfully_pinged_sockets->insert(socket);
    }
    return true;
}

bool forge_DHT_RPC_store(socket_t socket, int epollfd, u_short time_to_live, Key &key, Value &value) {
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
    write_body(message, RPC_SUB_HEADER_SIZE + 2, key.data(), KEY_SIZE);
    write_body(message, RPC_SUB_HEADER_SIZE + 2 + KEY_SIZE, value.data(), value.size());

    send_DHT_message(socket, message, epollfd);
    return true;
}

bool handle_DHT_RPC_store(const socket_t socket, const u_short body_size) {
    if (body_size <= RPC_SUB_HEADER_SIZE + 4 + KEY_SIZE) {
        return false;
    }
    const Message& message = connection_map[socket].receive_bytes;
    const u_short value_size = body_size - (RPC_SUB_HEADER_SIZE + 4 + KEY_SIZE);

    const Key rpc_id = read_rpc_header(message, connection_map[socket].client_addr);

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

    return forge_DHT_RPC_store_reply(socket, main_epollfd, rpc_id, key, value);
}

bool forge_DHT_RPC_store_reply(socket_t socket, int epollfd, Key rpc_id, Key &key, Value &value) {
    size_t body_size = RPC_SUB_HEADER_SIZE + KEY_SIZE + value.size();;
    size_t message_size = HEADER_SIZE + body_size;
    u_short message_type = DHT_RPC_STORE_REPLY;
    Message message(message_size);

    build_DHT_header(message, message_size, message_type);
    build_RPC_header(message, rpc_id);

    write_body(message, RPC_SUB_HEADER_SIZE, key.data(), KEY_SIZE);
    write_body(message, RPC_SUB_HEADER_SIZE + KEY_SIZE, value.data(), value.size());

    send_DHT_message(socket, message, epollfd);
    return true;
}

bool handle_DHT_RPC_store_reply(const socket_t socket, const u_short body_size) {
    if (body_size <= RPC_SUB_HEADER_SIZE + KEY_SIZE) {
        return false;
    }
    const Message& message = connection_map[socket].receive_bytes;
    if (!check_rpc_id(message, connection_map[socket].rpc_id)) {
        return false;
    }

    Value sent_value;
    size_t bytes_before_key = HEADER_SIZE + RPC_SUB_HEADER_SIZE + 4;
    size_t bytes_before_value = bytes_before_key + KEY_SIZE;
    auto& sent_message = connection_map[socket].send_bytes;

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
        #ifdef KADEMLIA_VERBOSE
        std::cout << "Got back different value than sent value for sent key " << key_to_string(sent_key) << std::endl;
        #endif
    }
    return true;
}

bool forge_DHT_RPC_find_node(socket_t socket, int epollfd, NodeID target_node_id) {
    Key rpc_id = generate_random_nodeID();
    connection_map.at(socket).rpc_id = rpc_id;

    size_t body_size = RPC_SUB_HEADER_SIZE + KEY_SIZE;
    size_t message_size = HEADER_SIZE + body_size;
    u_short message_type = DHT_RPC_FIND_NODE;
    Message message(message_size);

    build_DHT_header(message, message_size, message_type);
    build_RPC_header(message, rpc_id);

    write_body(message, RPC_SUB_HEADER_SIZE, target_node_id.data(), NODE_ID_SIZE);

    send_DHT_message(socket, message, epollfd);
    return true;
}

bool perform_maintenance() {
    int epollfd = epoll_create1(0);
    if (epollfd == -1) {
        std::cerr << "Error creating epollfd. Aborting maintenance." << std::endl;
        return false;
    }
    #ifdef KADEMLIA_VERBOSE
    std::cout << "Performing maintenance..." << std::endl;
    #endif

    size_t expected_answers = 0;
    auto pinged_sockets_map = std::map<socket_t, Node>{};
    for (auto& bucket : routing_table.get_bucket_list()) {
        for (auto& node : bucket.get_peers()) {
            socket_t peer_socket = setup_connect_socket(epollfd, node.addr, node.port, ConnectionType::P2P);
            if (peer_socket != -1) {
                setup_epollin(epollfd, peer_socket);
                if (!ensure_tls_blocking(peer_socket)) {
                    routing_table.remove(node);
                    continue;
                }
                auto sent = forge_DHT_RPC_ping(peer_socket, epollfd);
                auto [is_socket_still_up ,everything_was_sent] = flush_sendbuf(peer_socket, connection_map[peer_socket], epollfd);
                if (is_socket_still_up && everything_was_sent) {
                    pinged_sockets_map[peer_socket] = node;
                    expected_answers++;
                } else {
                    routing_table.remove(node);
                }
            } else {
                routing_table.remove(node);
            }
        }
    }

    std::set<socket_t> successfully_pinged_sockets{};
    auto handle_answer = [&](socket_t sockfd, u_short body_size) {
        return handle_DHT_RPC_ping_reply(sockfd, body_size, &successfully_pinged_sockets);
    };
    bool success = process_answers(epollfd, P2PType::DHT_RPC_FIND_NODE_REPLY, handle_answer, expected_answers);
    if (success) {
        for (auto& [sockfd, node] : pinged_sockets_map) {
            if (!successfully_pinged_sockets.contains(sockfd)) {
                routing_table.remove(node);
            }
        }
        return true;
    } else {
        return false;
    }
}

bool handle_DHT_RPC_find_node(const socket_t socket, const u_short body_size) {
    if (body_size != RPC_SUB_HEADER_SIZE + NODE_ID_SIZE) {
        return false;
    }
    const Message& message = connection_map[socket].receive_bytes;

    Key rpc_id = read_rpc_header(message, connection_map[socket].client_addr);

    NodeID target_node_id;
    read_body(message, RPC_SUB_HEADER_SIZE, target_node_id.data(), NODE_ID_SIZE);

    // find the closest nodes, then return them:
    auto closest_nodes = routing_table.find_closest_nodes(target_node_id);
    #ifdef KADEMLIA_VERBOSE
    std::cout << "Found " << closest_nodes.size() << " nodes and returning them" << std::endl;
    #endif
    return forge_DHT_RPC_find_node_reply(socket, main_epollfd, rpc_id, closest_nodes);
}

bool forge_DHT_RPC_find_node_reply(socket_t socket, int epollfd, Key rpc_id, std::vector<Node> closest_nodes) {
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

    send_DHT_message(socket, message, epollfd);
    return true;
}


bool handle_DHT_RPC_find_node_reply(const socket_t socket, const u_short body_size, std::set<Node>* closest_nodes_ptr, std::mutex* returned_nodes_mutex_ptr) {
    if ((body_size - RPC_SUB_HEADER_SIZE) % NODE_SIZE != 0) {
        return false;
    }
    const size_t num_nodes = (body_size - RPC_SUB_HEADER_SIZE) / NODE_SIZE;

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

    // std::cout << "Got back " << closest_nodes_ptr->size() << " node" << (closest_nodes_ptr->size() != 1 ? "s." : ".") << std::endl;

    if (created_closest_nodes) {
        delete(closest_nodes_ptr);
    }

    return true;
}

bool forge_DHT_RPC_find_value(socket_t socket, int epollfd, Key &key) {
    Key rpc_id = generate_random_nodeID();
    connection_map.at(socket).rpc_id = rpc_id;

    size_t body_size = RPC_SUB_HEADER_SIZE + KEY_SIZE;
    size_t message_size = HEADER_SIZE + body_size;
    u_short message_type = DHT_RPC_STORE;
    Message message(message_size);

    build_DHT_header(message, message_size, message_type);
    build_RPC_header(message, rpc_id);

    write_body(message, RPC_SUB_HEADER_SIZE, key.data(), KEY_SIZE);

    send_DHT_message(socket, message, epollfd);
    return true;
}

bool handle_DHT_RPC_find_value(const socket_t socket, const u_short body_size) {
    if (body_size != RPC_SUB_HEADER_SIZE + KEY_SIZE) {
        return false;
    }
    #ifdef KADEMLIA_VERBOSE
    std::cout << "Was asked to get value..." << std::endl;
    #endif
    const Message &message = connection_map[socket].receive_bytes;

    Key rpc_id = read_rpc_header(message, connection_map[socket].client_addr);
    Key key;
    read_body(message, RPC_SUB_HEADER_SIZE, key.data(), KEY_SIZE);

    auto val_ptr = get_from_storage(key);
    if (val_ptr) {
        return forge_DHT_RPC_find_value_reply(socket, main_epollfd, rpc_id, key, *val_ptr);
    } else {
        auto closest_nodes = routing_table.find_closest_nodes(key);
        return forge_DHT_RPC_find_node_reply(socket, main_epollfd, rpc_id, closest_nodes);
    }
}

bool forge_DHT_RPC_find_value_reply(socket_t socket, int epollfd, Key rpc_id, const Key &key, const Value &value) {
    u_short message_type = DHT_RPC_FIND_VALUE_REPLY;
    size_t body_size = RPC_SUB_HEADER_SIZE + KEY_SIZE + value.size();
    size_t message_size = HEADER_SIZE + body_size;
    Message message(message_size);

    build_DHT_header(message, message_size, message_type);
    build_RPC_header(message, rpc_id);

    write_body(message, RPC_SUB_HEADER_SIZE, key.data(), KEY_SIZE);
    write_body(message, RPC_SUB_HEADER_SIZE + KEY_SIZE, value.data(), value.size());

    send_DHT_message(socket, message, epollfd);
    return true;
}

bool handle_DHT_RPC_find_value_reply(const socket_t socket, const u_short body_size, std::vector<Value>* found_values) {
    if (body_size <= RPC_SUB_HEADER_SIZE + KEY_SIZE) {
        return false;
    }
    const u_short value_size = body_size - (RPC_SUB_HEADER_SIZE + KEY_SIZE);
    const Message& message = connection_map[socket].receive_bytes;

    if (!check_rpc_id(message, connection_map[socket].rpc_id)) {
        return false;
    }

    Key key;
    read_body(message, RPC_SUB_HEADER_SIZE, key.data(), KEY_SIZE);
    Value value{};
    value.resize(value_size);
    read_body(message, RPC_SUB_HEADER_SIZE + KEY_SIZE, value.data(), body_size - (RPC_SUB_HEADER_SIZE + KEY_SIZE));
    if (found_values) {
        found_values->push_back(value);
        return true;
    } else {
        std::cerr << "Received find value reply without forge or without given found_values list" << std::endl;
        return false;
    }
}

bool forge_DHT_error(socket_t socket, int epollfd, ErrorType error) {
    size_t message_size = HEADER_SIZE + 2;
    Message message(message_size);

    build_DHT_header(message, message_size, DHT_ERROR);
    u_short network_order_error = htons(error);
    write_body(message, 0, reinterpret_cast<unsigned char*>(&network_order_error), 2);

    send_DHT_message(socket, message, epollfd);
    return true;
}


bool handle_DHT_error(const socket_t socket, const u_short body_size) {
    if (body_size != 2) {
        return false;
    }
    const Message &message = connection_map[socket].receive_bytes;

    u_short error_type = 0;
    read_body(message, 0, reinterpret_cast<unsigned char *>(error_type), 2);
    error_type = ntohs(error_type);
    const auto addr_string = ip_to_string(connection_map[socket].client_addr) +
                             ":" + std::to_string(connection_map[socket].client_port);
    switch (error_type) {
        case ErrorType::DHT_NOT_FOUND:
            std::cerr << "Received DHT_NOT_FOUND error by " << addr_string <<std::endl;
        break;
        case ErrorType::DHT_BAD_REQUEST:
            std::cerr << "Sent out bad request to " << addr_string << std::endl;
        break;
        case ErrorType::DHT_SERVER_ERROR:
            std::cerr << "Had internal server error with " << addr_string << std::endl;
        break;
        default:
            std::cerr << "Got invalid server error by " << addr_string << std::endl;
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
    try {
        switch (p2p_type) {
            case DHT_RPC_PING:
                return handle_DHT_RPC_ping(socket, main_epollfd, body_size);
            case DHT_RPC_STORE:
                return handle_DHT_RPC_store(socket, body_size);
            case DHT_RPC_FIND_NODE:
                return handle_DHT_RPC_find_node(socket, body_size);
            case DHT_RPC_FIND_VALUE:
                return handle_DHT_RPC_find_value(socket, body_size);
            case DHT_RPC_PING_REPLY:
                return handle_DHT_RPC_ping_reply(socket, body_size, nullptr);
            case DHT_RPC_STORE_REPLY:
                return handle_DHT_RPC_store_reply(socket, body_size);
            case DHT_RPC_FIND_NODE_REPLY:
                return handle_DHT_RPC_find_node_reply(socket, body_size);
            case DHT_RPC_FIND_VALUE_REPLY:
                return handle_DHT_RPC_find_value_reply(socket, body_size, nullptr);
            case DHT_ERROR:
                return handle_DHT_error(socket, body_size);
        }
    } catch (std::exception& _) {
        forge_DHT_error(socket, main_epollfd, DHT_SERVER_ERROR);
        return true;
    }
    return true;
}

// Connection Processing

ProcessingStatus try_processing(socket_t curfd){
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
            std::cerr << "Tried to send invalid request to Module API Server. Aborting." << std::endl;
            return ProcessingStatus::ERROR;
        }

        valid_request = parse_API_request(curfd, message_size-HEADER_SIZE, module_api_type);
    } else if (connection_info.connection_type == ConnectionType::P2P) {
        P2PType p2p_type;
        if (is_valid_P2P_type(dht_type)) {
            p2p_type = static_cast<P2PType>(dht_type);
        } else {
            std::cerr << "Tried to send invalid request to P2P Server. Aborting." << std::endl;
            return ProcessingStatus::ERROR;
        }
        valid_request = parse_P2P_request(curfd, message_size-HEADER_SIZE, p2p_type);
        if (!valid_request) {
            forge_DHT_error(curfd, main_epollfd, DHT_BAD_REQUEST);
        }
    } else {
        std::cerr << "No ConnectionType registered for client. Aborting." << std::endl;
        return ProcessingStatus::ERROR;
    }
    if (byte_count_to_process > message_size) {
        connection_buffer.erase(connection_buffer.begin(), connection_buffer.begin() + message_size);
        return MORE_TO_READ;
    }
    if (valid_request) {
        return ProcessingStatus::PROCESSED;
    } else {
        std::cerr << "Unknown Error with request." << std::endl;
        return ProcessingStatus::ERROR;
    }
}


void accept_new_connection(int epollfd, const epoll_event &cur_event, ConnectionType connection_type) {
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


    #ifdef TCP_VERBOSE
    std::cout << "Accepted socket connection from " << ip_to_string(client_addr.sin6_addr) << ":" << client_port << std::endl;
    #endif


    if(connection_type == ConnectionType::P2P){

        #ifdef SSL_VERBOSE
        std::cout << "Setting up SSL for incoming client connection (we are server)" << std::endl;
        #endif

        SSL* ssl = SSL_new(SSLConfig::server_ctx);
        connection_info.ssl = ssl;

        if(!ssl){
            std::cerr << "Failure Server: SSL object null pointer" << std::endl;
            return;
        }
        SSL_set_fd(ssl, socketfd);

        #ifdef SSL_VERBOSE
        SSLUtils::check_ssl_blocking_mode(ssl);
        #endif

        #ifdef SSL_VERBOSE
        std::cout << "Supplying length-prefixed Server-Certificate over insecure TCP channel" << std::endl;
        #endif

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

//Do heavy lifting certificate storage logic
CertificateStatus receive_certificate_as_client(int epollfd, socket_t peer_socket, ConnectionInfo &connection_info_emplaced){
    if(connection_info_emplaced.role != ConnectionRole::CLIENT){
        tear_down_connection(epollfd,peer_socket);
        return CertificateStatus::ERRORED_CERTIFICATE;
    }
    unsigned char * foreign_cert_str = nullptr;
    uint32_t cert_len{0};
    bool socket_still_alive = receive_prefixed_sendbuf_in_charptr(epollfd, peer_socket, connection_info_emplaced, foreign_cert_str, cert_len);
    
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
        std::cerr << "Failed to extract IPv6 from certificate." << std::endl;
        return CertificateStatus::ERRORED_CERTIFICATE;
    }


    std::string hex_id = Utils::bin_to_hex(received_id, KEY_SIZE);
    #ifdef SSL_VERBOSE
    std::cout << "Hex ID received in certificate is: " << hex_id << std::endl;
    #endif

    std::string ipv6_str{};
    if(!SSLUtils::extract_ipv6_from_cert(foreign_certificate,ipv6_str)){
        std::cerr << "Failed to extract IPv6 from certificate." << std::endl;
        return CertificateStatus::ERRORED_CERTIFICATE;
    }
    if (SSLConfig::cert_map.find(hex_id) != SSLConfig::cert_map.end()) {
        #ifdef SSL_VERBOSE
        std::cout << "Kademlia ID already recognized." << std::endl;
        #endif
        //Compare certificates
        if(SSLUtils::compare_x509_cert_with_pem(foreign_certificate, SSLConfig::cert_map.find(hex_id)->second.second)){
            //Compare yielded equality:
            return CertificateStatus::EXPECTED_CERTIFICATE;
        }else{
            //Compare yielded difference. --> RPC_Ping old connection partner
            //TODO: Maybe leave out because of time reasons. For now, assume that peer is not reachable
            return CertificateStatus::KNOWN_CERTIFICATE_CONTENT_MISMATCH;
        }
    }
    
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
        std::cerr << "Failed to add certificate to trusted store." << std::endl;
        SSLConfig::cert_map.erase(hex_id);
        return CertificateStatus::ERRORED_CERTIFICATE;
    }
    return CertificateStatus::NEW_VALID_CERTIFICATE;
}


//Return value bool: socket_still_up
bool handle_custom_ssl_protocol(int epollfd, socket_t socketfd, ConnectionInfo &connection_info){
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
            case SSLStatus::PENDING_ACCEPT:
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
        CertificateStatus cs{};
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
                cs = receive_certificate_as_client(epollfd,socketfd,connection_info);
                //Perform heavy lifting (certificate validation, persistent storage)
                if(cs == CertificateStatus::NEW_VALID_CERTIFICATE || cs == CertificateStatus::EXPECTED_CERTIFICATE){
                    connection_info.ssl_stat = SSLUtils::try_ssl_connect(connection_info.ssl);
                    return true;
                }
                if(cs == CertificateStatus::ERRORED_CERTIFICATE || cs == CertificateStatus::KNOWN_CERTIFICATE_CONTENT_MISMATCH){
                    tear_down_connection(epollfd,socketfd);
                    return false;
                }
                //Certificate is not fully present yet. Return true, try again later.
                return true;
            case SSLStatus::PENDING_CONNECT:
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
    return true; //valid ssl connecton
}




bool handle_EPOLLOUT(int epollfd, const epoll_event &current_event){
    //Check connection type
    socket_t socketfd = current_event.data.fd;
    if (!connection_map.contains(socketfd)) {
        //Should never happen.
        tear_down_connection(main_epollfd, socketfd);
        return false;
    }

    ConnectionInfo &connection_info = connection_map.at(socketfd);

    if(connection_info.connection_type == ConnectionType::MODULE_API){
        flush_sendbuf(socketfd,connection_info,epollfd);
        return true; //Return early to distinguish from following ConnectionType::P2P
    }

    if(!handle_custom_ssl_protocol(epollfd,socketfd,connection_info)){
        return false;
    }


    //flush buffer.
    auto [socket_still_up, _ ]  = flush_sendbuf(socketfd,connection_info,epollfd);
    return socket_still_up;

}

bool read_EPOLLIN(int epollfd, const epoll_event& current_event){
    socket_t socketfd = current_event.data.fd;
    if (!connection_map.contains(socketfd)) {
        //Should never happen.
        tear_down_connection(main_epollfd, socketfd);
        return false;
    }
    ConnectionInfo &connection_info = connection_map.at(socketfd);

    if(connection_info.connection_type == ConnectionType::MODULE_API){
        flush_recvbuf(socketfd,connection_info,epollfd);
        //TODO: Notify kademlia logic.
        return true; //Return early to distinguish from following ConnectionType::P2P
    }

    if(!handle_custom_ssl_protocol(epollfd,socketfd,connection_info)){
        return false; //Socket was torn down by us.
    }

    return flush_recvbuf(socketfd, connection_info, epollfd);
}

bool handle_EPOLLIN(int epollfd, const epoll_event& current_event) { // returns whether the socket is still valid and should be kept open
    socket_t socketfd = current_event.data.fd;
    if (!read_EPOLLIN(epollfd, current_event)) {
        return false;
    }
    if (recv_buffer_empty(connection_map[socketfd])) {
        return true;
    }
    #ifdef TCP_VERBOSE
    std::cout << "Received new request." << std::endl;
    #endif
    ProcessingStatus processing_status;
    do {
        processing_status = try_processing(socketfd);
    } while (processing_status == MORE_TO_READ);
    #ifdef TCP_VERBOSE
    std::cout << "Processing finished: " << processing_status << std::endl;
    #endif
    if (processing_status == ProcessingStatus::ERROR) {
        std::cerr << "Had error with processing. Closing channel to e.g. unreachable or misbehaving peer." << std::endl;
        tear_down_connection(epollfd, socketfd);
        return false;
    }
    return true;
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
    if (serversocket < 0) {
        std::cerr << "Socket creation failed." << std::endl;
        return -1;
    }

    // Setting SO_REUSEADDR to avoid issues with TIME_WAIT
    setsockopt(serversocket, SOL_SOCKET, SO_REUSEADDR, &ONE, sizeof(ONE));
    setsockopt(serversocket, SOL_SOCKET, SO_KEEPALIVE, &ONE, sizeof(ONE));

    sockaddr_in6 sock_addr{};
    sock_addr.sin6_family = AF_INET6;
    sock_addr.sin6_port = htons(port);
    sock_addr.sin6_addr = in6addr_any;

    if (bind(serversocket, reinterpret_cast<sockaddr *>(&sock_addr), sizeof(sock_addr)) < 0) {
        std::cerr << "Failed to bind port " << port << ". Error: " << strerror(errno) << std::endl;
        close(serversocket);
        return -1;
    }

    if (listen(serversocket, 128) != 0) {
        std::cerr << "Failed to listen on port " << port << ". Error: " << strerror(errno) << std::endl;
        close(serversocket);
        return -1;
    }

    // std::cout << "Listening on port " << port << "." << std::endl;
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
    connection_info.client_port = port;

    if (connect(peer_socket, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) == -1) {
        std::cerr << "Couldn't connect to peer." << std::endl;
        close(peer_socket);
        return -1;
    }
    #ifdef TCP_VERBOSE
    std::cout << "Connected socket to " << ip_to_string(connection_info.client_addr) << ":" << connection_info.client_port << std::endl;
    #endif

    set_socket_blocking(peer_socket, false);

    connection_map[peer_socket] = connection_info;
    auto &connection_info_emplaced = connection_map[peer_socket];

    //Inject SSL-Code:
    if(connection_type == ConnectionType::P2P){
        #ifdef SSL_VERBOSE
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

        #ifdef SSL_VERBOSE
        SSLUtils::check_ssl_blocking_mode(ssl);
        #endif

        #ifdef SSL_VERBOSE
        std::cout << "Receiving length-prefixed Server-Certificate over insecure TCP channel" << std::endl;
        #endif

        // Do heavy lifting certificate storage logic
        CertificateStatus cert_stat =  receive_certificate_as_client(epollfd, peer_socket, connection_info_emplaced);
        if(cert_stat == CertificateStatus::ERRORED_CERTIFICATE || cert_stat == CertificateStatus::KNOWN_CERTIFICATE_CONTENT_MISMATCH){
            //Abort the connection. Could be a malicious Peer! Abort, abort!
            tear_down_connection(epollfd,peer_socket);
            return -1;
        }
        if(cert_stat == CertificateStatus::CERTIFICATE_NOT_FULLY_PRESENT){
            return peer_socket; //fd is valid, but wait for more bytes.
        }

        //Else: cert_stat is either NEW_VALID_CERTIFICATE  or EXPECTED_CERTIFICATE, continue with protocol.
        //New certificate saved or recognized previously trusted certificate.
        //Advance to at least SSLStatus::AWAITING_ACCEPT :)

        connection_info_emplaced.ssl_stat = SSLUtils::try_ssl_connect(ssl);
        if (connection_info_emplaced.ssl_stat == SSLStatus::FATAL_ERROR_ACCEPT_CONNECT) {
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

    #ifdef KADEMLIA_VERBOSE
    std::cout << "Generated Kademlia Node ID as hex: ";
    Utils::print_hex(SSLConfig::id.data(), 32);
    #endif

    //Retrieve own IPv6 ip to include in certificate:

    if(!NetworkUtils::getIPv6(SSLConfig::ipv6_buf,sizeof(SSLConfig::ipv6_buf))){
        std::cerr << "Failed to retrieve own IPv6 address" << std::endl;
        EVP_PKEY_free(SSLConfig::pkey);
        exit(EXIT_FAILURE);
    }

    //Generate self-signed certificate

    SSLConfig::cert = CertUtils::create_self_signed_cert(SSLConfig::pkey, SSLConfig::ipv6_buf, std::string(SSLConfig::id.begin(), SSLConfig::id.end()));
    if(!SSLConfig::cert){
        std::cerr << "Failed to generate self-signed X509 certificate" << std::endl;
        EVP_PKEY_free(SSLConfig::pkey);
        exit(EXIT_FAILURE);
    }


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
    if(signal == SIGINT || signal == SIGTERM){
        clean_up_SSL_Config();
        exit(0);
    }
}

socket_t set_socket_blocking(socket_t peer_socket, bool blocking) {
    int flags = fcntl(peer_socket, F_GETFL, 0);
    if (flags == -1) return -1;
    if (blocking) {
        flags &= ~O_NONBLOCK;
    } else {
        flags |= O_NONBLOCK;
    }
    if (fcntl(peer_socket, F_SETFL, flags) == -1) return -1;
    return peer_socket;
}

socket_t setup_connect_socket_blocking(int epollfd, struct in6_addr peer_address, u_short peer_port) {
    socket_t peer_socket = setup_connect_socket(epollfd, peer_address, peer_port, {ConnectionType::P2P});
    return set_socket_blocking(peer_socket, true);
}

void force_close_socket(int sockfd) {
    struct linger linger_option = {1, 0};  // Enable SO_LINGER with a timeout of 0
    if (setsockopt(sockfd, SOL_SOCKET, SO_LINGER, &linger_option, sizeof(linger_option)) < 0) {
        perror("setsockopt(SO_LINGER) failed");
        return;
    }

    if (close(sockfd) < 0) {
        perror("close failed");
        return;
    } else {
        #ifdef TCP_VERBOSE
        std::cout << "Socket forcefully closed." << std::endl;
        #endif
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

bool ensure_tls_blocking(socket_t peer_socket, std::chrono::seconds timeout_sec) {
    set_socket_blocking(peer_socket, false);

    int epollfd = epoll_create1(0);
    auto epollEvent = epoll_event{};
    epollEvent.events = EPOLLIN | EPOLLOUT | EPOLLERR;
    epollEvent.data.fd = peer_socket;
    epoll_ctl(epollfd, EPOLL_CTL_ADD, peer_socket, &epollEvent);
    std::vector<epoll_event> epoll_events{64};
    auto start_time = std::chrono::steady_clock::now();

    int tries = 0;
    while (true) { // event cound never -1 because epollout.
        int event_count = epoll_wait(epollfd, epoll_events.data(), std::ssize(epoll_events), 5000);  // dangerous cast
        if (event_count == -1) {
            if (errno == EINTR) { // for debugging purposes
                continue;
            }
            std::cerr << "Couldn't build TLS tunnel: " << errno << std::endl;
            return false;
        }
        for (int i = 0; i < event_count; ++i) {
            const epoll_event &current_event = epoll_events[i];
            bool socket_still_valid = true;
            if (!connection_map.contains(current_event.data.fd)) {
                std::cerr << "Tried to operate on a socket that's not connected anymore or not saved in our connections." << std::endl;
                continue;
            }
            // handle client processing of existing sessions
            if (connection_map[current_event.data.fd].ssl_stat == SSLStatus::CONNECTED) {
                #ifdef SSL_VERBOSE
                std::cout << "TLS Connection established." << std::endl;
                #endif
                return true;
            }
            if (current_event.events & EPOLLIN)
                socket_still_valid = handle_EPOLLIN(epollfd,current_event);
            if (socket_still_valid && current_event.events & EPOLLOUT)
                socket_still_valid = handle_EPOLLOUT(epollfd,current_event);
            if (socket_still_valid && current_event.events & EPOLLERR){
                tear_down_connection(epollfd,current_event.data.fd);
            }
        }
        auto current_time = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(current_time - start_time);
        if (elapsed > timeout_sec) {
            tear_down_connection(epollfd, peer_socket);
            return false;
        }
    }
}

bool wait_on_find_node_reply(socket_t peer_socket) {
    std::vector<epoll_event> epoll_events{64};
    int epollfd = epoll_create1(0);
    auto event = epoll_event{};
    event.events = EPOLLIN;
    event.data.fd = peer_socket;
    epoll_ctl(epollfd, EPOLL_CTL_ADD, peer_socket, &event);

    while (int event_count = epoll_wait(epollfd, epoll_events.data(), std::ssize(epoll_events), 5000) != -1) {
        for (int i = 0; i < event_count; i++) {
            bool still_valid = true;
            if  (epoll_events[i].events & EPOLLOUT) {
                still_valid = handle_EPOLLOUT(epollfd, epoll_events[i]);
            }
            if  (still_valid && epoll_events[i].events & EPOLLIN) {
                if (!read_EPOLLIN(epollfd, epoll_events[i])) {
                    std::cerr << "Didn't receive response during bootstrap" << std::endl;
                    return false;
                }

                socket_t sockfd = epoll_events[i].data.fd;
                auto& connection_info = connection_map[sockfd];

                u_short message_size, dht_type;
                if (parse_header(connection_info, message_size, dht_type) &&
                    dht_type == P2PType::DHT_RPC_FIND_NODE_REPLY) {
                    if (handle_DHT_RPC_find_node_reply(sockfd, message_size - HEADER_SIZE)) {
                        return true;
                    } else {
                        std::cerr << "Received invalid find node reply during bootstrap" << std::endl;
                        tear_down_connection(epollfd, peer_socket);
                        return false;
                    }
                } else {
                    continue;
                }
            }
        }
    }
    return false;
}

bool connect_to_network(u_short peer_port, const std::string &peer_address_string, struct in6_addr peer_address) {

    // 1. Send FIND_NODE RPC about our own node to peer (TODO: Don't immediately put our triple in peer's bucket list or else it won't return closer peers but us?)
    // 3. If response includes our own, we have no closer nodes, otherwise we get closer nodes to us
    // 4. Iterate over ever closer nodes
    // 5. Meanwhile, populate K_Buckets with ever closer nodes
    // 6. For Nodes farther away, do "refreshing" of random NodeID's in the respective ranges
    //    (choose closest nodes and send them find_node rpcs with the randomly generated NodeID's in said range)

    int epollfd = epoll_create1(0);
    socket_t peer_socket = setup_connect_socket_blocking(epollfd, peer_address, peer_port);
    setup_epollin(epollfd, peer_socket);

    bool ssl_success = ensure_tls_blocking(peer_socket, 300s);

    if (peer_socket == -1 || epollfd == -1 || !ssl_success) {
        std::cerr << "Error creating socket. Aborting." << std::endl;
        return false;
    }

    #ifdef KADEMLIA_VERBOSE
    std::cout << "Sending Find Node Request..." << std::endl;
    #endif
    if (!forge_DHT_RPC_find_node(peer_socket, epollfd, routing_table.get_local_node().id)) {
        std::cerr << "Couldn't send Find Node Request during bootstrap from " << peer_address_string << ":" << peer_port << std::endl;
    }

    // manually send forge
    flush_sendbuf(peer_socket, connection_map[peer_socket], epollfd);

    std::set<Node> returned_nodes{};
    auto handle_answer = [&](socket_t sockfd, u_short message_size) {
        return handle_DHT_RPC_find_node_reply(sockfd, message_size, &returned_nodes);
    };

    bool success = process_answers(epollfd, P2PType::DHT_RPC_FIND_NODE_REPLY, handle_answer, 1);

    if (!success) {
        std::cerr << "Expected valid find node reply response from peer " << peer_address_string << ":" << peer_port << " but didn't get a valid one." << std::endl;
        return false;
    }

    auto count = routing_table.count();
    #ifdef KADEMLIA_VERBOSE
    std::cout << "Got response with " << count << " peer" <<  (count != 1 ? "s" : "") << " other than our own." << std::endl;
    #endif

    size_t last_bucket_number;
    do {
        last_bucket_number = routing_table.get_bucket_list().size();
        for (auto& bucket : routing_table.get_bucket_list()) {
            auto random_key = generate_random_nodeID(bucket.get_start(), bucket.get_end());
            auto nodes = blocking_node_lookup(random_key);
            for(auto& node : nodes) {
                routing_table.add_peer(node);
            }
        }
    } while (routing_table.get_bucket_list().size() != last_bucket_number);

    count = routing_table.count();
    #ifdef KADEMLIA_VERBOSE
    std::cout << "Joined network and found " << count << " existing node" << (count != 1 ? "s." : ".") << std::endl;
    #endif
    return true;
}

#ifndef TESTING1
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

        bool should_connect_to_network = true;

        std::string help_description = "Run a DHT peer with local storage.\n\n"
                    "Multiple API clients can connect to this same instance.\n"
                    "To connect to an existing network, provide the ip address and port of a peer, otherwise a new network will be created.\n";
        std::string examples = "Example usages:\n" // TODO: ::1 ergänzen
                    "Start new p2p network on 192.168.0.42:7402\n"
                    "\tdht_server -a 192.168.0.42 -m 7401 -p 7402\n"
                    "Connect to p2p network on 192.168.0.42:7402 from 192.168.0.69:7404, accepting requests on port 7403\n"
                    "\tdht_server -a 192.168.0.69 -m 7403 -p 7404 -A 192.168.0.42 -P 7402\n";
        progOpt::options_description desc{help_description + examples};
        try {
            // Argument parsing:
            // Use boost::program_options for parsing:
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

            if (vm.contains("help"))
            {
                std::cout << desc << "\n";
                return 0;
            }

            if (vm.contains("unreg")) {
                std::cout << examples << "\n";
                return 1;
            }

            if (host_module_port == host_p2p_port) {
                std::cerr << "Cannot setup Module API server and P2P server on the same port (" << host_module_port << "). Exiting." << std::endl;
                return -1;
            }
            #ifdef GENERAL_VERBOSE
            std::cout << "Modules reach this server on " << host_address_string << ":" << host_module_port << std::endl;
            std::cout << "We communicate with peers on " << host_address_string << ":" << host_p2p_port << std::endl;
            #endif
            if (system(("ping -c1 -s1 " + host_address_string + "  > /dev/null 2>&1").c_str()) != 0) {
                std::cerr << "Warning: Failed to ping host." << std::endl;
            }

            if (vm.contains("peer-address") && vm.contains("peer-port")) {
            #ifdef GENERAL_VERBOSE
            std::cout << "Trying to connect to existing Network Node " << peer_address_string << ":" << peer_port << std::endl;
            #endif
                if (!convert_to_ipv6(peer_address_string, peer_address)) {
                    std::cerr << "Please provide a syntactically correct IP address (v4 or v6) for the peer";
                    return 1;
                }
                if (system(("ping -c1 -s1 " + peer_address_string + "  > /dev/null 2>&1").c_str()) != 0) {
                    std::cerr << "Warning: Failed to ping peer." << std::endl;
                }
            } else {
                #ifdef GENERAL_VERBOSE
                std::cout << "Since no peer to connect to was supplied, setting up new network..." << std::endl;
                #endif
                should_connect_to_network = false;
            }

        // Parsing complete
    }
    catch (std::exception& _)
    {
        // passed invalid arguments, e.g. ip to port or similar
        std::cerr << "Passed invalid arguments. Keep to correct formatting, format IPv4 addresses as 192.168.0.42 and ports separated by space.\n" << std::endl;
        std::cout << desc << examples << "\n";
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
    std::signal(SIGTERM,sig_c_handler);

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

    if(should_connect_to_network) {
        if (!connect_to_network(peer_port, peer_address_string, peer_address)) {
            return -1;
        }
    }

    //Start to periodically purge local_storage:

    std::thread purger(purge_local_storage);


    // event loop
    #ifdef GENERAL_VERBOSE
    std::cout << "Server running... " << std::endl;
    #endif
    bool server_is_running = true;
    while (server_is_running) {
        int event_count = epoll_wait(main_epollfd, epoll_events.data(), std::ssize(epoll_events), -1);  // dangerous cast
        // TODO: ADD SERVER MAINTAINENCE. purge storage (ttl), peer-ttl (k-bucket
        // maintainence) internal management clean up local_storage for all keys,
        // std::erase if ttl is outdated

        if (event_count == -1) {
            if (errno == EINTR) { // for debugging purposes
                continue;
            }
            std::cerr << "epoll had the error " << errno << std::endl;
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
                if (!connection_map.contains(current_event.data.fd)) {
                    std::cerr << "Tried to operate on a socket that's not connected anymore or not saved in our connections." << std::endl;
                    continue;
                }
                // handle client processing of existing sessions
                if (current_event.events & EPOLLIN)
                    socket_still_valid = handle_EPOLLIN(main_epollfd,current_event);
                if (socket_still_valid && current_event.events & EPOLLOUT)
                    socket_still_valid = handle_EPOLLOUT(main_epollfd,current_event);
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