#include "dht_server.h"
#include "routing.h"

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


/*
Important Remark: Maybe use a logger for keeping track of operations during runtime.
Boost provides one, seemingly a bit hard to setup, but anyways:
https://www.boost.org/doc/libs/1_82_0/libs/log/doc/html/index.html
*/


std::unordered_map<socket_t,ConnectionInfo> connectionMap;
static constexpr size_t MAXLIFETIMESEC = 20*60; // 20 minutes in seconds
static constexpr size_t MINLIFETIMESEC = 3*60;  //  3 minutes in seconds
static constexpr size_t DEFAULTLIFETIMESEC = 5*60; // 5 minutes in seconds


std::map<Key,std::pair<std::chrono::time_point<std::chrono::system_clock>, Value>> local_storage{};
std::mutex storage_lock;

RoutingTable routing_table;

// Utility functions

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

bool is_in_my_range(Key key){
    return true;
}

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

// Storage

// Returns optional value, either the correctly looked up value, or no value.
std::optional<Value> get_from_storage(const Key &key)
{
    // shouldn't be needed. Safety mesaure for now, based on python impl.
    std::lock_guard<std::mutex> lock(storage_lock);
    try
    {
        // We could also perform kademlia tree index checks here.
        if(local_storage.contains(key)){ //Log look-up hit, but maybe outdated.
            auto [ttl,value] = local_storage.at(key);
            if (ttl >= std::chrono::system_clock::now())
                return {value}; // Log lookup-hit.
            else
            {
                local_storage.erase(key);
                return {}; // Log lookup-miss.
            }
        }
        return {};
    }
    catch (std::out_of_range e)
    {
        // Log lookup-miss.
        return {};
    }
}

void save_to_storage(const Key &key, std::chrono::seconds ttl, Value &val)
{
    std::lock_guard<std::mutex> lock(storage_lock);

    auto fresh_insert = local_storage.insert_or_assign(key, std::pair{std::chrono::system_clock::now() + ttl,val});
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

void build_DHT_header(size_t body_size, u_short message_type, Message& message) {
    // we are extracting high and low bytes here
    // >> 8 gives us the high byte
    // and & 0xFF masks out the low byte
    message[0] = (body_size) >> 8;
    message[1] = (body_size) & 0xFF;
    message[2] = message_type >> 8;
    message[3] = message_type & 0xFF;
}

void write_body(Message& message, size_t body_offset, unsigned char* data, size_t data_size) {
    std::copy_n(data, data_size, message.data() + HEADER_SIZE + body_offset);
}

void read_body(const Message& message, size_t body_offset, unsigned char* data, size_t data_size) {
    std::copy_n(message.data() + HEADER_SIZE + body_offset, data_size, data);
}

bool send_DHT_message(socket_t socket, Message message) {
    auto sent = write(socket, message.data(), message.size());
    // TODO: @joern how was the connectionMap send buffer supposed to work again?
    if (sent != message.size()) {
        std::cerr << "Error sending message, aborting." << std::endl;
        return false;
    }
    return true;
}

// Module API functions handling+construction functions

bool send_DHT_put(socket_t socket, Key &key, Value &value) {
}


bool handle_DHT_put(ConnectionInfo &connection_info) {
    const Value &connectionBuffer = connection_info.receivedBytes;
    const size_t ttl_offset = HEADER_SIZE;
    const size_t key_offset = ttl_offset + 4;
    const size_t value_offset = key_offset + KEY_SIZE;

    // copy key into local var
    Key key;
    std::copy_n(connectionBuffer.cbegin() + key_offset, KEY_SIZE, std::begin(key));

    if (not is_in_my_range(key)) {
        // todo: Relay!!
        //--> Forward put_request with k-bucket table and await answer
        // 5. Forge answer to original peer (DHT_SUCCESS/DHT_FAILURE)
    }

    u_short time_to_live = connectionBuffer[ttl_offset + 1];
    time_to_live <<= 8;
    time_to_live += connectionBuffer[ttl_offset];
    if (time_to_live > MAXLIFETIMESEC || time_to_live < MINLIFETIMESEC) {
        // default time to live, as value is out of lifetime bounds
        time_to_live = DEFAULTLIFETIMESEC;
    }

    unsigned char replication = connectionBuffer[ttl_offset + 2];
    unsigned char reserved = connectionBuffer[ttl_offset + 3];

    // copy value into local var
    size_t value_size = connectionBuffer.size() - value_offset;
    Value value;
    value.reserve(value_size);
    std::copy_n(connectionBuffer.cbegin() + value_offset, value_size, std::begin(value));

    save_to_storage(key, std::chrono::seconds(time_to_live), value);
}

bool send_DHT_get(socket_t socket, Key &key) {
}

bool handle_DHT_get(ConnectionInfo &connection_info) {
    const Value &connectionBuffer = connection_info.receivedBytes;
    const size_t key_offset = HEADER_SIZE;

    // copy key into local var
    std::array<unsigned char, KEY_SIZE> key;
    std::copy_n(connectionBuffer.cbegin() + key_offset, KEY_SIZE, std::begin(key));

    if (not is_in_my_range(key)) {
        // todo: Relay!!
        //--> Forward get_request with k-bucket table and await answer
        // 5. Forge answer to original peer (DHT_SUCCESS/DHT_FAILURE)
    }

    auto optVal = get_from_storage(key);
    if (optVal.has_value()) {
        // local storage hit, forge answer to requesting party:
        //send_DHT_success(connection_info, optVal.value());
        // TODO: Queue send event in epoll, readied if EPOLLOUT
    } else {
        // local storage hit, forge answer to requesting party:
        //send_DHT_failure(connection_info, optVal.value());
        // TODO: Queue send event in epoll, readied if EPOLLOUT
    }
}

bool send_DHT_success(socket_t socket, Key &key, Value &value) {
}

bool send_DHT_success(socket_t socket, Key key, Value value); // TODO

bool forge_DHT_success(ConnectionInfo &connection_info, const Value &value){
    //TODO
    //Save buffer into connection_info
    return true;
};

bool handle_DHT_success(ConnectionInfo &connection_info) {
    const Value &connectionBuffer = connection_info.receivedBytes;
    // Currently received a frame for a relayed connection. Now, serve as relaying middlepoint and forward
    // message to correct peer (Client/Server, indistinguishable)
    const size_t key_offset = HEADER_SIZE;
    const size_t value_offset = key_offset + KEY_SIZE;
    // copy key into local var
    std::array<unsigned char, KEY_SIZE> key;
    std::copy_n(connectionBuffer.begin() + key_offset, KEY_SIZE, std::begin(key));

    if (!is_in_my_range(key)) {
        // todo: Relay!!
        //--> Forward unmodified dht_success message
        // We do not expect any confirmation.
        // close connection
    }

    // todo: Answer (basically same as relay)
    //--> Forward unmodified dht_success message
    // We do not expect any confirmation.
    // close connection
}

bool send_DHT_failure(socket_t socket, Key &key) {
}

bool forge_DHT_failure(ConnectionInfo &connection_info, const Value &value){
    //TODO
    //Save buffer into connection_info
    return true;
};

bool handle_DHT_failure(ConnectionInfo &connection_info) {
    const Value &connectionBuffer = connection_info.receivedBytes;
    // copy key into dataframe
    const size_t key_offset = HEADER_SIZE;
    // copy key into local var
    std::array<unsigned char, KEY_SIZE> key;
    std::copy_n(connectionBuffer.begin() + key_offset, KEY_SIZE, std::begin(key));

    if (!is_in_my_range(key)) {
        // todo: Relay!!
        //--> Forward unmodified dht_failure message with k-bucket table and DO NOT await answer.
        // We do not expect any confirmation.
        // close connection
    }

    // todo: Answer (basically same as relay)
    //--> Forward unmodified dht_failure message with k-bucket table and DO NOT await answer.
    // We do not expect any confirmation.
    // close connection
}


// P2P/RPC handling+construction functions

bool send_DHT_RPC_ping(socket_t socket) {
    // TODO: assumes connectionMap contains socket
    Key rpc_id = generate_random_nodeID();

    size_t body_size = 32;
    size_t message_size = HEADER_SIZE + body_size;
    u_short message_type = DHT_RPC_PING;
    Message message(message_size);

    build_DHT_header(body_size, message_type, message);

    write_body(message, 0, rpc_id.data(), 32);

    connectionMap.at(socket).rpc_id = rpc_id;

    return send_DHT_message(socket, message);
}

bool handle_DHT_RPC_ping(const ConnectionInfo& connection_info, const u_short body_size) {
    const Value &connectionBuffer = connection_info.receivedBytes;
    const size_t rpc_id_offset = HEADER_SIZE;

    // forgeDHTPingReply(connection_info, rpc_id);
}

bool send_DHT_RPC_ping_reply(socket_t socket) {
}

// TODO: following functions even necessary? Should answers be waited upon in the respective switch-cases?
bool handle_DHT_RPC_ping_reply(const ConnectionInfo& connection_info, const u_short body_size) {
}

bool send_DHT_RPC_store(socket_t socket, Key &key, Value &value) {
}

bool handle_DHT_RPC_store(const ConnectionInfo& connection_info, const u_short body_size) {
    const Value &connectionBuffer = connection_info.receivedBytes;
    const size_t rpc_id_offset = HEADER_SIZE;
    const size_t ttl_offset = rpc_id_offset + 32;
    const size_t key_offset = ttl_offset + 2;
    const size_t value_offset = key_offset + KEY_SIZE;

    // TODO: look at DHT_STORE, also decide on difference of functionalities

    // forgeDHTStoreReply(connection_info, rpc_id, key, value);
}

bool send_DHT_RPC_store_reply(socket_t socket, Key &key, Value &value) {
}

bool handle_DHT_RPC_store_reply(const ConnectionInfo& connection_info, const u_short body_size) {
}

bool send_DHT_RPC_find_node(socket_t socket, NodeID node_id) {
    Key rpc_id = generate_random_nodeID();

    size_t body_size = 32 + 32;
    size_t message_size = HEADER_SIZE + body_size;
    u_short message_type = DHT_RPC_FIND_NODE;
    Message message(message_size);

    build_DHT_header(body_size, message_type, message);

    write_body(message, 0, rpc_id.data(), RPC_ID_SIZE);
    write_body(message, RPC_ID_SIZE, node_id.data(), NODE_ID_SIZE);

    connectionMap.at(socket).rpc_id = rpc_id;

    return send_DHT_message(socket, message);
}

bool forge_DHT_find_node_reply(socket_t socket, const Key & key, const std::vector<Node> & nodes) {
    return true;
}

bool handle_DHT_RPC_find_node(const ConnectionInfo& connection_info, const u_short body_size) {
    if (body_size != 64) {
        return false;
    }
    const Message& message = connection_info.receivedBytes;

    Key rpc_id;
    read_body(message, 0, rpc_id.data(), RPC_ID_SIZE);
    NodeID target_node_id;
    read_body(message, RPC_ID_SIZE, target_node_id.data(), NODE_ID_SIZE);

    // find closest nodes, then return them:
    auto closest_nodes = routing_table.find_closest_nodes(target_node_id);
    return forge_DHT_find_node_reply(connection_info.replyTo, rpc_id, closest_nodes);
}

bool send_DHT_RPC_find_node_reply(socket_t socket, Key rpc_id,  std::vector<Node> closest_nodes) {
    // TODO: ipv6 or ipv4?
    size_t body_size = 32 + closest_nodes.size() * NODE_SIZE;
    size_t message_size = HEADER_SIZE + body_size;
    u_short message_type = DHT_RPC_FIND_NODE_REPLY;
    Message message(message_size);

    build_DHT_header(body_size, message_type, message);

    write_body(message, 0, rpc_id.data(), RPC_ID_SIZE);

    for (size_t i = 0; i < closest_nodes.size(); i++) {
        auto& node = closest_nodes.at(i);
        write_body(message, RPC_ID_SIZE + i*NODE_SIZE, node.addr.s6_addr, 16);
        // TODO: @joern Problem of endianness to reinterpret_cast here? Should we save in network byte order?
        u_short port_network_order = htons(node.port);
        write_body(message, RPC_ID_SIZE + i*NODE_SIZE + 16, reinterpret_cast<unsigned char*>(&port_network_order), 2);
        write_body(message, RPC_ID_SIZE + i*NODE_SIZE + 16 + 2, node.id.data(), 32);
    }

    return send_DHT_message(socket, message);
}

bool handle_DHT_RPC_find_node_reply(const ConnectionInfo& connection_info, const u_short body_size) {
    if ((body_size - 32) % NODE_SIZE != 0) {
        return false;
    }
    int num_nodes = (body_size - 32) / NODE_SIZE;
    std::vector<Node> closest_nodes{};
    const Message& message = connection_info.receivedBytes;

    Key rpc_id;
    read_body(message, 0, rpc_id.data(), 32);
    for (int i = 0; i < num_nodes; i++) {
        Node node{};

        read_body(message, i*NODE_SIZE, node.addr.s6_addr, 16);
        read_body(message, i*NODE_SIZE + 16, reinterpret_cast<unsigned char*>(&node.port), 2);
        node.port = ntohs(node.port);
        read_body(message, i*NODE_SIZE + 16 + 2, node.id.data(), 32);

        closest_nodes.push_back(node);
    }
    std::cout << "Got back " << closest_nodes.size() << " nodes." << std::endl;;
    return true;
}

bool send_DHT_RPC_find_value(socket_t socket, Key &key, Value &value) {
}

bool handle_DHT_RPC_find_value(const ConnectionInfo& connection_info, const u_short body_size) {
    const Value &connectionBuffer = connection_info.receivedBytes;
    const size_t rpc_id_offset = HEADER_SIZE;
    const size_t key_offset = rpc_id_offset + 32;

    Key key;
    std::copy_n(connectionBuffer.begin() + key_offset, KEY_SIZE, std::begin(key));



    auto optVal = get_from_storage(key);
    if (optVal.has_value()) {
        // forgeDHTFindValueReply(connection_info, rpc_id, key, optVal.value());
    } else {
        // auto closest_nodes = find_closest_nodes(key);
        // forgeDHTFindNodeReply(connection_info, rpc_id, closest_nodes);
    }
}

bool send_DHT_RPC_find_value_reply(socket_t socket, Key &key, Value &value) {
}

bool handle_DHT_RPC_find_value_reply(const ConnectionInfo& connection_info, const u_short body_size) {
}

// send

bool handle_DHT_error(const ConnectionInfo& connection_info, const u_short body_size) {
    const size_t error_type_offset = HEADER_SIZE;
    // TODO: extract error type, switch case based on that
}

// Message Parsing

bool parse_header(const ConnectionInfo &connection_info, u_short &message_size, u_short &dht_type){
    const Message &connectionBuffer = connection_info.receivedBytes;
    message_size = 0;
    dht_type = 0;

    message_size += connectionBuffer[0];
    message_size <<= 8;
    message_size += connectionBuffer[1];
    /*The message is expected to not even contain a key.
    All messages that adhere to protocol require a key sent.*/
    if(message_size < KEY_SIZE){
        return false;
    }

    dht_type += connectionBuffer[2];
    dht_type <<= 8;
    dht_type += connectionBuffer[3];
    /*The dht_type that was transmitted is not in the range of expected types*/
    if(!is_valid_DHT_type(dht_type)){
        return false;
    }
    return true;
}



bool parse_API_request(ConnectionInfo &connection_info, const u_short body_size, const ModuleApiType module_api_type){
    Value &connectionBuffer = connection_info.receivedBytes;
    switch (module_api_type){
        {
        case DHT_PUT:
            {
            handle_DHT_put(connection_info);
        break;
            }
        case DHT_GET:
            {
            handle_DHT_get(connection_info);
        break;
            }
        case DHT_SUCCESS:
            {
            handle_DHT_success(connection_info);
        break;
            // Close connection (was only for relaying!)
            }
        case DHT_FAILURE:
            {
            handle_DHT_failure(connection_info);
        break;
            }

        default:
            break;
        }
    }
    return true;
}

bool parse_P2P_request(ConnectionInfo& connection_info, const u_short body_size, const P2PType p2p_type) {
    switch (p2p_type) {
        case DHT_RPC_PING:
            break;
        case DHT_RPC_STORE:
            break;
        case DHT_RPC_FIND_NODE:
            return handle_DHT_RPC_find_node(connection_info, body_size);
            break;
        case DHT_RPC_FIND_VALUE:
            break;
        case DHT_RPC_PING_REPLY:
            break;
        case DHT_RPC_STORE_REPLY:
            break;
        case DHT_RPC_FIND_NODE_REPLY:
            return handle_DHT_RPC_find_node_reply(connection_info, body_size);
            break;
        case DHT_RPC_FIND_VALUE_REPLY:
            break;
        case DHT_ERROR:
            break;
    }
    return true;
}

// Connection Processing

ProcessingStatus try_processing(socket_t curfd){
    //retreive information for element to process:
    ConnectionInfo &connection_info = connectionMap.at(curfd);
    auto &connectionBuffer = connection_info.receivedBytes;
    size_t byteCountToProcess = connectionBuffer.size();
    if(connectionBuffer.size() == 0){
        /* i.e.: we got work to process (epoll event happened), the message buffer
        is empty, but all bytes of the kernel buffer were exhausted (server side).*/
        return ProcessingStatus::ERROR;
    }
    if(connectionBuffer.size() < HEADER_SIZE){
        return ProcessingStatus::WAIT_FOR_COMPLETE_MESSAGE_HEADER;
    }

        //Parse header:
        u_short body_size = -1;
        u_short dht_type = -1;

        bool headerSuccess = parse_header(connection_info, body_size, dht_type);
        if (not headerSuccess){
            return ProcessingStatus::ERROR;
        }

        //Header was successfully parsed. Check if entire message is present:
        if(byteCountToProcess < HEADER_SIZE + body_size){
            return ProcessingStatus::WAIT_FOR_COMPLETE_MESSAGE_BODY;
        }
        //Header was fully parsed and entire message is present. Do the "heavy lifting", parse received request semantically:

    bool request_successful = false;

    if (connection_info.connectionType == ConnectionType::MODULE_API) {
        ModuleApiType module_api_type;
        if (is_valid_module_API_type(dht_type)) {
            module_api_type = static_cast<ModuleApiType>(dht_type);
        } else {
            std::cerr << "Tried to send invalid Request to Module API Server. Aborting." << std::endl;
            return ProcessingStatus::ERROR;
        }
        // TODO: Pass socket instead of connection info
        request_successful = parse_API_request(connection_info, body_size, module_api_type);
    } else if (connection_info.connectionType == ConnectionType::P2P) {
        P2PType p2p_type;
        if (is_valid_P2P_type(dht_type)) {
            p2p_type = static_cast<P2PType>(dht_type);
        } else {
            std::cerr << "Tried to send invalid Request to P2P Server. Aborting." << std::endl;
            return ProcessingStatus::ERROR;
        }
        // TODO: Maybe temporary? How should we reply @joern
        connection_info.replyTo = curfd;
        request_successful = parse_P2P_request(connection_info, body_size, p2p_type);
    } else {
        std::cerr << "No ConnectionType registered for client. Aborting." << std::endl;
        return ProcessingStatus::ERROR;
    }
    if (request_successful) {
        return ProcessingStatus::PROCESSED;
    } else {
        std::cerr << "Unknown Error with request." << std::endl;
        return ProcessingStatus::ERROR;
    }
}


void accept_new_connection(int epollfd, std::vector<epoll_event>::value_type curEvent, ConnectionType connectionType) {
    // accept new client connections from serverside
    socket_t socket = accept4(curEvent.data.fd, nullptr, nullptr, SOCK_NONBLOCK);
    if (!socket) {
        // Accept-Error
        return;
    }
    auto epollEvent = epoll_event{};
    epollEvent.events = EPOLLIN | EPOLLOUT | EPOLLERR;
    epollEvent.data.fd = socket;
    // TODO: epollEvent out of scope? add to vector
    epoll_ctl(epollfd, EPOLL_CTL_ADD, socket, &epollEvent);
    connectionMap.insert_or_assign(socket, ConnectionInfo{connectionType});
}

void run_event_loop(socket_t module_api_socket, socket_t p2p_socket, int epollfd,
                  std::vector<epoll_event> &epoll_events) {
    std::cout << "Server running... " << std::endl;
    bool serverIsRunning = true;
    while (serverIsRunning) {
        int eventCount = epoll_wait(epollfd, epoll_events.data(), std::ssize(epoll_events), -1);  // dangerous cast
        // TODO: ADD SERVER MAINTAINENCE. purge storage (ttl), peer-ttl (k-bucket
        // maintainence) internal management clean up local_storage for all keys,
        // std::erase if ttl is outdated

        if (eventCount == -1) {
            serverIsRunning = false;
            break;
        }
        for (int i = 0; i < eventCount; ++i) {
            auto curEvent = epoll_events[i];
            if (curEvent.data.fd == module_api_socket) {
                accept_new_connection(epollfd, curEvent, ConnectionType::MODULE_API);
            } else if (curEvent.data.fd == p2p_socket) {
                accept_new_connection(epollfd, curEvent, ConnectionType::P2P);
            } else {
                // handle client processing of existing seassions
                if (curEvent.events & EPOLLIN) {
                    std::cout << "Received new request." << std::endl;
                    std::array<unsigned char, 4096> recv_buf{};
                    auto curfd = curEvent.data.fd;
                    if (!connectionMap.contains(curfd)) {
                        connectionMap.insert_or_assign(curfd, ConnectionInfo{});
                    }
                    auto &connectionBuffer = connectionMap.at(curfd).receivedBytes;
                    while (true) {
                        // This loop is used in order to pull all bytes that
                        // reside already on this machine in the kernel socket buffer.
                        // once this exausts, we try processing.
                        auto bytesRead = read(curfd, recv_buf.data(), recv_buf.size());
                        if (bytesRead == 0
                            || (bytesRead == -1 && errno == EWOULDBLOCK)) {
                            bool processingStatus = try_processing(curfd);
                            std::cout << "Processing finished: " << processingStatus
                                      << std::endl;
                            if (processingStatus == true) {
                                // epoll_ctl(epollfd,EPOLL_CTL_DEL,curfd,nullptr);
                            }
                            break;
                        } else if (bytesRead == -1) { // TODO: rutscht immer hier rein in der 2. iteration dieses loops
                            epoll_ctl(epollfd, EPOLL_CTL_DEL, curfd, nullptr);
                            connectionMap.erase(curfd);
                            break;
                        }
                        connectionBuffer.insert(connectionBuffer.end(), recv_buf.begin(),
                                                recv_buf.begin() + bytesRead);

                        std::cout << std::string_view(reinterpret_cast<const char *>(recv_buf.data()), bytesRead) << "\n";
                    }
                }
                if (curEvent.events & EPOLLOUT) {
                    // partial output. Send rest of answer
                }
                if (curEvent.events & EPOLLERR) {
                    epoll_ctl(epollfd, EPOLL_CTL_DEL, curEvent.data.fd, nullptr);
                    connectionMap.erase(curEvent.data.fd);
                    continue;
                }
            }
        }
    }
}

// Network/Socket functions

int setup_epoll(int epollfd, socket_t serversocket) {
    // TODO SSL

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
    bind(serversocket, reinterpret_cast<sockaddr *>(&sock_addr),
         sizeof(sock_addr));  // TODO Error-checking
    listen(serversocket, 128);
    return serversocket;
}

socket_t setup_connect_socket(std::string address_string, u_short port) {
    socket_t peer_socket = socket(AF_INET6, SOCK_STREAM, 0);
    if (peer_socket == -1) {
        std::cerr << "Failed to create client socket" << std::endl;
        return -1;
    }

    sockaddr_in6 address{};
    if (!convert_to_ipv6(address_string, address.sin6_addr)) {
        std::cerr << "Invalid address" << std::endl;
        close(peer_socket);
        return -1;
    }

    address.sin6_family = AF_INET6;
    address.sin6_port = htons(port);

    if (connect(peer_socket, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) == -1) {
        std::cerr << "Couldn't connect to peer." << std::endl;
        close(peer_socket);
        return -1;
    }
    return peer_socket;
}


#ifndef TESTING1
int main(int argc, char const *argv[])
{
    // TODO No. 1: restructure + refactor everything to be clear what uses p2p port and what module api port
    // Own address
    u_short host_port = ServerConfig::P2P_PORT;
    std::string host_address_string = {};
    struct in6_addr host_address{};

    // Peer to connect to as first contact
    u_short peer_port = 0;
    std::string peer_address_string = {};
    struct in6_addr peer_address{};
    bool connect_to_existing_network = true;

    try
    {
        // Argument parsing:
        // Use boost::program_options for parsing:
        progOpt::options_description desc{"Run a DHT module mockup with local storage.\n\nMultiple API clients can connect to this same instance.\nTo connect to an existing network, provide the ip address and port of a peer, otherwise new network will be created."};
        desc.add_options()("help,h", "Help screen")
        ("address,a", progOpt::value<std::string>(&host_address_string), "Bind server to this address")
        ("port,p", progOpt::value<u_short>(&host_port), "Bind server to this port")
        ("peer-address,A", progOpt::value<std::string>(&peer_address_string), "Try to connect to existing network at this address")
        ("peer-port,P", progOpt::value<u_short>(&peer_port), "Try to connect to existing network at this port")
        ("unreg", "Unrecognized options");

        progOpt::positional_options_description pos_desc;
        pos_desc.add("address", 1);
        pos_desc.add("port", 1);
        pos_desc.add("peer-address", 1);
        pos_desc.add("peer-port", 1);

        progOpt::command_line_parser parser{argc, argv};
        parser.options(desc)
            .allow_unregistered()
            .positional(pos_desc)
            .style(progOpt::command_line_style::default_style | progOpt::command_line_style::allow_slash_for_short);
        progOpt::parsed_options parsed_options = parser.run();

        progOpt::variables_map vm;
        progOpt::store(parsed_options, vm);
        progOpt::notify(vm);

        if (vm.count("help") || vm.count("unreg"))
        {
            std::cout << desc << "\n";
            return 0;
        }
        if (vm.count("address"))
        {
            //TODO PORT
        }
        if (vm.count("port"))
        {
            //TODO PORT
        }
        /*
          throws error:
         for (auto it = vm.begin(); it != vm.end(); ++it) {
            std::cout << it->first << " : " << it->second.as<std::string>() << std::endl;
        }*/

        std::cout << "We are on " << host_address_string << ":" << host_port << std::endl;
        if (vm.count("peer-address") && vm.count("peer-port")) {
        std::cout << "Trying to connect to existing Network Node " << peer_address_string << ":" << peer_port << std::endl;
            if (!convert_to_ipv6(peer_address_string, peer_address)) {
                std::cerr << "Please provide a syntactically correct IP address (v4 or v6) for the peer";
                return 1;
            }
        } else {
            std::cout << "Since no peer to connect to was supplied, setting up new network..." << std::endl;
            connect_to_existing_network = false;
        }


        // Parsing complete
    }
    catch (std::exception excep)
    {
        std::cout << "Is the argument parsing a problem?" << std::endl;
        std::cerr << excep.what() << '\n';
        std::cout << boost::stacktrace::stacktrace();
        return -1;
    }

    if (!convert_to_ipv6(host_address_string, host_address)) {
        std::cerr << "Please provide a syntactically correct IP address (v4 or v6) for the host";
        return 1;
    }


    // TODO:
    // switch: either
    // 1. join existing network -> we need an ip/ip list which we can ask
    // 2. create new network
    // finally: in both cases, to create a network, we need a way to exchange triples
    // first: setup RPC messages, to make "joining" possible by sending a "FIND_NODE" to the contact
    // then, for case 1 we need Node A to send FIND_NODE to node B that receives a triple from A or how does A present itself to B?


    routing_table = RoutingTable(host_address, host_port);

    if(connect_to_existing_network) {
        // TODO: connect to existing network
        // TODO: setup socket + add to connectionMap, then call:
        std::cout << "Sending Find Node Request..." << std::endl;
        socket_t peer_socket = setup_connect_socket(peer_address_string, peer_port);

        connectionMap[peer_socket] = {};
        send_DHT_RPC_find_node(peer_socket, routing_table.get_local_node().id);
        // 1. Send FIND_NODE RPC about our own node to peer (TODO: Don't immediately put our triple in peer's bucket list or else it won't return closer peers but us?)
        // 3. If response includes our own, we have no closer nodes, otherwise we get closer nodes to us
        // 4. Iterate over ever closer nodes
        // 5. Meanwhile, populate K_Buckets with ever closer nodes
        // 6. For Nodes farther away, do "refreshing" of random NodeID's in the respective ranges
        //    (choose closest nodes and send them find_node rpcs with the randomly generated NodeID's in said range)

    }

    // Open port for local API traffic from modules

    socket_t module_api_socket = setup_server_socket(ServerConfig::MODULE_API_PORT);
    int epollfd = epoll_create1(0);
    epollfd = setup_epoll(epollfd, module_api_socket);
    socket_t p2p_socket = setup_server_socket(ServerConfig::P2P_PORT);
    epollfd = setup_epoll(epollfd, p2p_socket);
    std::vector<epoll_event> epoll_events{64};
    run_event_loop(module_api_socket, p2p_socket, epollfd, epoll_events);

    return 0;
}
#endif
