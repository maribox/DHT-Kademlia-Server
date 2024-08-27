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


std::unordered_map<socket_t,ConnectionInfo> connection_map;
static constexpr size_t MAXLIFETIMESEC = 20*60; // 20 minutes in seconds
static constexpr size_t MINLIFETIMESEC = 3*60;  //  3 minutes in seconds
static constexpr size_t DEFAULTLIFETIMESEC = 5*60; // 5 minutes in seconds


std::map<Key,std::pair<std::chrono::time_point<std::chrono::system_clock>, Value>> local_storage{};
std::mutex storage_lock;

RoutingTable routing_table;

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

bool forge_DHT_message(socket_t socket, Message message) {
    int sent = 0;
    if (message.size() > 0) {
        sent = write(socket, message.data(), message.size());
    }
    // if write wasn't completed yet, rest will be sent with epoll wait
    if (sent == -1) {
        std::cerr << "Error sending message, aborting." << std::endl;
        return false;
    }
    return true;
}

bool check_rpc_id(const Message &message, const Key correct_rpc_id) {
    Key rpc_id;
    read_body(message, 0, rpc_id.data(), 32);
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


bool handle_DHT_put(socket_t socket) {
    const Value &connection_buffer = connection_map[socket].received_bytes;
    const size_t ttl_offset = HEADER_SIZE;
    const size_t key_offset = ttl_offset + 4;
    const size_t value_offset = key_offset + KEY_SIZE;

    // copy key into local var
    Key key;
    std::copy_n(connection_buffer.cbegin() + key_offset, KEY_SIZE, std::begin(key));

    if (not is_in_my_range(key)) {
        // todo: Relay!!
        //--> Forward put_request with k-bucket table and await answer
        // 5. Forge answer to original peer (DHT_SUCCESS/DHT_FAILURE)
    }

    u_short time_to_live = connection_buffer[ttl_offset + 1];
    time_to_live <<= 8;
    time_to_live += connection_buffer[ttl_offset];
    if (time_to_live > MAXLIFETIMESEC || time_to_live < MINLIFETIMESEC) {
        // default time to live, as value is out of lifetime bounds
        time_to_live = DEFAULTLIFETIMESEC;
    }

    unsigned char replication = connection_buffer[ttl_offset + 2];
    unsigned char reserved = connection_buffer[ttl_offset + 3];

    // copy value into local var
    size_t value_size = connection_buffer.size() - value_offset;
    Value value;
    value.reserve(value_size);
    std::copy_n(connection_buffer.cbegin() + value_offset, value_size, std::begin(value));

    save_to_storage(key, std::chrono::seconds(time_to_live), value);
    return true;
}

bool forge_DHT_get(socket_t socket, Key &key) {
    return true;
}

bool handle_DHT_get(socket_t socket) {
    const Value &connection_buffer = connection_map[socket].received_bytes;
    const size_t key_offset = HEADER_SIZE;

    // copy key into local var
    std::array<unsigned char, KEY_SIZE> key;
    std::copy_n(connection_buffer.cbegin() + key_offset, KEY_SIZE, std::begin(key));

    if (not is_in_my_range(key)) {
        // todo: Relay!!
        //--> Forward get_request with k-bucket table and await answer
        // 5. Forge answer to original peer (DHT_SUCCESS/DHT_FAILURE)
    }

    auto optVal = get_from_storage(key);
    if (optVal.has_value()) {
        // local storage hit, forge answer to requesting party:
        //forge_DHT_success(connection_info, optVal.value());
        // TODO: Queue send event in epoll, readied if EPOLLOUT
    } else {
        // local storage hit, forge answer to requesting party:
        //forge_DHT_failure(connection_info, optVal.value());
        // TODO: Queue send event in epoll, readied if EPOLLOUT
    }
    return true;
}

bool forge_DHT_success(socket_t socket, Key &key, Value &value) {
    return true;
}

bool handle_DHT_success(socket_t socket) {
    const Value &connection_buffer = connection_map[socket].received_bytes;
    // Currently received a frame for a relayed connection. Now, serve as relaying middlepoint and forward
    // message to correct peer (Client/Server, indistinguishable)
    const size_t key_offset = HEADER_SIZE;
    const size_t value_offset = key_offset + KEY_SIZE;
    // copy key into local var
    std::array<unsigned char, KEY_SIZE> key;
    std::copy_n(connection_buffer.begin() + key_offset, KEY_SIZE, std::begin(key));

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
    return true;
}

bool forge_DHT_failure(socket_t socket, Key &key) {
    return true;
}

bool handle_DHT_failure(socket_t socket) {
    const Value &connection_buffer = connection_map[socket].received_bytes;
    // copy key into dataframe
    const size_t key_offset = HEADER_SIZE;
    // copy key into local var
    std::array<unsigned char, KEY_SIZE> key;
    std::copy_n(connection_buffer.begin() + key_offset, KEY_SIZE, std::begin(key));

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
    return true;
}


// P2P/RPC handling+construction functions

bool forge_DHT_RPC_ping(socket_t socket) {
    // TODO: assumes connectionMap contains socket
    Key rpc_id = generate_random_nodeID();

    size_t body_size = 32;
    size_t message_size = HEADER_SIZE + body_size;
    u_short message_type = DHT_RPC_PING;
    Message message(message_size);

    build_DHT_header(body_size, message_type, message);

    write_body(message, 0, rpc_id.data(), RPC_ID_SIZE);

    connection_map.at(socket).rpc_id = rpc_id;

    return forge_DHT_message(socket, message);
}

bool handle_DHT_RPC_ping(const socket_t socket, const u_short body_size) {
    const Message& message = connection_map[socket].received_bytes;

    // forgeDHTPingReply(connection_info, rpc_id);
    return true;
}

bool forge_DHT_RPC_ping_reply(socket_t socket, Key rpc_id) {
    return true;
}

// TODO: following functions even necessary? Should answers be waited upon in the respective switch-cases?
bool handle_DHT_RPC_ping_reply(const socket_t socket, const u_short body_size) {
    const Message& message = connection_map[socket].received_bytes;
    if (!check_rpc_id(message, connection_map[socket].rpc_id)) {
        return false;
    }
    return true;
}

bool forge_DHT_RPC_store(socket_t socket, u_short time_to_live, int replication, Key &key, Value &value) {
    Key rpc_id = generate_random_nodeID();

    size_t body_size = RPC_ID_SIZE + KEY_SIZE + value.size();
    size_t message_size = HEADER_SIZE + body_size;
    u_short message_type = DHT_RPC_STORE;
    Message message(message_size);

    build_DHT_header(body_size, message_type, message);

    write_body(message, 0, rpc_id.data(), RPC_ID_SIZE);
    u_short network_order_TTL = htons(time_to_live);
    write_body(message, RPC_ID_SIZE, reinterpret_cast<unsigned char*>(&network_order_TTL), 2);
    auto replication_data = static_cast<unsigned char>(replication & 0xFF);
    write_body(message, RPC_ID_SIZE + 2, &replication_data, 1);
    write_body(message, RPC_ID_SIZE + 4, key.data(), KEY_SIZE);
    write_body(message, RPC_ID_SIZE + 4 + KEY_SIZE, value.data(), value.size());

    connection_map.at(socket).rpc_id = rpc_id;

    return forge_DHT_message(socket, message);
}

bool handle_DHT_RPC_store(const socket_t socket, const u_short body_size) {
    if (body_size <= RPC_ID_SIZE + 4 + KEY_SIZE) {
        return false;
    }
    const Message& message = connection_map[socket].received_bytes;
    int value_size = body_size - (RPC_ID_SIZE + 4 + KEY_SIZE);

    Key rpc_id;
    read_body(message, 0, rpc_id.data(), RPC_ID_SIZE);
    u_short network_order_TTL;
    read_body(message, RPC_ID_SIZE, reinterpret_cast<unsigned char*>(&network_order_TTL), 2);
    int time_to_live = ntohs(network_order_TTL);
    unsigned char replication_data;
    read_body(message, RPC_ID_SIZE + 2, &replication_data, 1);
    int replication = static_cast<int>(replication_data);
    Key key;
    read_body(message, RPC_ID_SIZE + 4, key.data(), KEY_SIZE);
    Value value;
    read_body(message, RPC_ID_SIZE + 4 + KEY_SIZE, value.data(), value_size);

    if (time_to_live > MAXLIFETIMESEC || time_to_live < MINLIFETIMESEC) {
        // default time to live, as value is out of lifetime bounds
        time_to_live = DEFAULTLIFETIMESEC;
    }

    // TODO: If closer nodes exist in routing_table and not inside churn_radius, don't save
    save_to_storage(key, std::chrono::seconds(time_to_live), value);

    return forge_DHT_RPC_store_reply(socket, rpc_id, key, value);
}

bool forge_DHT_RPC_store_reply(socket_t socket, Key rpc_id, Key &key, Value &value) {
    u_short message_type = DHT_RPC_STORE_REPLY;
    size_t body_size = RPC_ID_SIZE + KEY_SIZE;
    size_t message_size = HEADER_SIZE + body_size;
    Message message(message_size);

    build_DHT_header(body_size, message_type, message);
    write_body(message, 0, rpc_id.data(), RPC_ID_SIZE);
    write_body(message, RPC_ID_SIZE, key.data(), KEY_SIZE);
    write_body(message, RPC_ID_SIZE + KEY_SIZE, value.data(), value.size());

    return forge_DHT_message(socket, message);
}

bool handle_DHT_RPC_store_reply(const socket_t socket, const u_short body_size) {
    if (body_size <= RPC_ID_SIZE + KEY_SIZE) {
        return false;
    }
    const Message& message = connection_map[socket].received_bytes;
    if (!check_rpc_id(message, connection_map[socket].rpc_id)) {
        return false;
    }
    // TODO: maybe check if returned value is same as sent
    return true;
}

bool forge_DHT_RPC_find_node(socket_t socket, NodeID node_id) {
    Key rpc_id = generate_random_nodeID();

    size_t body_size = 32 + 32;
    size_t message_size = HEADER_SIZE + body_size;
    u_short message_type = DHT_RPC_FIND_NODE;
    Message message(message_size);

    build_DHT_header(body_size, message_type, message);

    write_body(message, 0, rpc_id.data(), RPC_ID_SIZE);
    write_body(message, RPC_ID_SIZE, node_id.data(), NODE_ID_SIZE);

    connection_map.at(socket).rpc_id = rpc_id;

    return forge_DHT_message(socket, message);
}

bool handle_DHT_RPC_find_node(const socket_t socket, const u_short body_size) {
    if (body_size != 64) {
        return false;
    }
    const Message& message = connection_map[socket].received_bytes;

    Key rpc_id;
    read_body(message, 0, rpc_id.data(), RPC_ID_SIZE);
    NodeID target_node_id;
    read_body(message, RPC_ID_SIZE, target_node_id.data(), NODE_ID_SIZE);

    // find closest nodes, then return them:
    auto closest_nodes = routing_table.find_closest_nodes(target_node_id);
    return forge_DHT_RPC_find_node_reply(socket, rpc_id, closest_nodes);
}

bool forge_DHT_RPC_find_node_reply(socket_t socket, Key rpc_id,  std::vector<Node> closest_nodes) {
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
        u_short port_network_order = htons(node.port);
        write_body(message, RPC_ID_SIZE + i*NODE_SIZE + 16, reinterpret_cast<unsigned char*>(&port_network_order), 2);
        write_body(message, RPC_ID_SIZE + i*NODE_SIZE + 16 + 2, node.id.data(), 32);
    }

    return forge_DHT_message(socket, message);
}


bool handle_DHT_RPC_find_node_reply(const socket_t socket, const u_short body_size) {
    if ((body_size - 32) % NODE_SIZE != 0) {
        return false;
    }
    int num_nodes = (body_size - 32) / NODE_SIZE;
    std::set<Node> closest_nodes{};
    const Message& message = connection_map[socket].received_bytes;
    if (!check_rpc_id(message, connection_map[socket].rpc_id)) {
        return false;
    }
    for (int i = 0; i < num_nodes; i++) {
        Node node{};

        read_body(message, i*NODE_SIZE, node.addr.s6_addr, 16);
        read_body(message, i*NODE_SIZE + 16, reinterpret_cast<unsigned char*>(&node.port), 2);
        node.port = ntohs(node.port);
        read_body(message, i*NODE_SIZE + 16 + 2, node.id.data(), 32);

        closest_nodes.insert(node);
        if (node.id != routing_table.get_local_node().id) {
            routing_table.add_peer(node);
        }
    }
    std::cout << "Got back " << closest_nodes.size() << " nodes." << std::endl;

    return true;
}

bool forge_DHT_RPC_find_value(socket_t socket, Key &key) {
    Key rpc_id = generate_random_nodeID();

    size_t body_size = RPC_ID_SIZE + KEY_SIZE;
    size_t message_size = HEADER_SIZE + body_size;
    u_short message_type = DHT_RPC_FIND_VALUE;
    Message message(message_size);

    build_DHT_header(body_size, message_type, message);

    write_body(message, 0, rpc_id.data(), RPC_ID_SIZE);
    write_body(message, RPC_ID_SIZE, key.data(), KEY_SIZE);

    connection_map.at(socket).rpc_id = rpc_id;

    return forge_DHT_message(socket, message);
}

bool handle_DHT_RPC_find_value(const socket_t socket, const u_short body_size) {
    if (body_size != RPC_ID_SIZE + KEY_SIZE) {
        return false;
    }
    const Message& message = connection_map[socket].received_bytes;

    Key rpc_id;
    read_body(message, 0, rpc_id.data(), RPC_ID_SIZE);
    Key key;
    read_body(message, RPC_ID_SIZE, key.data(), KEY_SIZE);

    auto opt_val = get_from_storage(key);
    if (opt_val.has_value()) {
        return forge_DHT_RPC_find_value_reply(socket, rpc_id, key, opt_val.value());
    } else {
        // TODO: What if we're closest and don't have value -> return FAILURE
        auto closest_nodes = routing_table.find_closest_nodes(key);
        return forge_DHT_RPC_find_node_reply(socket, rpc_id, closest_nodes);
    }
}

bool forge_DHT_RPC_find_value_reply(socket_t socket, Key rpc_id, Key &key, Value &value) {
    u_short message_type = DHT_RPC_FIND_VALUE_REPLY;
    size_t body_size = RPC_ID_SIZE + KEY_SIZE + value.size();
    size_t message_size = HEADER_SIZE + body_size;
    Message message(message_size);

    build_DHT_header(body_size, message_type, message);

    write_body(message, 0, rpc_id.data(), RPC_ID_SIZE);
    write_body(message, RPC_ID_SIZE, key.data(), KEY_SIZE);
    write_body(message, RPC_ID_SIZE + KEY_SIZE, value.data(), value.size());

    return forge_DHT_message(socket, message);
}

bool handle_DHT_RPC_find_value_reply(const socket_t socket, const u_short body_size) {
    if (body_size <= RPC_ID_SIZE + KEY_SIZE) {
        return false;
    }
    const Message& message = connection_map[socket].received_bytes;

    Key rpc_id;
    read_body(message, 0, rpc_id.data(), RPC_ID_SIZE);

    if (!check_rpc_id(message, connection_map[socket].rpc_id)) {
        return false;
    }

    Key key;
    read_body(message, RPC_ID_SIZE, key.data(), KEY_SIZE);
    Value value;
    read_body(message, RPC_ID_SIZE + KEY_SIZE, value.data(), body_size - (RPC_ID_SIZE + KEY_SIZE));

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
    const Message &connection_buffer = connection_info.received_bytes;
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
            handle_DHT_put(socket);
        break;
            }
        case DHT_GET:
            {
            handle_DHT_get(socket);
        break;
            }
        case DHT_SUCCESS:
            {
            handle_DHT_success(socket);
        break;
            // Close connection (was only for relaying!)
            }
        case DHT_FAILURE:
            {
            handle_DHT_failure(socket);
        break;
            }

        default:
            break;
        }
    }
    return true;
}

bool parse_P2P_request(socket_t socket, const u_short body_size, const P2PType p2p_type) {
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
    auto &connection_buffer = connection_info.received_bytes;
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

    if (connection_info.connection_type == ConnectionType::MODULE_API) {
        ModuleApiType module_api_type;
        if (is_valid_module_API_type(dht_type)) {
            module_api_type = static_cast<ModuleApiType>(dht_type);
        } else {
            std::cerr << "Tried to send invalid request to Module API Server. Aborting." << std::endl;
            return ProcessingStatus::ERROR;
        }
        // TODO: Pass socket instead of connection info
        request_successful = parse_API_request(curfd, body_size, module_api_type);
    } else if (connection_info.connection_type == ConnectionType::P2P) {
        P2PType p2p_type;
        if (is_valid_P2P_type(dht_type)) {
            p2p_type = static_cast<P2PType>(dht_type);
        } else {
            std::cerr << "Tried to send invalid request to P2P Server. Aborting." << std::endl;
            return ProcessingStatus::ERROR;
        }
        request_successful = parse_P2P_request(curfd, body_size, p2p_type);
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


void accept_new_connection(int epollfd, std::vector<epoll_event>::value_type cur_event, ConnectionType connection_type) {
    // accept new client connections from serverside
    socket_t socket = accept4(cur_event.data.fd, nullptr, nullptr, SOCK_NONBLOCK);
    if (!socket) {
        // Accept-Error
        return;
    }
    auto epollEvent = epoll_event{};
    epollEvent.events = EPOLLIN | EPOLLOUT | EPOLLERR;
    epollEvent.data.fd = socket;
    epoll_ctl(epollfd, EPOLL_CTL_ADD, socket, &epollEvent);
    connection_map.insert_or_assign(socket, ConnectionInfo{connection_type});
}



void handle_EPOLLOUT(auto epollfd, socket_t notifying_socket){
    ConnectionInfo connection_info = connection_map.at(notifying_socket);
    if(connection_info.send_bytes.size() == 0){
        return;
    }

    if(connection_info.sent_bytes < connection_info.send_bytes.size()){
        //Not all bytes were sent in a previous attemt to write the full message to the socket

        int written_bytes = write(notifying_socket,
                                    &(connection_info.send_bytes.at(connection_info.sent_bytes)),
                                    connection_info.send_bytes.size() - connection_info.sent_bytes);

        if(written_bytes == -1 && errno == EWOULDBLOCK){
            //Wait for new EPOLLOUT event. Buffer was full. This is considered a dead branch... Should not happen.
            std::cout << "Reached a considered dead branch. in handle_EPOLLOUT(epollfd,notifying_socket)" << std::endl;
            return;
        } 
        else if (written_bytes == -1){
            //Faulty connection. Remove relayTos, then remove it.
            std::cout << "Faulty connection detected while trying to send data. Closed it and all relayTo connections." << std::endl;
            if(connection_info.relay_to != -1) {
                auto relay_to_socket = connection_info.relay_to;
                epoll_ctl(epollfd,EPOLL_CTL_DEL,relay_to_socket,nullptr);
                close(relay_to_socket);
            }
            epoll_ctl(epollfd,EPOLL_CTL_DEL,notifying_socket,nullptr);
            close(notifying_socket);
            return;
        }

        assert(written_bytes > 0);

        connection_info.sent_bytes += written_bytes;
        //TODO: Unset the relayto field as soon as all answers have arrived (referring to concurrent lookups) (receiving event)
        
        //TODO: Check if i am initiator, if yes, keep connection open (wait for receiving). Otherwise, close connection (I was waiting, so i have received what i waited for).
    
    } else{
        //all bytes were sent. Nothing to do except for performing a hard-reset to default sent-fields.
        connection_info.send_bytes.clear();
        connection_info.sent_bytes = 0;
    }
}

void handle_EPOLLIN(auto epollfd, socket_t notifying_socket){
    std::cout << "Received new request." << std::endl;
    std::array<unsigned char, 4096> recv_buf{};
    auto curfd = curEvent.data.fd;
    if (!connection_map.contains(curfd)) {
        connection_map.insert_or_assign(curfd, ConnectionInfo{});
    }
    auto &connection_buffer = connection_map.at(curfd).received_bytes;
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
            connection_map.erase(curfd);
            break;
        }
        connection_buffer.insert(connection_buffer.end(), recv_buf.begin(),
                                    recv_buf.begin() + bytesRead);

        std::cout << std::string_view(reinterpret_cast<const char *>(recv_buf.data()), bytesRead) << "\n";
    }
}


// Network/Socket functions

int setup_epoll(int epollfd, socket_t serversocket) {
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
    if (bind(serversocket, reinterpret_cast<sockaddr *>(&sock_addr),sizeof(sock_addr)) != 0) {
        std::cerr << "Failed to bind port " << port << ". Try to pass a different port." << std::endl;
    }
    listen(serversocket, 128);
    return serversocket;
}

socket_t setup_connect_socket(std::string address_string, u_short port) {
    socket_t peer_socket = socket(AF_INET6, SOCK_STREAM, 0);
    if (peer_socket == -1) {
        std::cerr << "Failed to create client socket on port " << port << "." << std::endl;
        return -1;
    }

    sockaddr_in6 address{};
    if (!convert_to_ipv6(address_string, address.sin6_addr)) {
        std::cerr << "Invalid address" << std::endl;
        close(peer_socket);
        return -1;
    }

    static constexpr int ONE = 1;
    setsockopt(peer_socket, SOL_SOCKET, SO_KEEPALIVE, &ONE, sizeof(ONE));



    address.sin6_family = AF_INET6;
    address.sin6_port = htons(port);

    if (connect(peer_socket, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) == -1) {
        std::cerr << "Couldn't connect to peer." << std::endl;
        close(peer_socket);
        return -1;
    }
    int flags = fcntl(peer_socket, F_GETFL, 0);
    if (!(flags & O_NONBLOCK )) {
        flags |= O_NONBLOCK;
    }
    fcntl(peer_socket, F_SETFL, flags);
    return peer_socket;
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


    routing_table = RoutingTable(host_address, host_p2p_port);



    // Open port for local API traffic from modules
    signal(SIGPIPE, SIG_IGN);

    socket_t module_api_socket = setup_server_socket(host_module_port);
    int epollfd = epoll_create1(0);
    epollfd = setup_epoll(epollfd, module_api_socket);
    socket_t p2p_socket = setup_server_socket(host_p2p_port);
    epollfd = setup_epoll(epollfd, p2p_socket);
    std::vector<epoll_event> epoll_events{64};

    if (epollfd == -1 || module_api_socket == -1 || p2p_socket == -1) {
        std::cerr << "Error creating sockets. Aborting." << std::endl;
        return 1;
    }

    std::cout << "Server running... " << std::endl;
    bool serverIsRunning = true;
    if(connect_to_existing_network) {
        // TODO: connect to existing network
        // TODO: setup socket + add to connection_map, then call:
        std::cout << "Sending Find Node Request..." << std::endl;
        socket_t peer_socket = setup_connect_socket(peer_address_string, peer_port);

        setup_epoll(epollfd, peer_socket);
        if (peer_socket == -1) {
            std::cerr << "Error creating socket. Aborting." << std::endl;
            return -1;
        }
        connection_map[peer_socket] = {ConnectionType::P2P};

        forge_DHT_RPC_find_node(peer_socket, routing_table.get_local_node().id);
        // 1. Send FIND_NODE RPC about our own node to peer (TODO: Don't immediately put our triple in peer's bucket list or else it won't return closer peers but us?)
        // 3. If response includes our own, we have no closer nodes, otherwise we get closer nodes to us
        // 4. Iterate over ever closer nodes
        // 5. Meanwhile, populate K_Buckets with ever closer nodes
        // 6. For Nodes farther away, do "refreshing" of random NodeID's in the respective ranges
        //    (choose closest nodes and send them find_node rpcs with the randomly generated NodeID's in said range)

    }

    // event loop

    while (serverIsRunning) {
        int event_count = epoll_wait(epollfd, epoll_events.data(), std::ssize(epoll_events), -1);  // dangerous cast
        // TODO: ADD SERVER MAINTAINENCE. purge storage (ttl), peer-ttl (k-bucket
        // maintainence) internal management clean up local_storage for all keys,
        // std::erase if ttl is outdated

        if (event_count == -1) {
            serverIsRunning = false;
            break;
        }
        for (int i = 0; i < event_count; ++i) {
            auto curEvent = epoll_events[i];
            if (curEvent.data.fd == module_api_socket) {
                accept_new_connection(epollfd, curEvent, ConnectionType::MODULE_API);
            } else if (curEvent.data.fd == p2p_socket) {
                accept_new_connection(epollfd, curEvent, ConnectionType::P2P);
            } else {
                // handle client processing of existing seassions
                if (curEvent.events & EPOLLIN)
                    handle_EPOLLIN(epollfd,curEvent.data.fd);
                if (curEvent.events & EPOLLOUT)
                    handle_EPOLLOUT(epollfd,curEvent.data.fd);
                if (curEvent.events & EPOLLERR){
                    epoll_ctl(epollfd, EPOLL_CTL_DEL, curEvent.data.fd, nullptr);
                    connection_map.erase(curEvent.data.fd);
                }
            }
        }
    }

    std::cout << "Server terminating." << std::endl;
    return 0;
}
#endif