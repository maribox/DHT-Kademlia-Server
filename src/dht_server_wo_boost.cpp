#include "dht_server_wo_boost.h"
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


std::map<keyType,std::pair<std::chrono::time_point<std::chrono::system_clock>, valueType>> local_storage{};
std::mutex storage_lock;

RoutingTable routing_table;

bool isInMyRange(keyType key){
    return true;
}

std::string key_to_string(const keyType &key) {
    std::string str{};
        
    for (auto it = key.cbegin() ; it < key.end(); it++) {
        str += *it;
    }
    return str;
}

// Returns optional value, either the correctly looked up value, or no value.
std::optional<valueType> get_from_storage(const keyType &key)
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

void save_to_storage(const keyType &key, std::chrono::seconds ttl, valueType &val)
{
    std::lock_guard<std::mutex> lock(storage_lock);

    auto fresh_insert = local_storage.insert_or_assign(key, std::pair{std::chrono::system_clock::now() + ttl,val});
    // Log fresh_insert. True equiv. to "New value created". False equiv. to
    // "Overwritten, assignment"
}

bool send_dht_success(socket_t socket, keyType key, valueType value); // TODO

bool send_dht_failure(socket_t socket, keyType key); // TODO

bool forgeDHTSuccess(ConnectionInfo &connectInfo, const valueType &value){
    //TODO
    //Save buffer into connectInfo
    return true;
};

bool forgeDHTFailure(ConnectionInfo &connectInfo, const valueType &value){
    //TODO
    //Save buffer into connectInfo
    return true;
};



bool parseHeader(ConnectionInfo &connectInfo, u_short &messageSize, u_short &dhtType){
    std::vector<unsigned char> &connectionBuffer = connectInfo.receivedBytes;
    u_short msg_size = 0;
    u_short dht_type = 0;

    msg_size += connectionBuffer[0];
    msg_size <<= 8;
    msg_size += connectionBuffer[1];
    /*The message is expected to not even contain a key.
    All messages that adhere to protocol require a key sent.*/
    if(msg_size < KEYSIZE){
        return false;
    }

    msg_size += connectionBuffer[2];
    msg_size <<= 8;
    msg_size += connectionBuffer[3];
    /*The dht_type that was transmitted is not in the range of expected types*/
    if(dht_type < DHT_PUT || dht_type > DHT_FAILURE ){
        return false;
    }
    //Both fields contain possible values.
    messageSize = msg_size;
    dhtType = dht_type;
    return true;
}

bool parseFullRequest(ConnectionInfo &connectInfo, const u_short messageSize, const u_short dhtType){
    valueType &connectionBuffer = connectInfo.receivedBytes;
    switch (dhtType){
        {
        case DHT_PUT:
            {
            handleDHTPUT(connectInfo);
        break;
            }
        case DHT_GET:
            {
            handleDHTGET(connectInfo);
        break;
            }
        case DHT_SUCCESS:
            {
            handleDHTSUCCESS(connectInfo);
        break;
            // Close connection (was only for relaying!)
            }
        case DHT_FAILURE:
            {
            handleDHTFAILURE(connectInfo);
        break;
            }
        case DHT_RPC_PING:
            handleDHTRPCPing(connectInfo);
        break;
        case DHT_RPC_STORE:
            handleDHTRPCStore(connectInfo);
        break;
        case DHT_RPC_FIND_NODE:
            handleDHTRPCFindNode(connectInfo);
        break;
        case DHT_RPC_FIND_VALUE:
            handleDHTRPCFindValue(connectInfo);
        break;

        case DHT_RPC_PING_REPLY:
            handleDHTRPCPingReply(connectInfo);
        break;
        case DHT_RPC_STORE_REPLY:
            handleDHTRPCStoreReply(connectInfo);
        break;
        case DHT_RPC_FIND_NODE_REPLY:
            handleDHTRPCFindNodeReply(connectInfo);
        break;
        case DHT_RPC_FIND_VALUE_REPLY:
            handleDHTRPCFindValueReply(connectInfo);
        break;
        case DHT_ERROR:
            handleDHTError(connectInfo);
        break;
        default:
            break;
        }
    }
    return true;
}
void handleDHTFAILURE(ConnectionInfo &connectInfo) {
    const valueType &connectionBuffer = connectInfo.receivedBytes;
    // copy key into dataframe
    const size_t key_offset = HEADERSIZE;
    // copy key into local var
    std::array<unsigned char, KEYSIZE> key;
    std::copy_n(connectionBuffer.begin() + key_offset, KEYSIZE, std::begin(key));

    if (!isInMyRange(key)) {
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
void handleDHTSUCCESS(ConnectionInfo &connectInfo) {
    const valueType &connectionBuffer = connectInfo.receivedBytes;
    // Currently received a frame for a relayed connection. Now, serve as relaying middlepoint and forward
    // message to correct peer (Client/Server, indistinguishable)
    const size_t key_offset = HEADERSIZE;
    const size_t value_offset = key_offset + KEYSIZE;
    // copy key into local var
    std::array<unsigned char, KEYSIZE> key;
    std::copy_n(connectionBuffer.begin() + key_offset, KEYSIZE, std::begin(key));

    if (!isInMyRange(key)) {
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
void handleDHTGET(ConnectionInfo &connectInfo) {
    const valueType &connectionBuffer = connectInfo.receivedBytes;
    const size_t key_offset = HEADERSIZE;

    // copy key into local var
    std::array<unsigned char, KEYSIZE> key;
    std::copy_n(connectionBuffer.cbegin() + key_offset, KEYSIZE, std::begin(key));

    if (not isInMyRange(key)) {
        // todo: Relay!!
        //--> Forward get_request with k-bucket table and await answer
        // 5. Forge answer to original peer (DHT_SUCCESS/DHT_FAILURE)
    }

    auto optVal = get_from_storage(key);
    if (optVal.has_value()) {
        // local storage hit, forge answer to requesting party:
        forgeDHTSuccess(connectInfo, optVal.value());

        // TODO: Queue send event in epoll, readied if EPOLLOUT
    } else {
        // local storage hit, forge answer to requesting party:
        forgeDHTFailure(connectInfo, optVal.value());
        // TODO: Queue send event in epoll, readied if EPOLLOUT
    }
}
void handleDHTPUT(ConnectionInfo &connectInfo) {
    const valueType &connectionBuffer = connectInfo.receivedBytes;
    const size_t ttl_offset = HEADERSIZE;
    const size_t key_offset = ttl_offset + 4;
    const size_t value_offset = key_offset + KEYSIZE;

    // copy key into local var
    std::array<unsigned char, KEYSIZE> key;
    std::copy_n(connectionBuffer.cbegin() + key_offset, KEYSIZE, std::begin(key));

    if (not isInMyRange(key)) {
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
    std::vector<unsigned char> value;
    value.reserve(value_size);
    std::copy_n(connectionBuffer.cbegin() + value_offset, value_size, std::begin(value));

    save_to_storage(key, std::chrono::seconds(time_to_live), value);
}
void handleDHTRPCPing(const ConnectionInfo& connectInfo) {
    const valueType &connectionBuffer = connectInfo.receivedBytes;
    const size_t rpc_id_offset = HEADERSIZE;
        
    // forgeDHTPingReply(connectInfo, rpc_id);
}
void handleDHTRPCStore(const ConnectionInfo& connectInfo) {
    const valueType &connectionBuffer = connectInfo.receivedBytes;
    const size_t rpc_id_offset = HEADERSIZE;
    const size_t ttl_offset = rpc_id_offset + 32;
    const size_t key_offset = ttl_offset + 2;
    const size_t value_offset = key_offset + KEYSIZE;

    // TODO: look at DHT_STORE, also decide on difference of functionalities

    // forgeDHTStoreReply(connectInfo, rpc_id, key, value);
}
void handleDHTRPCFindNode(const ConnectionInfo& connectInfo) {
    const valueType &connectionBuffer = connectInfo.receivedBytes;
    const size_t rpc_id_offset = HEADERSIZE;
    const size_t node_id_offset = rpc_id_offset + 32;

    // find closest nodes, then return them:

    // forgeDHTFindNodeReply(connectInfo, rpc_id, closest_nodes);
}
void handleDHTRPCFindValue(const ConnectionInfo& connectInfo) {
    const valueType &connectionBuffer = connectInfo.receivedBytes;
    const size_t rpc_id_offset = HEADERSIZE;
    const size_t key_offset = rpc_id_offset + 32;

    keyType key;
    std::copy_n(connectionBuffer.begin() + key_offset, KEYSIZE, std::begin(key));



    auto optVal = get_from_storage(key);
    if (optVal.has_value()) {
        // forgeDHTFindValueReply(connectInfo, rpc_id, key, optVal.value());
    } else {
        // auto closest_nodes = find_closest_nodes(key);
        // forgeDHTFindNodeReply(connectInfo, rpc_id, closest_nodes);
    }
}

// TODO: following functions even necessary? Should answers be waited upon in the respective switch-cases?
void handleDHTRPCPingReply(const ConnectionInfo& connectInfo) {
}

void handleDHTRPCStoreReply(const ConnectionInfo& connectInfo) {
}

void handleDHTRPCFindNodeReply(const ConnectionInfo& connectInfo) {
}

void handleDHTRPCFindValueReply(const ConnectionInfo& connectInfo) {
}

void handleDHTError(const ConnectionInfo& connectInfo) {
    const size_t error_type_offset = HEADERSIZE;
    // TODO: extract error type, switch case based on that
}




ProcessingStatus tryProcessing(socket_t curfd){
    //retreive information for element to process:
    ConnectionInfo &connectInfo = connectionMap.at(curfd);
    auto &connectionBuffer = connectInfo.receivedBytes;
    size_t byteCountToProcess = connectionBuffer.size();
    if(connectionBuffer.size() == 0){
        /* i.e.: we got work to process (epoll event happened), the message buffer
        is empty, but all bytes of the kernel buffer were exhausted (server side).*/
        return ProcessingStatus::error;
    }
    if(connectionBuffer.size() < HEADERSIZE){
        return ProcessingStatus::waitForCompleteMessageHeader;
    }

    //Parse header:
    u_short body_size = -1;
    u_short dht_type = -1;

    bool headerSuccess = parseHeader(connectInfo, body_size, dht_type);
    if (not headerSuccess){
        return ProcessingStatus::error;
    }

    //Header was successfully parsed. Check if entire message is present:
    if(byteCountToProcess < HEADERSIZE + body_size){
        return ProcessingStatus::waitForCompleteMessageBody;
    }
    //Header was fully parsed and entire message is present. Do the "heavy lifting", parse received request semantically:
    
    bool parseSemanticSuccess = parseFullRequest(connectInfo, body_size, dht_type);

    //TODO: CHECK THIS RETURN!! Maybe false in future
    return ProcessingStatus::processed;
}

//#ifndef TESTING
int main(int argc, char const *argv[])
{
    u_short host_port = DHTServerConfig::DHT_PORT;
    std::string host_address_string = {};
    struct in6_addr host_address{};
    u_short peer_port = DHTServerConfig::DHT_PORT;
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
        if (vm.count("peer-address") && vm.count("peer-port")) {
            std::cout << "Connecting to existing network at " << peer_address_string << ":" << peer_port << std::endl;
            if (!convertToIPv6(peer_address_string, peer_address)) {
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

    if (!convertToIPv6(host_address_string, host_address)) {
        std::cerr << "Please provide a syntactically correct IP address (v4 or v6) for the host";
        return 1;
    }

    socket_t serversocket = setupSocket(DHTServerConfig::DHT_PORT);
    int epollfd = setupEpoll(serversocket);
    std::vector<epoll_event> eventsPerLoop{64};
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
        // 1. Add contact node (given with argv, should be in vars "peer_address:peer_port") to k_bucket_list
        // 2. Send FIND_NODE RPC about our own node to peer (TODO: Don't immediately put our triple in peer's bucket list or else it won't return closer peers but us?)
        // 3. If response includes our own, we have no closer nodes, otherwise we get closer nodes to us
        // 4. Iterate over ever closer nodes
        // 5. Meanwhile, populate K_Buckets with ever closer nodes
        // 6. For Nodes farther away, do "refreshing" of random NodeID's in the respective ranges
        //    (choose closest nodes and send them find_node rpcs with the randomly generated NodeID's in said range)


    }

    runEventLoop(serversocket, epollfd, eventsPerLoop);

    return 0;
}
//#endif

bool convertToIPv6(const std::string& address_string, struct in6_addr& address) {
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
            std::cout << "Converted address "  << address_string  << " to " << address_converted << std::endl;
        } catch (...) {
            std::cout << "Converted address " << address_string  << " but couldn't format." << std::endl;
        }
        return true;
    }
    return false;  // Invalid address
}


void runEventLoop(socket_t serversocket, int epollfd,
                  std::vector<epoll_event> &eventsPerLoop) {
    std::cout << "Server running... " << std::endl;
    bool serverIsRunning = true;
    while (serverIsRunning) {
        int eventCount = epoll_wait(epollfd, eventsPerLoop.data(), std::ssize(eventsPerLoop), -1);  // dangerous cast
        // TODO: ADD SERVER MAINTAINENCE. purge storage (ttl), peer-ttl (k-bucket
        // maintainence) internal management clean up local_storage for all keys,
        // std::erase if ttl is outdated

        if (eventCount == -1) {
            serverIsRunning = false;
            break;
        }
        for (int i = 0; i < eventCount; ++i) {
            auto curEvent = eventsPerLoop[i];
            if (curEvent.data.fd == serversocket) {
                // accept new client connections from serverside
                socket_t client_socket = accept4(curEvent.data.fd, nullptr, nullptr, SOCK_NONBLOCK);
                if (!client_socket) {
                    // Accept-Error
                    continue;
                }
                auto epollEvent = epoll_event{};
                epollEvent.events = EPOLLIN | EPOLLOUT | EPOLLERR;
                epollEvent.data.fd = client_socket;
                epoll_ctl(epollfd, EPOLL_CTL_ADD, client_socket, &epollEvent);
            } else {
                // handle client processing of existing seassions
                if (curEvent.events & EPOLLIN) {
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
                        if (bytesRead == 0) {
                            bool processingStatus = tryProcessing(curfd);
                            std::cout << "Processing finished: " << processingStatus
                                      << std::endl;
                            if (processingStatus == true) {
                                // epoll_ctl(epollfd,EPOLL_CTL_DEL,curfd,nullptr);
                            }
                            break;
                        } else if (bytesRead == -1) {
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

int setupEpoll(socket_t serversocket) {
    int epollfd = epoll_create1(0);
    // TODO SSL

    auto epollEvent = epoll_event{};
    epollEvent.events = EPOLLIN;
    epollEvent.data.fd = serversocket;
    epoll_ctl(epollfd, EPOLL_CTL_ADD, serversocket, &epollEvent);
    return epollfd;
}

socket_t setupSocket(u_short port) {
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
