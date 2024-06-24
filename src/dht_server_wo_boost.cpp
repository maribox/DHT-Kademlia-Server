#include "dht_server_wo_boost.h"

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

std::map<keyType,std::pair<std::chrono::time_point<std::chrono::system_clock>, valueType>> local_storage{};
std::mutex storage_lock;

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

void save_to_storage(const keyType &key, std::chrono::seconds ttl, valueType val)
{
    std::lock_guard<std::mutex> lock(storage_lock);

    auto fresh_insert = local_storage.insert_or_assign(key, std::pair{std::chrono::system_clock::now() + ttl,val});
    // Log fresh_insert. True equiv. to "New value created". False equiv. to
    // "Overwritten, assignment"
}


void parseRequest(std::shared_ptr<std::array<char, 320UL>> rec_buf,size_t bytesReceived) {
    //if (bytesReceived < 32) --> Critical, message header torn apart
    //See specification for all bit-fields, their size and interpretation.
    u_short *short_rec_buf = (u_short *) rec_buf->data();

    //Size and dht_tye are at invariant positions.
    u_short size = short_rec_buf[0];
    u_short dht_type = short_rec_buf[1];
    //key is always transmitted, at different positions.
    std::vector<char> data;

    ReceiveFrame rf{short_rec_buf[0],short_rec_buf[1]};


    //GIGANTIC SWITCH CASE, HANDLE LOGIC OF REQUESTS.
    switch (dht_type)
    {
    case DHTServerConfig::DHT_PUT:
        {
        rf.time_to_live  = short_rec_buf[2];
        rf.replication = rec_buf->at(6);
        rf.reserved = rec_buf->at(7);
        //copy key into dataframe
        std::copy_n(rec_buf->begin() + 8, KEYSIZE, std::begin(rf.key));

        //copy value into dataframe
        size_t data_size = rec_buf->end() - (rec_buf->begin() + (8+KEYSIZE)) ;
        rf.value.reserve(data_size);
        std::copy_n(rec_buf->begin() + 8 + KEYSIZE, data_size, std::back_inserter(rf.value));
        if(isInMyRange(rf.key)){
            //send_dht_success()
        }
        //1. kademlia logic, ID in my range?
        //2. Yes? --> Save to value local storage
        //3. No? Consider Replication field:
        //                                  --> With replication factor in range?
        //                                  --> Yes? --> Save to value local storage
        //4. No --> Forward put_request with k-bucket table and await answer
        //5. Forge answer to original peer (DHT_SUCCESS/DHT_FAILURE)
        break;
        }
    case DHTServerConfig::DHT_GET:
        {
        //copy key into dataframe
        std::copy_n(rec_buf->begin() + 4, KEYSIZE, std::begin(rf.key));
        //1. kademlia logic, ID in my range?
        //2. Yes? --> Retreive value from local storage
        //   No?  --> Forward request with k-bucket table
        //3. Forge answer to original peer (DHT_SUCCESS/DHT_FAILURE)
            //3. Forge answer to original peer (DHT_SUCCESS/DHT_FAILURE)
        break;}
    
    case DHTServerConfig::DHT_SUCCESS:
        {
        //copy key into dataframe
        std::copy_n(rec_buf->begin() + 4, KEYSIZE, std::begin(rf.key));

        //copy value into dataframe
        size_t data_size = rec_buf->end() - (rec_buf->begin() + (4+KEYSIZE));
        rf.value.reserve(data_size);
        std::copy_n(rec_buf->begin() + 4 + KEYSIZE, data_size, std::back_inserter(rf.value));
        
        // Was the value intended for me?
        // Yes? --> Forward to my client.
        // No? --> Forward answer to original peer
        break;}
    case DHTServerConfig::DHT_FAILURE:
        {
        //copy key into dataframe
        std::copy_n(rec_buf->begin() + 4, KEYSIZE, std::begin(rf.key));

        // Was the value intended for me?
        // Yes? --> Forward to my client.
        // No? --> Forward answer to original peer
        break;}
    
    default:
        break;
    }

    
}

bool send_dht_success(socket_t socket, keyType key, valueType value); // TODO

bool send_dht_failure(socket_t socket, keyType key); // TODO


#ifndef TESTING

int main(int argc, char const *argv[])
{
    u_short port = DHTServerConfig::DHT_PORT;
    std::string host_string = {};

    try
    {
        // Argument parsing:
        // Use boost::program_options for parsing:
        progOpt::options_description desc{"Run a DHT module mockup with local storage.\n\nMultiple API clients can connect to this same instance."};
        desc.add_options()("help,h", "Help screen")("address,a", progOpt::value<std::string>(&host_string), "Bind server to this address")("port,p", progOpt::value<u_short>(&port), "Bind server to this port")("unreg", "Unrecognized options");
        progOpt::positional_options_description pos_desc;
        pos_desc.add("address", 1);
        pos_desc.add("port", 1);

        progOpt::command_line_parser parser{argc, argv};
        parser.options(desc).allow_unregistered().style(progOpt::command_line_style::default_style |
                                                        progOpt::command_line_style::allow_slash_for_short);
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
        // Parsing complete
    }
    catch (std::exception excep)
    {
        std::cerr << excep.what() << '\n';
        std::cout << boost::stacktrace::stacktrace();
        return -1;
    }

    // Setting up Routing Table
    //auto routing_table = RoutingTable(generateRandomNodeID(), host, port);

    // std::cout << "Host: " << "127.0.0.1" << "\n"
    //           << "Port: " << port << "\n"
    //           << "NodeID" << key_to_string(routing_table.get_node_id()) << "\n";
    
    //start_accepting(acceptor);
    bool serverIsRunning = true;

    struct ConnectionInfo{
        std::vector<char> receivedBytes;
        std::vector<char> sendBytes; //This is a todo send buffer. See epoll case EPOLLOUT.
        socket_t relayTo{-1}; //Possibly relay the request to other server that sits closer (XOR) to the requested key.
    };


    std::unordered_map<int,ConnectionInfo> connectionMap;
    int one = 1;
    socket_t serversocket = socket(AF_INET6,SOCK_STREAM,0);
    
    setsockopt(serversocket,SOL_SOCKET,SO_REUSEPORT,&one,sizeof(one));
    setsockopt(serversocket,SOL_SOCKET,SO_KEEPALIVE,&one,sizeof(one));

    sockaddr_in6 sock_addr;
    sock_addr.sin6_family = AF_INET6;
    sock_addr.sin6_port = htons(DHTServerConfig::DHT_PORT);
    sock_addr.sin6_addr = in6addr_any;
    bind(serversocket,reinterpret_cast<sockaddr*>(&sock_addr),sizeof(sock_addr)); //TODO Error-checking
    listen(serversocket,128);

    auto epollfd = epoll_create1(0);
    //TODO SSL

    auto epollEvent = epoll_event{};
    epollEvent.events = EPOLLIN;
    epollEvent.data.fd = serversocket;
    epoll_ctl(epollfd,EPOLL_CTL_ADD,serversocket,&epollEvent);
    std::vector<epoll_event> eventsPerLoop{64};

    //NEW
    while(serverIsRunning){
        int eventCount = epoll_wait(epollfd,eventsPerLoop.data(),std::ssize(eventsPerLoop),-1); //dangerous cast
        //internal management
        //clean up local_storage
        //for all keys, std::erase if ttl is outdated

        if (eventCount == -1){
            serverIsRunning = false;
            break;
        }
        for(int i = 0; i < eventCount; ++i){
            auto curEvent = eventsPerLoop[i];
            if(curEvent.data.fd == serversocket){
                socket_t client_socket = accept4(curEvent.data.fd,nullptr,nullptr,SOCK_NONBLOCK);
                if(!client_socket){
                    //Accept-Error
                    continue;
                }
                auto epollEvent = epoll_event{};
                epollEvent.events = EPOLLIN | EPOLLOUT | EPOLLERR;
                epollEvent.data.fd = client_socket;
                epoll_ctl(epollfd,EPOLL_CTL_ADD,client_socket,&epollEvent);
            }else{
                //client processing
                if(curEvent.events & EPOLLIN){
                    std::array<char,4096> recv_buf{};
                    auto curfd = curEvent.data.fd;
                    auto &connectionBuffer = connectionMap.at(curfd).receivedBytes;
                    while(true){
                        auto bytesRead = read(curfd,recv_buf.data(),recv_buf.size());
                        if(bytesRead==0){
                            //Finished reading, try processing. Watch out for maybe incomplete message. TODO.
                            break;
                        }
                        else if (bytesRead == -1){
                            epoll_ctl(epollfd,EPOLL_CTL_DEL,curfd,nullptr);
                            connectionMap.erase(curfd);
                            break;
                        }
                        connectionBuffer.insert(connectionBuffer.end(),recv_buf.begin(), recv_buf.begin() + bytesRead);

                        std::cout << std::string_view(recv_buf.data(),bytesRead) << "\n";
                    }
                }
                if(curEvent.events & EPOLLOUT){
                    //partial output. Send rest of answer
                }
                if(curEvent.events & EPOLLERR){
                    epoll_ctl(epollfd,EPOLL_CTL_DEL,curEvent.data.fd,nullptr);
                    connectionMap.erase(curEvent.data.fd);
                    continue;
                }
            }
        }
    }

    return 0;
}

#endif