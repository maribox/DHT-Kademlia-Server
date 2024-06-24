#include "dht_server.h"

#include <array>
#include <boost/asio.hpp>
#include <boost/multiprecision/cpp_int.hpp>
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

#include "routing.cpp"

/*
Important Remark: Maybe use a logger for keeping track of operations during runtime.
Boost provides one, seemingly a bit hard to setup, but anyways:
https://www.boost.org/doc/libs/1_82_0/libs/log/doc/html/index.html
*/
namespace progOpt = boost::program_options;
namespace asIp = boost::asio::ip;
using boost::asio::ip::tcp;

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

bool send_dht_success(const boost::asio::ip::address address, u_short port,
                       keyType key, valueType value); // TODO

bool send_dht_failure(const boost::asio::ip::address address, u_short port, keyType key); // TODO

void handle_connection(std::shared_ptr<tcp::socket> socket) {
    // Buffer for receiving incoming DHT_requests
    auto rec_buf = std::make_shared<std::array<char, 256 + 64>>();
    socket->async_receive(
        boost::asio::buffer(*rec_buf, 256 + 64),
        [rec_buf, socket](std::error_code ec, size_t bytesReceived) mutable {
            //Good, vital connection:
            if(!ec && bytesReceived > 0){
                //Here, add parsing for Kademliad DHT logic
                std::cout << "Received: " << bytesReceived << " Bytes: " << std::string_view(rec_buf->data(),bytesReceived) << std::endl;
                //parseRequest
                parseRequest(rec_buf,bytesReceived);
                handle_connection(socket);
            }
            else{
                //Somewhat wrong connection. Determine flaw:
                if(ec){
                    std::cout << "Handle_Connection Error: " << ec.message() << std::endl;
                }
                else if (bytesReceived == 0){
                    std::cout << "Connection closed by remote." << std::endl;
                }
            }
        }
    );
}

void start_accepting(tcp::acceptor& acceptor) {
    auto socket = std::make_shared<tcp::socket>(acceptor.get_executor());
    acceptor.async_accept(*socket,
        [&acceptor,socket](std::error_code ec){
            if (!ec) {
                std::cout << "Accepted new connection from " << socket->remote_endpoint() << std::endl;
                handle_connection(socket);
            }else{
                std::cout << "Accept Error: " << ec.message() << std::endl;
            }
            //Accept new conncetion. This seems like recursion, but is more like tail recursion.
            start_accepting(acceptor);
        }
    );
}

/**
 * @brief setup initial tcp connections
 * @param in_ctx io_context of the serverSocket, used for dispatching asynchronus IO with handlers.
 */

void setupTCPs(boost::asio::io_context &ctx) {
    
    //start_accepting(acceptor);

    ctx.run(); // TODO: Blocking call to run the I/O context. Do this in another thread.
}


#ifndef TESTING

int main(int argc, char const *argv[])
{
    asIp::address host = DHTServerConfig::DHT_ADDR;
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
            host = asIp::make_address(host_string);
        }
        if (vm.count("port"))
        {
            port = boost::any_cast<u_short>(vm["port"]);
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
    auto routing_table = RoutingTable(generateRandomNodeID(), host, port);

    std::cout << "Host: " << host << "\n"
              << "Port: " << port << "\n"
              << "NodeID" << key_to_string(routing_table.get_node_id()) << "\n";


    boost::asio::io_context ctx;

    boost::asio::ip::tcp::acceptor acceptor(ctx);
    boost::asio::ip::tcp::endpoint endpoint(boost::asio::ip::tcp::v4(), port);
    acceptor.open(endpoint.protocol());
    acceptor.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
    acceptor.bind(endpoint);
    acceptor.listen();
    
    //start_accepting(acceptor);
    bool serverIsRunning = true;
    struct ConnectionInfo{};
    std::vector<boost::asio::ip::tcp::socket> connectionMap;

    while(serverIsRunning){
        //internal management
        //clean up local_storage
        acceptor.async_wait(boost::asio::ip::tcp::acceptor::wait_read,
            [&](const boost::system::error_code& error) {
                if(!error){
                    auto & socket = connectionMap.emplace_back(ctx);
                    acceptor.accept(socket);
                    std::printf("Accepted new connection!\n");
                }
            });

        ctx.run(); // TODO: Blocking call to run the I/O context. Do this in another thread.

    }   


    return 0;
}

#endif