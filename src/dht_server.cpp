#include "dht_server.h"
#include <iostream>

#include <boost/stacktrace.hpp>
#include <boost/asio.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/program_options.hpp>

#include <mutex>
#include <array>
#include <map>
#include <optional>
#include <string>
#include <stdexcept>
#include <string_view>

/*
Important Remark: Maybe use a logger for keeping track of operations during runtime.
Boost provides one, seemingly a bit hard to setup, but anyways:
https://www.boost.org/doc/libs/1_82_0/libs/log/doc/html/index.html
*/
namespace progOpt = boost::program_options;
namespace asIp = boost::asio::ip;
using boost::asio::ip::tcp;

const boost::asio::ip::address DHTServerConfig::DEFAULT_DHT_ADDR = boost::asio::ip::make_address("127.0.0.1");

DHTServerConfig config;

DHTServerConfig::DHTServerConfig()
    : dht_addr(DEFAULT_DHT_ADDR),
      server_endpoint(dht_addr, dht_port),
      client_endpoint(dht_addr, dht_port + 1)
{
}

std::map<keyType, valueType, BitsetComparator<KEYSIZE>> local_storage{};
std::mutex storage_lock;

// Returns optional value, either the correctly looked up value, or no value.
std::optional<valueType> get_from_storage(const keyType &key)
{
    // shouldn't be needed. Safety mesaure for now, based on python impl.
    std::lock_guard<std::mutex> lock(storage_lock);
    try
    {
        // We could also perform kademlia tree index checks here.
        return {local_storage.at(key)};
        // Log lookup-hit.
    }
    catch (std::out_of_range e)
    {
        // Log lookup-miss.
        return {};
    }
}

void save_to_storage(const keyType &key, valueType val)
{
    std::lock_guard<std::mutex> lock(storage_lock);

    auto fresh_insert = local_storage.insert_or_assign(key, val);
    // Log fresh_insert. True equiv. to "New value created". False equiv. to
    // "Overwritten, assignment"
}

bool send_dht_success(); // TODO

bool send_dht_failure(); // TODO

void handle_connection(tcp::socket&& socket) {
    // Buffer for receiving incoming DHT_requests
    char rec_buf[256 + 64];
    socket.async_receive(
        boost::asio::buffer(rec_buf, 256 + 64),
        [rec_buf, socket = std::move(socket)](std::error_code ec, size_t bytesReceived) mutable{
            //Good, vital connection:
            if(!ec && bytesReceived > 0){
                //Here, add parsing for Kademliad DHT logic
                std::cout << "Received: " << std::string_view(rec_buf,bytesReceived) << std::endl;
                handle_connection(std::move(socket));
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
    acceptor.async_accept(
        [&acceptor](std::error_code ec, tcp::socket socket){
            if (!ec) {
                std::cout << "Accepted new connection from " << socket.remote_endpoint() << std::endl;
                handle_connection(std::move(socket));
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
    tcp::acceptor acceptor(ctx, tcp::endpoint(tcp::v4(), config.dht_port));

    start_accepting(acceptor);

    ctx.run(); // TODO: Blocking call to run the I/O context. Do this in another thread.
}




#ifndef TESTING

int main(int argc, char const *argv[])
{
    asIp::address host = config.dht_addr;
    u_short port = config.dht_port;
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
    }

    std::cout << "Host: " << host << "\n"
              << "Port: " << port << "\n";

    boost::asio::io_context ctx;

    setupTCPs(ctx);

    return 0;
}

#endif