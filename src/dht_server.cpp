#include <iostream>
#include <boost/stacktrace.hpp>

#include <boost/asio.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/program_options.hpp>

#include <bitset>
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

/*
Here, the int( former 256 bit bitset) represents a SHA256 digest.
The int however is not fixed, it should store arbitrary values...
maybe use std::vectors or something...
*/
//TODO: Performance critical, comparison
template <int T>
class Bitset{
    public:
    std::bitset<T> bits;
    bool operator<(const Bitset<T> rhs) const{
        for(int i = 0; i < T; i++){
            if(rhs[i] < bits[i]){
                return false;
            }
        }
        return true;
    }

    bool operator[](int i) const{
       return this->bits[i];
    }
    
    //TODO: Set function ovverrides all
    template<class ... Types>
    void set(Types... args){
        bits.set(std::forward<Types>(args)...);
    }
};


using keyType = Bitset<256>;

/*defaults valueType to int*/
using valueType = int;

asIp::address DHT_ADDR{asIp::make_address("127.0.0.1")}; // This ip is solely mock, use own ip, best make it commandline argument (loopback or local ip)
tcp::endpoint SERVER_ENDPOINT{DHT_ADDR , 7401}; //fixed, set by python client
tcp::endpoint CLIENT_ENDPOINT{DHT_ADDR , 7401};  //may vary?

u_short DHT_PORT = 7401;
u_short DHT_PUT = 650;
u_short DHT_GET = 651;
u_short DHT_SUCCESS = 652;
u_short DHT_FAILURE = 653;

std::map<keyType, valueType> local_storage = {};
std::mutex storage_lock;

// Returns optional value, either the correctly looked up value, or no value.
std::optional<valueType> get_from_storage(keyType key)
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

void save_to_storage(keyType key, valueType val)
{
    std::lock_guard<std::mutex> lock(storage_lock);
    auto fresh_insert = local_storage.insert_or_assign(key, val);
    // Log fresh_insert. True equiv. to "New value created". False equiv. to "Overwritten, assignment"
}

bool send_dht_success(); // TODO

bool send_dht_failure(); // TODO


//TODO: Implement method parameter usage
 //max header + key size, used for DHT_PUT

/**
 * @brief setup initial tcp connection
 * 
 * @param rec_buf buffer for receiving incoming DHT_requests. Size of 64+256 provides at least enough bytes
 * for all DHT_queries without their possible value (just metadata). 
 * @param in_ctx io_context of the serverSocket, used for dispatching asynchronus IO with handlers.
 */
void setupTCP(boost::asio::io_context &in_ctx, char rec_buf[256+64]){
    boost::asio::io_context ctx;
    tcp::socket serverSocket(ctx, SERVER_ENDPOINT);
    //this connects to the port and establishes this programm instance as "port-user 7401"
    //std::array<char, 256+32> buf; //min header + key size, used for DHT_GET, _SUCCESS, _FAILURE

    serverSocket.async_receive(
        boost::asio::buffer(rec_buf,256+64),
        [&](std::error_code ec, size_t bytesReceived){
            if(!ec && bytesReceived > 0){
                std::cout << "Received: " << std::string_view(rec_buf,bytesReceived) << std::endl;
            }
            else{
                //TODO: Problem, Transport endpoint is not connected. (ec hit)
                std::cout << "Error! No bytes received! " << ec.message() << std::endl;
            }
        }
        ); //non-blocking
    ctx.run(); //blocking, could also be called from different thread. Maybe use producer consumer fashion: Producer(receiver) thread: thread-safe enqueue --> Consumer (handler) thread: thread-safe dequeue.
}

int main(int argc, char const *argv[])
{
    asIp::address host = DHT_ADDR;
    u_short port = DHT_PORT;
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
    char rec_buf[256+64];

    setupTCP(ctx,rec_buf);


    return 0;
}
