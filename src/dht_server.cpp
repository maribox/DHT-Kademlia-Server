#include <iostream>
#include <boost/stacktrace.hpp>

#include <boost/asio.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/program_options.hpp>

#include <bitset>
#include <mutex>
#include <map>
#include <optional>
#include <string>
#include <stdexcept>

/*
Important Remark: Maybe use a logger for keeping track of operations during runtime.
Boost provides one, seemingly a bit hard to setup, but anyways:
https://www.boost.org/doc/libs/1_82_0/libs/log/doc/html/index.html
*/
namespace progOpt = boost::program_options;
namespace asIp = boost::asio::ip;

/*
Here, the int( former 256 bit bitset) represents a SHA256 digest.
The int however is not fixed, it should store arbitrary values...
maybe use std::vectors or something...
*/
//TODO: Performance critical, comparison
template <int T>
class Bitset{
    std::bitset<T> bits;
    bool operator<(const Bitset<T> b){
        for(int i = 0; i < T; i++){
            if(b[i] < bits[i]){
                return false;
            }
            return true;
        }
    }
};



using keyType = Bitset<256>;

/*defaults valueType to int*/
using valueType = int;

asIp::address DHT_ADDR{asIp::make_address("127.0.0.1")}; // This ip is solely mock, use own ip, best make it commandline argument (loopback or local ip)
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

// Custom validate function for boost::asio::ip::address
void validate(boost::any &v, const std::vector<std::string> &values, asIp::address *, int)
{
    // Make sure no previous assignment to 'v' was made
    boost::program_options::validators::check_first_occurrence(v);

    // Extract the string from 'values'
    const std::string &s = boost::program_options::validators::get_single_string(values);

    // Create the address from the string
    v = boost::any(asIp::make_address(s));
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
    
    return 0;
}
