#pragma once

#include <boost/asio.hpp>
#include <optional>
#include <map>
#include <mutex>
#include <string>
#include <array>
#include <vector>
static constexpr size_t KEYSIZE = 256;
using keyType = std::array<char,KEYSIZE/8>;
using valueType = int;

std::string key_to_string(const keyType& key);

namespace DHTServerConfig {
    static constexpr u_short DHT_PORT = 7401;
    static constexpr u_short DHT_PUT = 650;
    static constexpr u_short DHT_GET = 651;
    static constexpr u_short DHT_SUCCESS = 652;
    static constexpr u_short DHT_FAILURE = 653;

    static const boost::asio::ip::address DHT_ADDR = boost::asio::ip::make_address("127.0.0.1");
};

std::optional<valueType> get_from_storage(const keyType& key);
void save_to_storage(const keyType& key, valueType val);

bool send_dht_success(const boost::asio::ip::address, u_short, keyType, valueType); // TODO
bool send_dht_failure(const boost::asio::ip::address, u_short, keyType); // TODO
 // TODO

void setupTCP(boost::asio::io_context &in_ctx, char rec_buf[256+64]);

class ReceiveFrame
{
public:
    u_short size;
    u_short dht_type;
    u_short time_to_live;
    char replication;
    char reserved;
    std::array<char,KEYSIZE/8> key;
    std::vector<char> value;

    ReceiveFrame(u_short size, u_short dht_type, u_short time_to_live = 0, char replication = 0,char reserved = 0, std::array<char,KEYSIZE>  key = {}, std::vector<char> value = {}): 
    size(size), dht_type(dht_type), time_to_live(time_to_live), replication(replication), reserved(reserved)
    {}


    //Intentionally listed constructors, for others reading this code :)
    ReceiveFrame() = default;

    ReceiveFrame(const ReceiveFrame& other) = default;

    ReceiveFrame& operator=(const ReceiveFrame& other) = default;

    ~ReceiveFrame() = default;

};
