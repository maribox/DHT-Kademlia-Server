#pragma once

#include <boost/asio.hpp>
#include <optional>
#include <map>
#include <mutex>
#include <string>
#include <array>
#include "util.h"

using keyType = std::array<char,KEYSIZE>;
using valueType = int;


class DHTServerConfig {
public:
    static constexpr u_short DEFAULT_DHT_PORT = 7401;
    static constexpr u_short DEFAULT_DHT_PUT = 650;
    static constexpr u_short DEFAULT_DHT_GET = 651;
    static constexpr u_short DEFAULT_DHT_SUCCESS = 652;
    static constexpr u_short DEFAULT_DHT_FAILURE = 653;

    static const boost::asio::ip::address DEFAULT_DHT_ADDR;

    DHTServerConfig();

    const boost::asio::ip::address dht_addr;
    u_short dht_port = DEFAULT_DHT_PORT;
    u_short dht_put = DEFAULT_DHT_PUT;
    u_short dht_get = DEFAULT_DHT_GET;
    u_short dht_success = DEFAULT_DHT_SUCCESS;
    u_short dht_failure = DEFAULT_DHT_FAILURE;

    // Declare endpoints
    boost::asio::ip::tcp::endpoint server_endpoint;
    boost::asio::ip::tcp::endpoint client_endpoint;
};

extern DHTServerConfig config;

extern std::map<keyType, valueType> local_storage;
extern std::mutex storage_lock;

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
    std::array<char,KEYSIZE> key;
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
