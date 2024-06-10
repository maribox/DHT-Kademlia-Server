#pragma once

#include <boost/asio.hpp>
#include <optional>
#include <map>
#include <mutex>
#include <string>
#include <bitset>
#include "util.h"

using keyType = std::bitset<KEYSIZE>;
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

extern std::map<keyType, valueType, BitsetComparator<KEYSIZE>> local_storage;
extern std::mutex storage_lock;

std::optional<valueType> get_from_storage(const keyType& key);
void save_to_storage(const keyType& key, valueType val);

bool send_dht_success(); // TODO
bool send_dht_failure(); // TODO

void setupTCP(boost::asio::io_context &in_ctx, char rec_buf[256+64]);