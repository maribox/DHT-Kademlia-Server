#pragma once

#include <bitset>
#include <boost/algorithm/string.hpp>
#include <boost/asio.hpp>
#include <list>
#include <random>
#include <vector>

#include "dht_server_wo_boost.h"

extern const size_t K;

using IpAddress = std::string;
using UDP_Port = uint16_t;
using NodeID = keyType;

struct Node {
    in6_addr addr;
    in_port_t port;
    NodeID id;
};

class K_Bucket {
   private:
    NodeID start;
    NodeID end;
    std::list<Node> peers;
    std::list<Node> replacement_cache;

   public:
    K_Bucket(const NodeID& start, const NodeID& end);
    void add_peer(const Node& peer);
    NodeID get_start();
    NodeID get_end();
    const std::list<Node>& get_peers() const;
};

NodeID generateRandomNodeID();

class RoutingTable {
   private:
    std::vector<K_Bucket> bucket_list;
    Node local_node;

   public:
    void split_bucket();
    RoutingTable(const in6_addr& ip, const in_port_t& port, const NodeID& id = generateRandomNodeID());
    const Node& get_local_node() const;
    const std::vector<K_Bucket>& get_bucket_list() const;
};
