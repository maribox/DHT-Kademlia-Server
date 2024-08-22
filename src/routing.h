#pragma once

#include <bitset>
#include <boost/algorithm/string.hpp>
#include <boost/asio.hpp>
#include <list>
#include <random>
#include <set>
#include <vector>

#include "dht_server_wo_boost.h"

extern const size_t K;

using IpAddress = std::string;
using UDP_Port = uint16_t;
using NodeID = key_type;

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
    bool operator==(const K_Bucket& other) const {
        return this->start == other.start && this->end == other.end;
    }
    bool add_peer(const Node &peer);
    NodeID get_start() const;
    NodeID get_end() const;
    const std::list<Node>& get_peers() const;
};

NodeID generateRandomNodeID();

class RoutingTable {
   private:
    std::vector<K_Bucket> bucket_list;
    Node local_node;

   public:
    void add_peer(const Node& peer);
    void split_bucket();

    size_t get_bucket_for(NodeID key);

    std::vector<Node> find_closest_nodes(NodeID node_id);

    RoutingTable(const in6_addr& ip, const in_port_t& port, const NodeID& id = generateRandomNodeID());
    int get_shared_prefix_bits(K_Bucket bucket);
    void split_bucket(K_Bucket bucket, int depth);

    RoutingTable() = default;
    const Node& get_local_node() const;
    const std::vector<K_Bucket>& get_bucket_list() const;
    static NodeID node_distance(const NodeID& node_1, const NodeID& node_2);
    template<typename Iterable>
    static bool has_duplicate_id(const Iterable& nodes);
};

template<typename Iterable>
bool RoutingTable::has_duplicate_id(const Iterable& nodes) {
    std::set<NodeID> seen_ids;
    for (Node node : nodes) {
        if (!seen_ids.insert(node.id).second) {
            return true;
        }
    }
    return false;
}