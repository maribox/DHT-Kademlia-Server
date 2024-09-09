#pragma once

#include <bitset>
#include <boost/algorithm/string.hpp>
#include <boost/asio.hpp>
#include <list>
#include <random>
#include <set>
#include <vector>

#include "dht_server.h"
#include "common_types.h"

static constexpr size_t MAX_REPLACMENT_CACHE_SIZE = 3*K;

class KBucket {
   private:
    NodeID start;
    NodeID end;
    std::list<Node> peers;
    std::list<Node> replacement_cache;

   public:
    KBucket(const NodeID& start, const NodeID& end);
    bool operator==(const KBucket& other) const {
        return this->start == other.start && this->end == other.end;
    }
    bool add_peer(const Node &peer);
    bool remove (const in6_addr &ip, const in_port_t &port);
    bool remove (const Node& node);
    bool contains(const Node &);
    NodeID get_start() const;
    NodeID get_end() const;
    const std::list<Node>& get_peers() const;
    const std::list<Node>& get_replacement_cache() const;
};

NodeID generate_random_nodeID(
    NodeID nodeID1 = NodeID{},
    NodeID nodeID2 = [] {
        NodeID id;
        id.fill(0xFF);
        return id;
    }());

class RoutingTable {
   private:
    std::vector<KBucket> bucket_list;
    Node local_node;

   public:
    void try_add_peer(const Node& peer, bool replace_if_similar = false);
    void split_bucket();

    size_t count();
    bool contains(const Node &node);
    bool remove(const in6_addr& ip, const in_port_t& port);
    bool remove(const Node &target_node);

    size_t get_bucket_for(NodeID key) const;

    std::vector<Node> find_closest_nodes_excluding_us(const NodeID &node_id) const;
    std::vector<Node> find_closest_nodes_including_us(const NodeID &node_id) const;
    RoutingTable(const in6_addr& ip, const in_port_t& port, const NodeID& id = generate_random_nodeID());
    static int get_shared_prefix_bits(const KBucket& bucket);
    void split_bucket(const KBucket& bucket, int depth);

    RoutingTable() = default;
    const Node& get_local_node() const;
    const std::vector<KBucket>& get_bucket_list() const;
    static NodeID node_distance(const NodeID& node_1, const NodeID& node_2);
    static void sort_by_distance_to(std::vector<Node> nodes, Key key);

    static bool has_same_addr_or_id(const Node& node1, const Node &node2);

    template<typename Iterable>
    static bool has_duplicate_id(const Iterable& nodes); // debug function
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