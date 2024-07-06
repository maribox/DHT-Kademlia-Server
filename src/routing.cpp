#include "routing.h"

#include <netinet/in.h>

// #include <print>

const size_t K = 20;
const size_t ALPHA = 3;

K_Bucket::K_Bucket(const NodeID& start, const NodeID& end)
    : start(start), end(end), peers(), replacement_cache() {
}

void K_Bucket::add_peer(const Node& peer) {
    if (peers.size() < K) {
        peers.push_back(peer);
    } else {
        replacement_cache.push_front(peer);
    }
}

NodeID K_Bucket::get_start() {
    return this->start;
}

NodeID K_Bucket::get_end() {
    return this->end;
}

const std::list<Node>& K_Bucket::get_peers() const {
    return peers;
}

RoutingTable::RoutingTable(const in6_addr& ip, const in_port_t& port,
                           const NodeID& id)
    : bucket_list(), local_node({ip, port, id}) {
    NodeID first_bucket_start;
    first_bucket_start.fill(0);
    NodeID first_bucket_end;
    first_bucket_end.fill(255);
    bucket_list.push_back(K_Bucket(first_bucket_start, first_bucket_end));
}


const Node& RoutingTable::get_local_node() const {
    return this->local_node;
}

const std::vector<K_Bucket>& RoutingTable::get_bucket_list() const {
    return this->bucket_list;
}

NodeID generateRandomNodeID() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    NodeID nodeId;
    for (size_t i = 0; i < nodeId.size(); ++i) {
        nodeId[i] = dis(gen);
    }
    return nodeId;
}
