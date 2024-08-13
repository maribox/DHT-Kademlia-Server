#include "routing.h"

#include <netinet/in.h>

// #include <print>

const size_t K = 20;
const size_t ALPHA = 3;

K_Bucket::K_Bucket(const NodeID& start, const NodeID& end)
    : start(start), end(end), peers(), replacement_cache() {
}

void K_Bucket::add_peer(const Node& peer) {
    // according to 2.2: "Each k-bucket is kept sorted by time last seen—least-recently seen node  at the head, most-recently seen at the tail."
    // therefore, try to find and then move to back
    auto it = std::find(peers.begin(), peers.end(), peer);
    if (it != peers.end()) {
        peers.erase(it);
        peers.push_back(peer);
        return;
    }
    if (peers.size() < K) {
        peers.push_back(peer);
    } else {
        // according to 4.1, we have a replacement cache that gets filled if the K_Bucket is full.
        // "The replacement cache is kept sorted by time last seen, with the most  recently seen entry having the highest priority as a replacement candidate."
        // we keep it sorted in the same way as the peers list, so the last entry is the most recently seen
        auto it = std::find(replacement_cache.begin(), replacement_cache.end(), peer);
        if (it != replacement_cache.end()) {
            replacement_cache.erase(it);
        }
        replacement_cache.push_back(peer);
        // TODO: Think about max size of raplcement cache? If yes, remove from front
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

//TODO: implement this. look at sections 2.2, 2.4, 4.2
void add_peer(const Node& peer) {

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
