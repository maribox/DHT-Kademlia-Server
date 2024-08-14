#include "routing.h"

#include <netinet/in.h>

// #include <print>

const size_t K = 20;
const size_t ALPHA = 3;

K_Bucket::K_Bucket(const NodeID& start, const NodeID& end)
    : start(start), end(end), peers(), replacement_cache() {
}

bool K_Bucket::add_peer(const Node &peer) { // returns true if inserted or already in the list, else false
    // according to 2.2: "Each k-bucket is kept sorted by time last seen—least-recently seen node  at the head, most-recently seen at the tail."
    // therefore, try to find and then move to back
    auto it = std::find(peers.begin(), peers.end(), peer);
    if (it != peers.end()) {
        peers.erase(it);
        peers.push_back(peer);
        return true;
    }
    if (peers.size() < K) {
        peers.push_back(peer);
        return true;
    } else {
        // according to 4.1, we have a replacement cache that gets filled if the K_Bucket is full.
        // "The replacement cache is kept sorted by time last seen, with the most  recently seen entry having the highest priority as a replacement candidate."
        // we keep it sorted in the same way as the peers list, so the last entry is the most recently seen
        auto it = std::find(replacement_cache.begin(), replacement_cache.end(), peer);
        if (it != replacement_cache.end()) {
            replacement_cache.erase(it);
        }
        replacement_cache.push_back(peer);
        return false;
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

int RoutingTable::get_shared_prefix_bits(K_Bucket bucket) {
    // if bucket full and d !≡ 0 (mod 6), try to split
    // -> check length of prefix shared by all nodes in k-bucket's range
    int shared_prefix_bits = 0;
    for (auto byte_no = 0; byte_no < KEYSIZE; byte_no++) {
        auto start_byte = bucket.get_start()[byte_no]; // e.g. 0011.0000
        auto end_byte = bucket.get_end()[byte_no]; // e.g. 0011.1111 -> depth would be 4

        // bit_no represents positiion with value 2^i of byte
        for (auto bit_no = 0; bit_no < 8; bit_no++) {
            bool start_bit = ((1 << bit_no) & start_byte) != 0;
            bool end_bit = ((1 << bit_no) & end_byte) != 0;
            if (start_bit == end_bit) {
                shared_prefix_bits++;
            } else {
                byte_no = KEYSIZE;
                break;
            }
        }
    }
    return shared_prefix_bits;
}

//TODO: implement this. look at sections 2.2, 2.4, 4.2
void RoutingTable::add_peer(const Node& peer) {
    for (auto bucket : bucket_list) {
        if (bucket.get_start() <= peer.id  && peer.id <= bucket.get_end()) {
        // according to 2.4: "When u learns of a new contact, it  attempts to insert the contact in the appropriate k-bucket.
        // If that bucket  is  not full, the new contact is simply inserted. Otherwise, if the k-bucket’s range  includes u’s
        // own node ID, then the bucket  is split into two new buckets, the  old contents divided between the two, and the
        // insertion attempt repeated. If a  k-bucket with a different range is full, the new contact is simply dropped"

        // according to 4.2: "The general splitting rule is that a node splits a full k-bucket if the  bucket’s range contains
        // the node’s own ID or the depth d of the k-bucket in the  routing tree satisfies  d !     ≡ 0 (mod 6). (The depth is just
        // the length of the prefix  shared by all nodes in the k-bucket’s range.) The current implementation uses  b=5."
            if (!bucket.add_peer(peer)) {
                int depth = get_shared_prefix_bits(bucket);
                // TODO: WHY could the bucket not contain the peer's ID if we checked that earlier???
            }
        }
    }
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
