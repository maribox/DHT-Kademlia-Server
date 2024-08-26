#include "routing.h"
#include "dht_server.h"

#include <iostream>
#include <netinet/in.h>

// #include <print>

const size_t K = 20;
const size_t ALPHA = 3;

//TODO: Is this enough?
bool operator==(const Node& lhs, const Node& rhs) {
    return lhs.id == rhs.id;
}

KBucket::KBucket(const NodeID& start, const NodeID& end)
    : start(start), end(end), peers(), replacement_cache() {
}

bool KBucket::add_peer(const Node &peer) { // returns true if inserted or already in the list, else false
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

NodeID KBucket::get_start() const {
    return this->start;
}

NodeID KBucket::get_end() const {
    return this->end;
}

const std::list<Node>& KBucket::get_peers() const {
    return peers;
}

const std::list<Node>& KBucket::get_replacement_cache() const{
    return replacement_cache;
}

size_t RoutingTable::get_bucket_for(NodeID node_id) {
    for (size_t bucket_i = 0; bucket_i < bucket_list.size(); bucket_i++) {
        auto& bucket = bucket_list.at(bucket_i);
        if (bucket.get_start() <= node_id && node_id <= bucket.get_end()) {
            return bucket_i;
        }
    }
    return -1;
}

NodeID RoutingTable::node_distance(const NodeID& node_1, const NodeID& node_2) {
    NodeID distance;
    for (int i = 0; i < KEY_SIZE; ++i) {
        distance[i] = (node_1[i] ^ node_2[i]);
    }
    return distance;
}



std::vector<Node> RoutingTable::find_closest_nodes(NodeID target_node_id) {
    std::vector<Node> closest_nodes;
    int bucket_index_left = get_bucket_for(target_node_id) - 1;
    int bucket_index_right = bucket_index_left + 1;

    int added_on_left = 0;
    int added_on_right = 0;

    while((added_on_left < K && bucket_index_left >= 0)) { // add up to K on the left
        closest_nodes.insert(closest_nodes.end(),
            bucket_list.at(bucket_index_left).get_peers().begin(),
            bucket_list.at(bucket_index_left).get_peers().end());
        added_on_left += bucket_list.at(bucket_index_left).get_peers().size();
        bucket_index_left--;
    }

    while(added_on_right < K && bucket_index_right < bucket_list.size()) { // add up to K on the right
        closest_nodes.insert(closest_nodes.end(),
            bucket_list.at(bucket_index_right).get_peers().begin(),
            bucket_list.at(bucket_index_right).get_peers().end());
        added_on_right += bucket_list.at(bucket_index_right).get_peers().size();
        bucket_index_right++;
    }

    closest_nodes.push_back(local_node);
    std::sort(closest_nodes.begin(), closest_nodes.end(),
        [this, target_node_id](const Node& node_1, const Node& node_2){return node_distance(node_1.id, target_node_id) < node_distance(node_2.id, target_node_id);}
    );

    if (closest_nodes.size() > K) {
        closest_nodes.resize(K);
    }

    return closest_nodes;
}

RoutingTable::RoutingTable(const in6_addr& ip, const in_port_t& port,
                           const NodeID& id)
    : bucket_list(), local_node({ip, port, id}) {
    NodeID first_bucket_start;
    first_bucket_start.fill(0);
    NodeID first_bucket_end;
    first_bucket_end.fill(255);
    bucket_list.push_back(KBucket(first_bucket_start, first_bucket_end));
}

int RoutingTable::get_shared_prefix_bits(KBucket bucket) {
    // if bucket full and d !≡ 0 (mod 6), try to split
    // -> check length of prefix shared by all nodes in k-bucket's range
    int shared_prefix_bits = 0;
    for (auto byte_no = 0; byte_no < KEY_SIZE; byte_no++) {
        auto start_byte = bucket.get_start()[byte_no]; // e.g. 0011.0000
        auto end_byte = bucket.get_end()[byte_no]; // e.g. 0011.1111 -> depth would be 4

        // bit_no represents positiion with value 2^i of byte
        for (auto bit_no = 7; bit_no >= 0; bit_no--) {
            bool start_bit = ((1 << bit_no) & start_byte) != 0;
            bool end_bit = ((1 << bit_no) & end_byte) != 0;
            if (start_bit == end_bit) {
                shared_prefix_bits++;
            } else {
                byte_no = KEY_SIZE;
                break;
            }
        }
    }
    return shared_prefix_bits;
}

void RoutingTable::split_bucket(KBucket bucket, int depth) {
    // TODO: replacement cache
    // e.g. // e.g. 110|0|000 - // e.g. 110|1|111 -> depth == index of bit to switch, in this example 3
    auto start_first = bucket.get_start(); // e.g. 110|0|000

    auto byte_no = depth / 8;
    auto bit_no = 7 - depth % 8; // again, position worth 2^bit_no
    auto end_first = bucket.get_end(); // e.g. 110|0|111 -> we flip byte_no bit of end
    end_first[byte_no] = end_first[byte_no] ^ (1 << bit_no);
    auto start_second = bucket.get_start(); // e.g. 110|1|000 -> we flip byte_no bit of start
    start_second[byte_no] = start_second[byte_no] ^ (1 << bit_no);
    auto end_second = bucket.get_end(); // e.g. 110|1|111
    KBucket first(start_first, end_first);
    KBucket second(start_second, end_second);

    for (auto& peer : bucket.get_peers()) {
        if (peer.id <= first.get_end()) {
            first.add_peer(peer);
        } else {
            second.add_peer(peer);
        }
    }

    for (auto& peer : bucket.get_replacement_cache()) {
        if (peer.id <= first.get_end()) {
            first.add_peer(peer);
        } else {
            second.add_peer(peer);
        }
    }

    auto it = std::ranges::find(std::as_const(bucket_list), bucket);
    if (it == bucket_list.cend()) {
        std::cerr << "Provided a bucket not in the bucket list" << std::endl;
        return;
    } else {
        bucket_list.erase(it);
        bucket_list.insert(it, second);
        bucket_list.insert(it, first);
    }
}



//TODO: implement this. look at sections 2.2, 2.4, 4.2
void RoutingTable::add_peer(const Node& peer) {
    // TODO: replace with function
    for (auto& bucket : bucket_list) {
        if (bucket.get_start() <= peer.id  && peer.id <= bucket.get_end()) {
        // according to 2.4: "When u learns of a new contact, it  attempts to insert the contact in the appropriate k-bucket.
        // If that bucket  is  not full, the new contact is simply inserted. Otherwise, if the k-bucket’s range  includes u’s
        // own node ID, then the bucket  is split into two new buckets, the  old contents divided between the two, and the
        // insertion attempt repeated. If a  k-bucket with a different range is full, the new contact is simply dropped"

        // according to 4.2: "The general splitting rule is that a node splits a full k-bucket if the  bucket’s range contains
        // the node’s own ID or the depth d of the k-bucket in the  routing tree satisfies  d !≡ 0 (mod b). (The depth is just
        // the length of the prefix  shared by all nodes in the k-bucket’s range.) The current implementation uses  b=5."
            if (!bucket.add_peer(peer)) {
                int depth = get_shared_prefix_bits(bucket);
                if ((bucket.get_start() <= this->local_node.id && this->local_node.id <= bucket.get_end())
                    || depth % 5 == 0) {
                    split_bucket(bucket, depth);
                }
            }
        }
    }
}

const Node& RoutingTable::get_local_node() const {
    return this->local_node;
}

const std::vector<KBucket>& RoutingTable::get_bucket_list() const {
    return this->bucket_list;
}

NodeID generate_random_nodeID() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    NodeID nodeId;
    for (size_t i = 0; i < nodeId.size(); ++i) {
        nodeId[i] = dis(gen);
    }
    return nodeId;
}
