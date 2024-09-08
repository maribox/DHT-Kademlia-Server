#include "routing.h"
#include "dht_server.h"

#include <iostream>
#include <netinet/in.h>

// #include <print>


KBucket::KBucket(const NodeID& start, const NodeID& end)
    : start(start), end(end), peers(), replacement_cache() {
}

bool KBucket::add_peer(const Node &peer) { // returns true if inserted or already in the list, false if inserted into replacement cache -> split
    // according to 2.2: "Each k-bucket is kept sorted by time last seen—least-recently seen node  at the head, most-recently seen at the tail."
    // therefore, try to find and then move to back
    auto peers_it = std::ranges::find(peers, peer);
    if (peers_it != peers.end()) {
        peers.erase(peers_it);
        peers.push_back(peer);
        logTrace("Tried to add existing node {} with ip {}:{} to RoutingTable", key_to_string(peer.id), ip_to_string(peer.addr), peer.port);
        return true;
    }
    if (peers.size() < K) {
        peers.push_back(peer);
        logDebug("Added new node {} with ip {}:{} to RoutingTable", key_to_string(peer.id), ip_to_string(peer.addr), peer.port);
        return true;
    } else {
        // according to 4.1, we have a replacement cache that gets filled if the K_Bucket is full.
        // "The replacement cache is kept sorted by time last seen, with the most  recently seen entry having the highest priority as a replacement candidate."
        // we keep it sorted in the same way as the peers list, so the last entry is the most recently seen
        auto cache_it = std::ranges::find(replacement_cache, peer);
        if (cache_it != replacement_cache.end()) {
            replacement_cache.erase(cache_it);
            replacement_cache.push_back(peer);
            return false;
        } else if (replacement_cache.size() < MAX_REPLACMENT_CACHE_SIZE) {
            replacement_cache.push_back(peer);
            logDebug("Added new node {} with ip {}:{} to replacement cache", key_to_string(peer.id), ip_to_string(peer.addr), peer.port);
            return false;
        } else {
            logDebug("Tried to add node {} with ip {}:{} to replacement cache but was full", key_to_string(peer.id), ip_to_string(peer.addr), peer.port);
            return false;
        }
    }
}

bool KBucket::remove(const in6_addr &ip, const in_port_t &port) {
    const auto it = std::ranges::find_if(peers,
                 [&ip, &port](const Node& node) {
                     return memcmp(&node.addr, &ip, sizeof(in6_addr)) == 0 && node.port == port;
                 });
    if (it != peers.end()) {
        peers.erase(it);
        return true;
    }
    return false;
}

bool KBucket::remove(const Node& target_node) {
    const auto it = std::ranges::find_if(peers,
                 [&target_node](const Node& node) { return node == target_node;});
    if (it != peers.end()) {
        peers.erase(it);
        return true;
    }
    return false;
}

bool KBucket::contains(const Node &node) {
    return std::ranges::find(peers, node) != peers.end();
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

size_t RoutingTable::count() {
    return std::accumulate(bucket_list.begin(), bucket_list.end(), 0,
        [](size_t sum, const KBucket& bucket) {
           return sum + bucket.get_peers().size();
        });
}

bool RoutingTable::contains(const Node &node) {
    return bucket_list[get_bucket_for(node.id)].contains(node);
}

bool RoutingTable::remove(const in6_addr &ip, const in_port_t &port) {
    for (auto& bucket : bucket_list) {
        if (bucket.remove(ip, port)) {
            return true;
        }
    }
    return false;
}

bool RoutingTable::remove(const Node& target_node) {
    for (auto& bucket : bucket_list) {
        if (bucket.remove(target_node)) {
            return true;
        }
    }
    return false;
}

size_t RoutingTable::get_bucket_for(NodeID node_id) const {
    for (size_t bucket_i = 0; bucket_i < bucket_list.size(); bucket_i++) {
        auto& bucket = bucket_list.at(bucket_i);
        if (bucket.get_start() <= node_id && node_id <= bucket.get_end()) {
            return bucket_i;
        }
    }
    logCritical("Couldn't find valid bucket for target_node_id. The RoutingTable is in an invalid state");
    return 0;
}

NodeID RoutingTable::node_distance(const NodeID& node_1, const NodeID& node_2) {
    NodeID distance;
    for (int i = 0; i < KEY_SIZE; ++i) {
        distance[i] = (node_1[i] ^ node_2[i]);
    }
    return distance;
}

void RoutingTable::sort_by_distance_to(std::vector<Node> nodes, Key key) {
    std::ranges::sort(nodes,[key](const Node& node_1, const Node& node_2)
        {return RoutingTable::node_distance(node_1.id, key) < RoutingTable::node_distance(node_2.id, key);});
}

bool RoutingTable::has_same_addr_or_id(const Node &node) const {
    return local_node.id == node.id ||
       (local_node.addr == node.addr && local_node.port == node.port);
}

std::vector<Node> RoutingTable::find_closest_nodes(const NodeID &target_node_id) const {
    std::vector<Node> closest_nodes;


    size_t bucket_index_right = get_bucket_for(target_node_id);
    auto bucket_index_left = static_cast<ssize_t>(bucket_index_right - 1);

    size_t added_on_left = 0;
    size_t added_on_right = 0;

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

    sort_by_distance_to(closest_nodes, target_node_id);

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
    bucket_list.emplace_back(first_bucket_start, first_bucket_end);
}

int RoutingTable::get_shared_prefix_bits(const KBucket& bucket) {
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

void RoutingTable::split_bucket(const KBucket& bucket, int depth) {
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

    auto it = std::ranges::find(bucket_list, bucket);
    if (it == bucket_list.end()) {
        std::cerr << "Provided a bucket not in the bucket list" << std::endl;
        return;
    } else {
        auto index = std::distance(bucket_list.begin(), it);
        bucket_list.erase(it);
        bucket_list.insert(bucket_list.begin() + index, second);
        bucket_list.insert(bucket_list.begin() + index, first);
    }
}


//TODO: implement this. look at sections 2.2, 2.4, 4.2
void RoutingTable::try_add_peer(const Node& peer) {
    // TODO: replace with function
    if (has_same_addr_or_id(peer)) {
        logDebug("Tried to add own node to RoutingTable. Returning");
        return;
    }
        // according to 2.4: "When u learns of a new contact, it  attempts to insert the contact in the appropriate k-bucket.
        // If that bucket  is  not full, the new contact is simply inserted. Otherwise, if the k-bucket’s range  includes u’s
        // own node ID, then the bucket  is split into two new buckets, the  old contents divided between the two, and the
        // insertion attempt repeated. If a  k-bucket with a different range is full, the new contact is simply dropped"

        // according to 4.2: "The general splitting rule is that a node splits a full k-bucket if the  bucket’s range contains
        // the node’s own ID or the depth d of the k-bucket in the  routing tree satisfies  d !≡ 0 (mod b). (The depth is just
        // the length of the prefix  shared by all nodes in the k-bucket’s range.) The current implementation uses  b=5."
    auto& bucket = bucket_list.at(get_bucket_for(peer.id));
    if (!bucket.add_peer(peer)) {
        int depth = get_shared_prefix_bits(bucket);
        if ((bucket.get_start() <= this->local_node.id && this->local_node.id <= bucket.get_end())
            || depth % 5 == 0) {
            split_bucket(bucket, depth);
            try_add_peer(peer);
        }
    }
}

const Node& RoutingTable::get_local_node() const {
    return this->local_node;
}

const std::vector<KBucket>& RoutingTable::get_bucket_list() const {
    return this->bucket_list;
}

// TODO rewrite if time
NodeID generate_random_nodeID(NodeID nodeID1, NodeID nodeID2) {
    if (nodeID1 > nodeID2) {
        return {};
    }
    std::random_device rd;
    std::mt19937 gen(rd());
    NodeID generated_id;
    for (size_t i = 0; i < generated_id.size(); ++i) {
        std::uniform_int_distribution<unsigned int> dis(nodeID1[i], nodeID2[i]);
        generated_id[i] = dis(gen);
        if (nodeID1[i] != nodeID2[i]) {
            std::uniform_int_distribution<unsigned int> dis(0, 255);

            if (generated_id[i] == nodeID1[i]) { // hit lower bound
                for (int j = i + 1; j < generated_id.size(); j++) {
                    do {
                        generated_id[j] = dis(gen);
                    } while (generated_id[j] < nodeID1[j]);
                    if (generated_id[j] > nodeID1[j]) {
                        i = j;
                        break;
                    }
                }
            } else if (generated_id[i] == nodeID2[i]) { // hit higher bound
                for (int j = i + 1; j < generated_id.size(); j++) {
                    do {
                        generated_id[j] = dis(gen);
                    } while (generated_id[j] > nodeID2[j]);
                    if (generated_id[j] < nodeID2[j]) {
                        i = j;
                        break;
                    }
                }
            } // hit no bounds -> rest can be filled with completely random values
            for (int j = i + 1; j < generated_id.size(); j++) {
                generated_id[j] = dis(gen);
            }
            break;
        }
    }
    return generated_id;
}
