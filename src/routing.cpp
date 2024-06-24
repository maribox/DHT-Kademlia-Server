#include "routing.h"

#include <print>

const size_t K = 20;

K_Bucket::K_Bucket() : peers(), replacement_cache() {
}

void K_Bucket::add_peer(const Node& peer) {
  if (peers.size() < K) {
    peers.push_back(peer);
  } else {
    replacement_cache.push_front(peer);
  }
}

const std::list<Node>& K_Bucket::get_peers() const {
  return peers;
}

RoutingTable::RoutingTable(const NodeID& id,
                           const boost::asio::ip::address& ip,
                           const uint16_t& port)
    : us({id, ip, port}), bucket_list()  {
  
}

const NodeID& RoutingTable::get_node_id() const {
  return us.id;
}

NodeID generateRandomNodeID() {
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<> dis(0, 1);
  NodeID nodeId;
  for (size_t i = 0; i < nodeId.size(); ++i) {
    nodeId[i] = dis(gen);
  }
  return nodeId;
}

// You can keep your main function here if you want to test the routing
// functionality
/*
int main() {
    std::println("Starting DHT Storage...");

    boost::asio::io_context io_context;

    DHTServer server(io_context, config);

    NodeID nodeId = generateRandomNodeID();

    keyType key;
    key.fill(0);
    key[31] = 1;

    std::vector<uint8_t> value{0x4e, 0x65, 0x76, 0x65, 0x72, 0x20, 0x67,
                               0x6f, 0x6e, 0x6e, 0x61, 0x20, 0x67, 0x69,
                               0x76, 0x65, 0x20, 0x79, 0x6f, 0x75, 0x20,
                               0x75, 0x70, 0x20, 0x0a};
    save_to_storage(key, value);

    auto retrieved_value = get_from_storage(key);
    if (retrieved_value) {
        std::println("Retrieved value:");
        for (const auto& byte : *retrieved_value) {
            std::print("{}", static_cast<char>(byte));
        }
        std::println("");
    } else {
        std::println("Value not found");
    }

    server.run();

    return 0;
}
*/