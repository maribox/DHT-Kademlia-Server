#include <bitset>
#include <boost/algorithm/string.hpp>
#include <list>
#include <print>
#include <random>


const size_t K = 20;

using IpAddress = std::string;
using UDP_Port = uint16_t;
using NodeID = std::bitset<256>;
using PeerInfo = std::tuple<IpAddress, UDP_Port, NodeID>;

class K_Bucket {  // List of (up to) k Nodes
 private:
  std::list<PeerInfo> peers;

 public:
  void addPeer(const PeerInfo& peer) {
    if (peers.size() < K) {
      peers.push_back(peer);
    }
  }
};

class RoutingNode {
 private:
  K_Bucket k_bucket;
  public:
    void addPeer(const PeerInfo& peer) { k_bucket.addPeer(peer); }// For now, will be implemented correctly later
};

class RoutingTable {
 private:
  RoutingNode tree;

 public:
  void addPeer(const PeerInfo& peer) { tree.addPeer(peer); }// For now, will be implemented correctly later
};


using Key = std::bitset<256>;
using Value = std::vector<uint8_t>;

class Storage {
 private:
  std::unordered_map<Key, Value> store;

 public:
  void put(const Key& key, const Value& value) { store[key] = value; }
  Value get(const Key& key) { return store[key]; }
};

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

int main() { 
    std::println("Starting DHT Storage...");
    Storage storage;
    RoutingTable routingTable;

    IpAddress ipAddress = "127.0.0.1";
    UDP_Port port = 5000;
    NodeID nodeId = generateRandomNodeID();

    PeerInfo peer = std::make_tuple(ipAddress, port, nodeId);
    routingTable.addPeer(peer);
    Key key(0x0000000000000000000000000000000000000000000000000000000000000001);
    Value value {0x4e,0x65,0x76,0x65,0x72,0x20,0x67,0x6f,0x6e,0x6e,0x61,0x20,0x67,0x69,0x76,0x65,0x20,0x79,0x6f,0x75,0x20,0x75,0x70,0x20,0x0a};
    storage.put(key, value);

    Value retrieved_value = storage.get(key);
    std::println("Retrieved value:");
    for (const auto& byte : retrieved_value) {
      std::print("{}", static_cast<char>(byte));
    }
    std::println("");

    return 0;
}