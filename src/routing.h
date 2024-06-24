#pragma once

#include <bitset>
#include <boost/algorithm/string.hpp>
#include <boost/asio.hpp>
#include <list>
#include <random>
#include <vector>

#include "dht_server.h"

extern const size_t K;

using IpAddress = std::string;
using UDP_Port = uint16_t;
using NodeID = keyType;

struct Node {
  NodeID id;
  boost::asio::ip::address ip;
  uint16_t port;
};

class K_Bucket {
 private:
  std::list<Node> peers;
  std::list<Node> replacement_cache;
  NodeID start;
  NodeID end;

 public:
  K_Bucket();
  void add_peer(const Node& peer);
  const std::list<Node>& get_peers() const;
};

class RoutingTable {
 private:
  std::vector<K_Bucket> bucket_list;
  Node us;
 public:
  RoutingTable(const NodeID& id, const boost::asio::ip::address& ip,
               const uint16_t& port);
  void split_bucket();
  const NodeID& get_node_id() const;
};

NodeID generateRandomNodeID();