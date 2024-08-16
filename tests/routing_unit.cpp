#ifndef TESTING
  #define TESTING
#endif

#include <catch2/catch_test_macros.hpp>

#include "../src/routing.h"

TEST_CASE("K_Bucket", "[routing]") {
    NodeID start_id = NodeID();
    start_id.fill(0);
    NodeID end_id = NodeID();
    end_id.fill(255);
    K_Bucket bucket(start_id, end_id);
    SECTION("Creating K_Bucket") {
        auto start = bucket.get_start();
        auto end = bucket.get_end();
        for (size_t i = 0; i < KEYSIZE; i++) {
            REQUIRE(start[i] == 0);
            REQUIRE(end[i] == 255);
        }
        REQUIRE(bucket.get_peers().empty());
    }

    NodeID testID;
    testID.fill(0);
    testID[0] = 1;
    Node testNode = {in6addr_loopback, 8080, testID};

    SECTION("Adding peer") {
        bucket.add_peer(testNode);
        REQUIRE(bucket.get_peers().size() == 1);
    }
}

bool compare_in6_addr(const in6_addr& a, const in6_addr& b) {
    return memcmp(&a, &b, sizeof(in6_addr)) == 0;
}

TEST_CASE("RoutingTable", "[routing]") {
    RoutingTable routing_table = RoutingTable(in6addr_loopback, 8080);
    REQUIRE(compare_in6_addr(routing_table.get_local_node().addr, in6addr_loopback));
    REQUIRE(routing_table.get_local_node().port == 8080);
    SECTION("RoutingTable creating K_Bucket") {
        auto bucket = routing_table.get_bucket_list().at(0);
        auto start = bucket.get_start();
        auto end = bucket.get_end();
        for (size_t i = 0; i < KEYSIZE; i++) {
            REQUIRE(start[i] == 0);
            REQUIRE(end[i] == 255);
        }
        REQUIRE(bucket.get_peers().empty());
    }
    SECTION("RoutingTable add peer") {
        NodeID peerID;
        peerID.fill(0);
        peerID[0] = 1;
        Node peer = {in6addr_loopback, ServerConfig::P2P_PORT + 2, peerID};

        routing_table.add_peer(peer);
        auto& peers = routing_table.get_bucket_list().at(0).get_peers();
        REQUIRE(peers.size() == 1);
        auto it = peers.begin();
        REQUIRE(compare_in6_addr(it->addr, in6addr_loopback));
        REQUIRE(it->port == ServerConfig::P2P_PORT + 2);
        REQUIRE(it->id == peerID);
    }
    SECTION("RoutingTable Split Bucket") {
        for (int i = 0; i < K + 1; i++) {
            Node peer = {in6addr_loopback, static_cast<u_short> (ServerConfig::P2P_PORT + 2 + i), generateRandomNodeID()};
            routing_table.add_peer(peer);
        }
        auto& buckets = routing_table.get_bucket_list();
        REQUIRE(buckets.size() == 2);
        REQUIRE(buckets.at(0).get_peers().size() + buckets.at(1).get_peers().size() == K);
        auto first_start = std::array<unsigned char, KEYSIZE>{};
        first_start.fill(0);
        REQUIRE(buckets.at(0).get_start() == first_start);
        auto first_end = std::array<unsigned char, KEYSIZE>{};
        first_end.fill(0xff);
        first_end[0] = 0x7f;
        REQUIRE(buckets.at(0).get_end() == first_end);
        auto second_start = std::array<unsigned char, KEYSIZE>{};
        second_start.fill(0);
        second_start[0] = 0x80;
        REQUIRE(buckets.at(1).get_start() == second_start);
        auto second_end = std::array<unsigned char, KEYSIZE>{};
        second_end.fill(0xff);
        REQUIRE(buckets.at(1).get_end() == second_end);
    }
}




