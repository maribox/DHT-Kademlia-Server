#ifndef TESTING
  #define TESTING
#endif

#include <iostream>
#include <catch2/catch_test_macros.hpp>

#include "../src/routing.h"

TEST_CASE("K_Bucket", "[routing]") {
    NodeID start_id = NodeID();
    start_id.fill(0);
    NodeID end_id = NodeID();
    end_id.fill(255);
    KBucket bucket(start_id, end_id);
    SECTION("Creating K_Bucket") {
        auto start = bucket.get_start();
        auto end = bucket.get_end();
        for (size_t i = 0; i < KEY_SIZE; i++) {
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
        for (size_t i = 0; i < KEY_SIZE; i++) {
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
            Node peer = {in6addr_loopback, static_cast<u_short> (ServerConfig::P2P_PORT + 2 + i), generate_random_nodeID()};
            routing_table.add_peer(peer);
        }
        auto& buckets = routing_table.get_bucket_list();
        REQUIRE(buckets.size() == 2);
        REQUIRE(buckets.at(0).get_peers().size() + buckets.at(1).get_peers().size() == K);
        auto first_start = std::array<unsigned char, KEY_SIZE>{};
        first_start.fill(0);
        REQUIRE(buckets.at(0).get_start() == first_start);
        auto first_end = std::array<unsigned char, KEY_SIZE>{};
        first_end.fill(0xff);
        first_end[0] = 0x7f;
        REQUIRE(buckets.at(0).get_end() == first_end);
        auto second_start = std::array<unsigned char, KEY_SIZE>{};
        second_start.fill(0);
        second_start[0] = 0x80;
        REQUIRE(buckets.at(1).get_start() == second_start);
        auto second_end = std::array<unsigned char, KEY_SIZE>{};
        second_end.fill(0xff);
        REQUIRE(buckets.at(1).get_end() == second_end);
    }
    SECTION("Routing Table find_closest_nodes") {
        for (int i = 0; i < K + 1; i++) {
            Node peer = {in6addr_loopback, static_cast<u_short> (ServerConfig::P2P_PORT + 2 + i), generate_random_nodeID()};
            routing_table.add_peer(peer);
        }
        std::vector<Node> all_nodes;
        for (auto& bucket : routing_table.get_bucket_list()) {
            REQUIRE(!RoutingTable::has_duplicate_id(bucket.get_peers()));
            all_nodes.insert(all_nodes.end(), bucket.get_peers().begin(), bucket.get_peers().end());
        }

        REQUIRE(!RoutingTable::has_duplicate_id(all_nodes));

        NodeID target_node_id = generate_random_nodeID();
        std::vector<Node> closest_nodes = routing_table.find_closest_nodes(target_node_id);
        REQUIRE(!RoutingTable::has_duplicate_id(closest_nodes));
        REQUIRE(closest_nodes.size() == K);
        NodeID last_distance = RoutingTable::node_distance(closest_nodes.at(0).id, target_node_id);
        for (int i = 1; i < closest_nodes.size(); i++) {
            auto distance = RoutingTable::node_distance(closest_nodes.at(i).id, target_node_id);
            REQUIRE(last_distance < distance);
            last_distance = distance;
        }
    }
}

TEST_CASE("RoutingTable remove peer", "[routing]") {
    RoutingTable routing_table = RoutingTable(in6addr_loopback, 8080);

    NodeID peerID;
    peerID.fill(0);
    peerID[0] = 1;
    Node peer = {in6addr_loopback, static_cast<u_short>(ServerConfig::P2P_PORT + 2), peerID};

    NodeID peerID2;
    peerID2.fill(2);
    peerID2[0] = 1;
    Node peer2 = {in6addr_loopback, static_cast<u_short>(ServerConfig::P2P_PORT + 4), peerID2};

    routing_table.add_peer(peer);
    routing_table.add_peer(peer2);

    auto& peers = routing_table.get_bucket_list().at(0).get_peers();
    REQUIRE(peers.size() == 2);

    bool removed = routing_table.remove(in6addr_loopback, static_cast<u_short>(ServerConfig::P2P_PORT + 2));
    REQUIRE(removed);
    bool removed2 = routing_table.remove(peer2);
    REQUIRE(removed2);

    REQUIRE(peers.empty());
}


TEST_CASE( "generate_random_nodeID", "[routing]") { // this test was very flaky during development, hence the high number of repetitions
    for (int j = 0; j < 200; j++) {
        REQUIRE_NOTHROW(generate_random_nodeID());
        auto nodeID = generate_random_nodeID();
        REQUIRE(generate_random_nodeID(nodeID, NodeID{}) == NodeID{});
        NodeID nodeID_with_ones{};
        nodeID_with_ones.fill(0x01);

        NodeID nodeID_with_one_zero{};
        nodeID_with_one_zero.fill(0x01);
        nodeID_with_one_zero[1] = 0x0;

        auto generated_nodeID = generate_random_nodeID(nodeID_with_one_zero, nodeID_with_ones);
        REQUIRE(generated_nodeID <= nodeID_with_ones);
        REQUIRE(generated_nodeID >= nodeID_with_one_zero);


        NodeID nodeID_with_one_five{};
        nodeID_with_one_five.fill(0x01);
        nodeID_with_one_five[1] = 0x5;

        generated_nodeID = generate_random_nodeID(nodeID_with_one_zero, nodeID_with_one_five);
        REQUIRE(generated_nodeID <= nodeID_with_one_five);
        REQUIRE(generated_nodeID >= nodeID_with_one_zero);

        NodeID nodeID_with_five_one{};
        nodeID_with_five_one.fill(0x01);
        nodeID_with_five_one[0] = 0x5;
        nodeID_with_five_one[1] = 0x1;

        generated_nodeID = generate_random_nodeID(nodeID_with_one_zero, nodeID_with_five_one);
        REQUIRE(generated_nodeID <= nodeID_with_five_one);
        REQUIRE(generated_nodeID >= nodeID_with_one_zero);
        for (int i = 0 ; i<50; i++) {

            //std::cout << i << std::endl;
            NodeID nodeID_with_50{};
            nodeID_with_50.fill(0x32);

            NodeID nodeID_with_200{};
            nodeID_with_200.fill(0xc8);
            nodeID_with_200[0] = 0x0;

            generated_nodeID = generate_random_nodeID(nodeID_with_200, nodeID_with_50);
            REQUIRE(generated_nodeID <= nodeID_with_50);
            REQUIRE(generated_nodeID >= nodeID_with_200);
        }
    }
}
