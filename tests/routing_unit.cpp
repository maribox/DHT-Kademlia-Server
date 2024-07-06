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
}
