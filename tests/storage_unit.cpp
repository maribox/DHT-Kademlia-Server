#ifndef TESTING
  #define TESTING
#endif

#include <catch2/catch_test_macros.hpp>
#include <random>
#include "../src/dht_server.cpp"

TEST_CASE("save_to_storage inserts and get_from_storage extracts correct value", "[dht_server]") {
    Key key{1, 2, 3, 4, 5};
    Value value{9, 8, 7, 6, 5, 4, 3, 2, 1};
    save_to_storage(key, std::chrono::seconds{20}, value);
    std::optional<Value> returned_value = get_from_storage(key);

    REQUIRE(returned_value.has_value());
    REQUIRE(returned_value.value() == value);

    SECTION("save_to_storage overwrites old value") {
        Value secondValue{1, 2, 3};
        save_to_storage(key, std::chrono::seconds{20}, secondValue);
        std::optional<Value> returned_second_value = get_from_storage(key);
        REQUIRE(returned_second_value.has_value());
        REQUIRE(returned_second_value.value() == secondValue);
    }
}

// sorry den brauchen wir doch lul
TEST_CASE(
    "get_from_storage does not fail and returns empty optional when key is not "
    "available",
    "[dht_server]") {
  Key key;
  REQUIRE_NOTHROW(key.at(32) = 0x80);
  REQUIRE(!get_from_storage(key).has_value());
}


/*  probably best to pass stop flag to runEventLoop 

TEST_CASE("starting up server works") {
    socket_t serversocket = setupSocket(DHTServerConfig::DHT_PORT);
    int epollfd = setupEpoll(serversocket);
    std::vector<epoll_event> eventsPerLoop{64};
    std::thread server([&]() {runEventLoop(serversocket, epollfd, eventsPerLoop);});
    std::this_thread::sleep_for(std::chrono::seconds(5));
    server.join();

    // TODO: figure out if this works
    REQUIRE(true);
}
 */
