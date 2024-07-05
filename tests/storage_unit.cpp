#define CATCH_CONFIG_MAIN

#include <catch2/catch_test_macros.hpp>
#include <random>

#include "../src/dht_server_wo_boost.cpp"

TEST_CASE("save_to_storage inserts and get_from_storage extracts correct value", "[dht_server]") {
    keyType key{1, 2, 3, 4, 5};
    valueType value{9, 8, 7, 6, 5, 4, 3, 2, 1};
    save_to_storage(key, std::chrono::seconds{20}, value);
    std::optional<valueType> returned_value = get_from_storage(key);

    REQUIRE(returned_value.has_value());
    REQUIRE(returned_value.value() == value);

    SECTION("save_to_storage overwrites old value") {
        valueType secondValue{1, 2, 3};
        save_to_storage(key, std::chrono::seconds{20}, secondValue);
        std::optional<valueType> returned_second_value = get_from_storage(key);
        REQUIRE(returned_second_value.has_value());
        REQUIRE(returned_second_value.value() == secondValue);
    }
}

TEST_CASE("starting up server works") {
    socket_t serversocket = setupSocket(DHTServerConfig::DHT_PORT);
    int epollfd = setupEpoll(serversocket);
    std::vector<epoll_event> eventsPerLoop{64};
    runEventLoop(serversocket, epollfd, eventsPerLoop);
}
