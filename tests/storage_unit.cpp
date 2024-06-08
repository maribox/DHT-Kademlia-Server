#define CATCH_CONFIG_MAIN

#ifndef TESTING
#define TESTING
#endif

#include <catch2/catch_test_macros.hpp>
#include <random>

#include "../src/dht_server.cpp"

TEST_CASE("save_to_storage inserts and get_from_storage extracts correct value", "[dht_server]") {
  keyType key;
  key.set(0);
  key.set(3);
  key.set(4);
  key.set(5);
  key.set(8);
  key.set(10);

  valueType value = 98419561;
  save_to_storage(key, value);
  std::optional<valueType> returned_value = get_from_storage(key);

  REQUIRE(returned_value.has_value());
  REQUIRE(returned_value.value() == value);

  SECTION("save_to_storage overwrites old value") {
    valueType secondValue = 123;
    save_to_storage(key, secondValue);
    std::optional<valueType> returned_second_value = get_from_storage(key);
    REQUIRE(returned_second_value.has_value());
    REQUIRE(returned_second_value.value() == secondValue);
  }
}



TEST_CASE(
    "get_from_storage does not fail and returns empty optional when key is not "
    "available",
    "[dht_server]") {
  keyType key;
  REQUIRE_NOTHROW(key.set(255));
  REQUIRE(!get_from_storage(key).has_value());
}

