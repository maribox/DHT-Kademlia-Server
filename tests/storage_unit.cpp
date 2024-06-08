#include <catch2/catch_test_macros.hpp>
#include "../src/dht_server.cpp"
#include <random>


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
}

TEST_CASE("get_from_storage fails for invalid key", "[dht_server]") {
  keyType key;
  key.set(255);
  std::optional<valueType> returned_value = get_from_storage(key);
}