#define CATCH_CONFIG_MAIN
#include <catch2/catch_test_macros.hpp>
#include "../src/dht_server.hpp"
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

// Command-Line Argument Tests
TEST_CASE("does not crash when running without arguments", "[dht_server]") {
  const char* argv[] = {"dht_app"};
  int argc = 1;
  REQUIRE_NOTHROW(main(argc, argv));
}

TEST_CASE("does not crash when running with correct arguments",
          "[dht_server]") {
  const char* argv[] = {"dht_app", "--address", "127.0.0.1", "--port", "1234"};
  int argc = 5;
  REQUIRE_NOTHROW(main(argc, argv));
}
