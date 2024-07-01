cmake_minimum_required(VERSION 3.13)
project(die_hashies_DHT)

include(FetchContent)

FetchContent_Declare(
  Catch2
  GIT_REPOSITORY https://github.com/catchorg/Catch2.git
  GIT_TAG        v3.6.0  
)
FetchContent_MakeAvailable(Catch2)

list(APPEND CMAKE_MODULE_PATH ${catch2_SOURCE_DIR}/extras) #necessary for include Catch to work
include(CTest)
include(Catch)


set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(SOURCE_DIR ./src)
set(TEST_DIR ./tests)

set(CMAKE_POSITION_INDEPENDENT_CODE OFF)
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g -O0") # Add -O0 flag for debug builds

find_package(Boost REQUIRED COMPONENTS program_options)

add_executable(dht_server ${SOURCE_DIR}/dht_server.cpp)
add_executable(testing ${TEST_DIR}/storage_unit.cpp )
add_executable(dht_server_wo_boost ${SOURCE_DIR}/dht_server_wo_boost.cpp)

target_include_directories(dht_server PRIVATE ${Boost_INCLUDE_DIRS})

target_compile_options(dht_server PRIVATE -g -no-pie)
target_compile_definitions(dht_server PRIVATE BOOST_STACKTRACE_USE_ADDR2LINE)

target_link_libraries(dht_server PRIVATE ${Boost_LIBRARIES})
target_link_libraries(dht_server_wo_boost PRIVATE ${Boost_LIBRARIES})
target_link_libraries(testing PRIVATE Catch2::Catch2WithMain ${Boost_LIBRARIES})

target_link_options(dht_server PRIVATE -no-pie)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()


#Testing
catch_discover_tests(testing)
