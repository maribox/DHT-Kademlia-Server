cmake_minimum_required(VERSION 3.13)

include(FetchContent)

FetchContent_Declare(
  Catch2
  GIT_REPOSITORY https://github.com/catchorg/Catch2.git
  GIT_TAG        v3.6.0  
)
FetchContent_MakeAvailable(Catch2)

project(die_hashies_DHT)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(SOURCE_DIR ./src)
set(TEST_DIR ./tests)

set(CMAKE_POSITION_INDEPENDENT_CODE OFF)
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g")

find_package(Boost REQUIRED COMPONENTS program_options)

add_executable(die_hashies_DHT ${SOURCE_DIR}/dht_server.cpp)
add_executable(tests ${TEST_DIR}/storage_unit.cpp)

target_include_directories(die_hashies_DHT PRIVATE ${Boost_INCLUDE_DIRS})

target_compile_options(die_hashies_DHT PRIVATE -g -no-pie)
target_compile_definitions(die_hashies_DHT PRIVATE BOOST_STACKTRACE_USE_ADDR2LINE)

target_link_libraries(die_hashies_DHT PRIVATE ${Boost_LIBRARIES})
target_link_libraries(tests PRIVATE Catch2::Catch2WithMain)

target_link_options(die_hashies_DHT PRIVATE -no-pie)


if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()
