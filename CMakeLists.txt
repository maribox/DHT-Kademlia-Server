cmake_minimum_required(VERSION 3.13)

project(die_hashies_DHT)

set(SOURCE_DIR ./src)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Boost REQUIRED COMPONENTS program_options)

add_executable(die_hashies_DHT ${SOURCE_DIR}/dht_server.cpp)
target_include_directories(die_hashies_DHT PRIVATE ${Boost_INCLUDE_DIRS})
target_link_libraries(die_hashies_DHT PRIVATE ${Boost_LIBRARIES})

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()

target_compile_options(die_hashies_DHT PRIVATE -g -no-pie)
target_compile_definitions(die_hashies_DHT PRIVATE BOOST_STACKTRACE_USE_ADDR2LINE)

target_link_options(die_hashies_DHT PRIVATE -no-pie)

set(CMAKE_POSITION_INDEPENDENT_CODE OFF)

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g")