cmake_minimum_required(VERSION 3.10)
project(die_hashies_DHT)
set(SOURCE_DIR ./src)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED True)

find_package(Boost REQUIRED)
add_executable(die_hashies_DHT ${SOURCE_DIR}/main.cpp)
target_link_libraries(die_hashies_DHT Boost::boost)