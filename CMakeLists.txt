cmake_minimum_required(VERSION 3.10)
cmake_minimum_required(VERSION 3.10)
project(die_hashies_DHT)
set(SOURCE_DIR ./src)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED True)

find_package(Boost REQUIRED)
add_executable(die_hashies_DHT ${SOURCE_DIR}/dht_server.cpp)
target_link_libraries(die_hashies_DHT Boost::boost)


find_package(Boost REQUIRED COMPONENTS program_options)
include_directories(${Boost_INCLUDE_DIRS})
target_link_libraries(die_hashies_DHT ${Boost_LIBRARIES})

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()

add_compile_options(-g)
link_libraries(dl)
add_compile_definitions(BOOST_STACKTRACE_USE_ADDR2LINE)
set(CMAKE_POSITION_INDEPENDENT_CODE OFF)
add_compile_options(-no-pie)
add_link_options(-no-pie)

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g")