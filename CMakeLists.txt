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
find_package(OpenSSL REQUIRED)

add_executable(dht_server ${SOURCE_DIR}/dht_server.cpp ${SOURCE_DIR}/routing.cpp
${SOURCE_DIR}/common_types.h ${SOURCE_DIR}/ssl.cpp)
add_executable(testing ${TEST_DIR}/storage_unit.cpp)
add_executable(routing_tests ${TEST_DIR}/routing_unit.cpp ${SOURCE_DIR}/routing.cpp ${SOURCE_DIR}/dht_server.cpp ${SOURCE_DIR}/common_types.h ${SOURCE_DIR}/ssl.cpp)
add_executable(tls_server ${SOURCE_DIR}/tls_server.cpp)

# shouldn't be necessary, but somehow doesn't work when removed
target_compile_definitions(routing_tests PRIVATE TESTING)

target_include_directories(dht_server PRIVATE ${Boost_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR})
target_include_directories(routing_tests PRIVATE ${OPENSSL_INCLUDE_DIR})
target_include_directories(tls_server PRIVATE ${OPENSSL_INCLUDE_DIR})

target_compile_options(dht_server PRIVATE -g -no-pie)
target_compile_definitions(dht_server PRIVATE BOOST_STACKTRACE_USE_ADDR2LINE)
target_compile_options(routing_tests PRIVATE -g)

target_link_libraries(dht_server PRIVATE ${Boost_LIBRARIES} OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(testing PRIVATE Catch2::Catch2WithMain ${Boost_LIBRARIES})
target_link_libraries(routing_tests PRIVATE Catch2::Catch2WithMain ${Boost_LIBRARIES} OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(tls_server OpenSSL::SSL OpenSSL::Crypto)

target_link_options(dht_server PRIVATE -no-pie)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()


#Testing
catch_discover_tests(testing)
catch_discover_tests(routing_tests)

#For cleaning:

# Define a custom target to clean additional files
add_custom_target(clean-extra
    COMMAND ${CMAKE_COMMAND} -E echo "Cleaning .pem and .txt files"
    COMMAND ${CMAKE_COMMAND} -E remove ${CMAKE_BINARY_DIR}/*.pem
    COMMAND ${CMAKE_COMMAND} -E remove ${CMAKE_BINARY_DIR}/*.txt
    COMMENT "Removing additional files (.pem, .txt) from build directory"
)

# Define a clean-all target that runs both built-in clean and clean-extra
add_custom_target(clean-all
    DEPENDS clean-extra
)
# Now, running `cmake --build . --target clean-all` will clean everything