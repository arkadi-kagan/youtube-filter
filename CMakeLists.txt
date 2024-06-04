cmake_minimum_required(VERSION 3.26)

project(proxy VERSION 1.0)

set(CMAKE_BUILD_TYPE Debug)
# set(CMAKE_BUILD_TYPE Release)

add_executable(proxy
    main.cpp
)

find_package(OpenSSL)

target_link_libraries(proxy
    PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
)
