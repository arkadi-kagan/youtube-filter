cmake_minimum_required(VERSION 3.22)

project(proxy VERSION 1.0)

set(CMAKE_BUILD_TYPE Debug)
# set(CMAKE_BUILD_TYPE Release)

find_package(OpenSSL)

add_executable(proxy
    ProxyHTTPS.h
    ProxyHTTPS.cpp
    main.cpp
)

target_link_libraries(proxy
    PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
)
