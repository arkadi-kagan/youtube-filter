cmake_minimum_required(VERSION 3.22)

project(proxy VERSION 1.0)

set(CMAKE_BUILD_TYPE Debug)
# set(CMAKE_BUILD_TYPE Release)

find_package(OpenSSL)
find_package(libzip)    # sudo apt install libzip-dev zipcmp zipmerge ziptool
find_package(ZLIB)  # sudo apt install zlib1g-dev

add_executable(proxy
    ProxyHTTPS.h
    ProxyHTTPS.cpp
    main.cpp
)

target_link_libraries(proxy
    PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
        zip
        ZLIB::ZLIB
)
