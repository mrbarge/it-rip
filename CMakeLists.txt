cmake_minimum_required(VERSION 3.16)
project(it_rip C)

set(CMAKE_C_STANDARD 99)

add_executable(it_rip main.c)

include_directories("/usr/include/mysql/")

find_library(XMP_LIB xmp)
find_library(SSL_LIB ssl)
find_library(CRYPTO_LIB crypto)
find_library(MYSQL_LIB mysqlclient)

target_link_libraries(it_rip "${XMP_LIB}")
target_link_libraries(it_rip "${SSL_LIB}")
target_link_libraries(it_rip "${CRYPTO_LIB}")
target_link_libraries(it_rip "${MYSQL_LIB}")
