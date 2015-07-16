cmake_minimum_required(VERSION 3.2)
project(filters)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

include_directories("../../include")
include_directories("/usr/local/opt/apr/libexec/include/apr-1")
include_directories("/usr/local/opt/apr-util/libexec/include/apr-1")

set(SOURCE_FILES
    mod_url_replace.c)

add_executable(filters ${SOURCE_FILES})