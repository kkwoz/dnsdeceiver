cmake_minimum_required(VERSION 3.14)
project(dnsdeceiver C)

set(CMAKE_C_STANDARD 11)
set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -pedantic")


add_executable(dnsdeceiver
        src/main.c)


