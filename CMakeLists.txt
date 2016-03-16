cmake_minimum_required(VERSION 3.3)
project(BitTorrent)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gcc")

set(HEADER_FILES bt_devel/bencode.h)
set(HEADER_FILES bt_devel/bt_io.h)
set(HEADER_FILES bt_devel/bt_lib.h)
set(HEADER_FILES bt_devel/bt_setup.h)
set(HEADER_FILES bt_devel/bt_sock.h)

set(SOURCE_FILES bt_devel/bencode.c)
set(SOURCE_FILES bt_devel/bt_io.c)
set(SOURCE_FILES bt_devel/bt_lib.c)
set(SOURCE_FILES bt_devel/bt_setup.c)
set(SOURCE_FILES bt_devel/bt_sock.c)
set(SOURCE_FILES bt_devel/bt_client.c)

add_executable(BitTorrent ${SOURCE_FILES} ${HEADER_FILES})