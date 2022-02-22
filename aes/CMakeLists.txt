cmake_minimum_required(VERSION 3.18)
project(aes)

file(GLOB SOURCES CONFIGURE_DEPENDS
    src/*.cc
)

add_library(${PROJECT_NAME} SHARED ${SOURCES})

target_include_directories(${PROJECT_NAME} PUBLIC
    include
)
