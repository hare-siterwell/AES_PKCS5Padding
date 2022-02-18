cmake_minimum_required(VERSION 3.18)
project(main)

file(GLOB SOURCES CONFIGURE_DEPENDS
    dev/*.cc
    src/*.cc
)

SET(EXECUTABLE_OUTPUT_PATH ${CMAKE_CURRENT_SOURCE_DIR}/bin)

add_executable(${PROJECT_NAME} ${SOURCES})

target_include_directories(${PROJECT_NAME} PRIVATE
    src
)
