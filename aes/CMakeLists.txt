# CMake最低版本要求
cmake_minimum_required(VERSION 3.18)

# 项目名称
project(aes)

# 添加源文件
file(GLOB SOURCES CONFIGURE_DEPENDS
    src/*.cc
)

# 生成静态库
add_library(${PROJECT_NAME} ${SOURCES})

# 生成动态库
# add_library(${PROJECT_NAME} SHARED ${SOURCES})

# 添加头文件目录
target_include_directories(${PROJECT_NAME} PUBLIC
    include
)
