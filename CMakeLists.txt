# CMake最低版本要求
cmake_minimum_required(VERSION 3.18)

# 项目名称
project(main)

# 设置可执行文件输出目录
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/bin)

# 设置动态库输出目录
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})

# 添加子目录
add_subdirectory(aes)

# 添加源文件
file(GLOB SOURCES CONFIGURE_DEPENDS
    src/*.cc
)

# 生成可执行文件
add_executable(${PROJECT_NAME} ${SOURCES})

# 链接目标文件与可执行文件
target_link_libraries(${PROJECT_NAME} PRIVATE
    aes
)
