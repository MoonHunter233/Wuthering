cmake_minimum_required(VERSION 3.15)
project(wuthering)

# 设置 C++ 标准和相关编译选项
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_EXPORT_COMPILE_COMMANDS 1)
# 添加 cmake 模块路径
# list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# 项目配置选项
# option(BUILD_TESTS "Build tests" ON)
# option(BUILD_DOCS "Build documentation" OFF)

# 查找依赖
# find_package(Threads REQUIRED)
# find_package(PCAP REQUIRED)

# 包含目录
include_directories(${PROJECT_SOURCE_DIR}/include)

# 添加子目录
# add_subdirectory(src)

# 可选：测试和文档
# if(BUILD_TESTS)
#     enable_testing()
#     add_subdirectory(tests)
# endif()
#
# if(BUILD_DOCS)
#     add_subdirectory(docs)
# endif()

file(GLOB_RECURSE src ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp)

add_executable(wuthering ${src})
