message("======================================")
message("Project Name   : TinyCrypto")
message("Author  Name   : CandyMi")
message("Author  Email  : 869646063@qq.com")
message("Author  Github : github.com/CandyMi")
message("======================================")

# 最低版本号
cmake_minimum_required(VERSION 2.8...3.13)

# 项目名称
project("TinyCrypto" C)

# 头文件
set(tc_inc
  inc/tc.h
  inc/sha.h
  inc/rc4.h
  inc/aes.h
  inc/utils.h
)

if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  set(CMAKE_MACOSX_RPATH 1)
else()
  set(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)
endif()

# 增加 CCache 支持
find_program(CCACHE_FOUND ccache)
if(CCACHE_FOUND)
  set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE ccache)
  set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK ccache)
endif()

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/inc)

add_compile_definitions( _CRT_RAND_S _GNU_SOURCE )

if (NOT MSVC)
  add_compile_options(-fPIC -pipe)
endif(NOT MSVC)

file(GLOB tinycrypto src/*.c)

add_library(crypto_object OBJECT ${tinycrypto})

# 动态库
add_library(crypto-static STATIC $<TARGET_OBJECTS:crypto_object>)
# 静态库
add_library(crypto SHARED $<TARGET_OBJECTS:crypto_object>)

if(WIN32)
  set_target_properties(crypto PROPERTIES PUBLIC_HEADER "${tc_inc}" C_EXTENSIONS ON C_STANDARD 99 OUTPUT_NAME "tccrypto" PREFIX "" )
  set_target_properties(crypto-static PROPERTIES PUBLIC_HEADER "${tc_inc}" C_EXTENSIONS ON C_STANDARD 99 OUTPUT_NAME "tccrypto" PREFIX "")
else()
  set_target_properties(crypto PROPERTIES PUBLIC_HEADER "${tc_inc}" C_EXTENSIONS ON C_STANDARD 99 OUTPUT_NAME "tccrypto" PREFIX "lib")
  set_target_properties(crypto-static PROPERTIES PUBLIC_HEADER "${tc_inc}" C_EXTENSIONS ON C_STANDARD 99 OUTPUT_NAME "tccrypto" PREFIX "lib")
endif(WIN32)

if(ENABLE_TEST)
  add_subdirectory( tests )
endif()

install(
  TARGETS crypto crypto-static
  ARCHIVE  DESTINATION ${CMAKE_INSTALL_PREFIX}/lib              # libcrypto
  LIBRARY  DESTINATION ${CMAKE_INSTALL_PREFIX}/lib              # libcrypto
  PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_PREFIX}/include/tc  # include
)
