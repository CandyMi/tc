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
  inc/utils.h
)

if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  set(CMAKE_MACOSX_RPATH 1)
else()
  set(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)
endif()

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/inc)

# 使用指定的编译标准
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 99)

file(GLOB tinycrypto src/*.c)

add_library(crypto-static STATIC ${tinycrypto})
add_library(crypto SHARED ${tinycrypto})

set_target_properties(
  crypto-static PROPERTIES 
    PREFIX "lib"
    OUTPUT_NAME   "crypto"
    PUBLIC_HEADER "${tc_inc}"
  crypto PROPERTIES
    PREFIX "lib"
    OUTPUT_NAME   "crypto"
    PUBLIC_HEADER "${tc_inc}"
)

if(ENABLE_TEST)
  add_subdirectory( test )
endif()

install(
  TARGETS crypto crypto-static
  ARCHIVE  DESTINATION ${CMAKE_INSTALL_PREFIX}/lib              # libcrypto
  LIBRARY  DESTINATION ${CMAKE_INSTALL_PREFIX}/lib              # libcrypto
  PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_PREFIX}/include/tc  # include
)
