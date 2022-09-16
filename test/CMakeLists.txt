enable_language(CXX)

# 测试MD5
add_executable( test_md5 test_md5.cc )
target_link_libraries(
  test_md5 PRIVATE crypto
)

# 测试SHA
add_executable( test_sha test_sha.cc )
target_link_libraries(
  test_sha PRIVATE crypto
)

# 测试随机
add_executable( test_random test_random.cc )
target_link_libraries(
  test_random PRIVATE crypto
)

# 测试校验
add_executable( test_check test_check.cc )
target_link_libraries(
  test_check PRIVATE crypto
)

# 测试RC4
# add_executable( test_rc4 test_rc4.cc )
# target_link_libraries(
#   test_rc4 PRIVATE crypto
# )


# 单元测试
enable_testing()

# check
add_test(NAME adler32 COMMAND $<TARGET_FILE:test_check> adler32 admin)
add_test(NAME crc32 COMMAND $<TARGET_FILE:test_check> crc32 admin)

# MD5
add_test(NAME md5 COMMAND $<TARGET_FILE:test_md5> md5 admin)
add_test(NAME hmac_md5 COMMAND $<TARGET_FILE:test_md5> md5 admin 123456789)

# SHA
add_test(NAME sha COMMAND $<TARGET_FILE:test_sha> sha admin)
add_test(NAME hmac_sha COMMAND $<TARGET_FILE:test_sha> hmac_sha admin 123456789)

# uuid and randomkey
add_test(NAME uuid COMMAND $<TARGET_FILE:test_random> uuid)
add_test(NAME rkey COMMAND $<TARGET_FILE:test_random> randomkey)