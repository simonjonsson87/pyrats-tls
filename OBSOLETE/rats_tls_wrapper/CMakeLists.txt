# CMakeLists.txt

cmake_minimum_required(VERSION 3.10)
project(rats_tls_wrapper C)

add_library(rats_tls_wrapper SHARED rats_tls_wrapper.c)
set_target_properties(rats_tls_wrapper PROPERTIES PREFIX "lib")
