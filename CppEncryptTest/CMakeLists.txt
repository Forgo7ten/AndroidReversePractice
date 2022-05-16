cmake_minimum_required(VERSION 3.21)
project(Ctest)

set(CMAKE_CXX_STANDARD 11)
#set(CMAKE_CXX_FLAGS “${CMAKE_CXX_FLAGS} -Wall -fexec-charset=GBK”)
#set(CMAKE_C_FLAGS “${CMAKE_C_FLAGS} -Wall -fexec-charset=GBK”)
add_executable(Crypt crypt.cpp fcrypt/fcrypt.h fcrypt/tea.cpp fcrypt/rc4.cpp fcrypt/base64.cpp)
