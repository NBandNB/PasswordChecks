cmake_minimum_required(VERSION 3.0.0)

project(PasswordChecks VERSION 0.1.0)



add_executable(PasswordChecks PasswordChecks.cpp )

target_link_libraries(PasswordChecks cryptopp curl)