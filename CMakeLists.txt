cmake_minimum_required(VERSION 3.10)
project(SmartExceptionHandler)

set(CMAKE_CXX_STANDARD 17)
set(SOURCES src/main.cpp)

add_library(SmartExceptionHandler SHARED ${SOURCES})

set_target_properties(SmartExceptionHandler PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/output
)
