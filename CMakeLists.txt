cmake_minimum_required(VERSION 3.15)
project(VEHGuardian LANGUAGES CXX)

# Build a DLL
set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Compiler options (release for MSVC)
if(MSVC)
  add_compile_options(/W3 /MD /O2)
  add_compile_definitions(NOMINMAX)
else()
  add_compile_options(-Wall -Wextra -O2)
endif()

# Sources
add_library(VEHGuardian SHARED
  src/VEHGuardian.cpp
)

# Link debug help lib (used on Windows)
if(WIN32)
  target_link_libraries(VEHGuardian PRIVATE dbghelp)
  target_compile_definitions(VEHGuardian PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

# Install target (optional)
install(TARGETS VEHGuardian
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION bin
  ARCHIVE DESTINATION lib
)
