cmake_minimum_required(VERSION 3.15)
project(VEHGuardian LANGUAGES CXX)

# 强制使用 C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 设置输出为 DLL
set(BUILD_SHARED_LIBS ON)

# 自动查找 src 目录下的所有源文件
file(GLOB_RECURSE SRC_FILES
    "src/*.cpp"
    "src/*.c"
)

# 如果没找到源文件则提示错误（防止空构建）
if(NOT SRC_FILES)
    message(FATAL_ERROR "❌ 未找到源码文件（例如 src/VEHGuardian.cpp），请确认路径正确！")
endif()

# 生成 VEHGuardian 动态库（DLL）
add_library(VEHGuardian SHARED ${SRC_FILES})

# 输出路径
set_target_properties(VEHGuardian PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
)

# 开启编译优化和较强安全保护
if(MSVC)
    target_compile_options(VEHGuardian PRIVATE /W4 /O2 /Zi /EHsc /MP)
    target_link_options(VEHGuardian PRIVATE /INCREMENTAL:NO /DEBUG)
endif()

# 可选：定义导出宏（若代码中有 __declspec(dllexport) 控制）
target_compile_definitions(VEHGuardian PRIVATE VEHGUARDIAN_EXPORTS)

# 打印状态提示
message(STATUS "✅ VEHGuardian will be built as a 64-bit DLL")
message(STATUS "Source files: ${SRC_FILES}")
