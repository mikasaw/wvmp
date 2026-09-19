cmake_minimum_required(VERSION 3.15)
project(wvmp_test_target LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# MIT-520 AVX corpus batch is x64-only, matching build.bat: the x86 flavor
# carries neither TU, so kernavx registration stays in exactly one place.
set(WVMPTEST_AVX_SOURCES "")
if(MSVC AND CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(WVMPTEST_AVX_SOURCES
        src/targets/avx_kernels.cpp
        src/tests/t_kernels_avx.cpp
    )
    set_source_files_properties(src/targets/avx_kernels.cpp PROPERTIES
        COMPILE_OPTIONS "/Od;/arch:AVX")
endif()

add_executable(test_target
    src/main.cpp
    src/testfw.cpp
    src/targets/kernels.cpp
    src/tests/t_math.cpp
    src/tests/t_controlflow.cpp
    src/tests/t_string.cpp
    src/tests/t_memory.cpp
    src/tests/t_datastruct.cpp
    src/tests/t_hashcrypto.cpp
    src/tests/t_exception.cpp
    src/tests/t_stl.cpp
    src/tests/t_oop.cpp
    src/tests/t_thread.cpp
    src/tests/t_winapi.cpp
    src/tests/t_float_sse.cpp
    src/tests/t_kernels.cpp
    ${WVMPTEST_AVX_SOURCES}
)

target_compile_definitions(test_target PRIVATE
    $<$<PLATFORM_ID:Windows>:_WIN32_WINNT=0x0601>
    NOMINMAX WIN32_LEAN_AND_MEAN
)

if(MSVC)
    target_compile_options(test_target PRIVATE /W3 /EHsc /utf-8)
else()
    target_compile_options(test_target PRIVATE -Wall -Wextra)
endif()

# Lower optimization makes packed-baseline comparisons easier to reason
# about; flip to Release when profiling real-world protection overhead.
