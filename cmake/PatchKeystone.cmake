# Keystone 0.9.2 predates CMake 4: its top-level and llvm/ CMakeLists
# explicitly select the OLD behavior of CMP0051, which CMake >= 4 refuses to
# emulate. NEW behavior (TARGET_OBJECTS listed in SOURCES) is what a modern
# CMake produces anyway, so flip the two lines. Runs with the freshly
# extracted keystone source tree as the working directory.
foreach(f CMakeLists.txt llvm/CMakeLists.txt)
    if(EXISTS "${f}")
        file(READ "${f}" text)
        string(REPLACE
            "cmake_policy(SET CMP0051 OLD)"
            "cmake_policy(SET CMP0051 NEW)"
            text "${text}")
        file(WRITE "${f}" "${text}")
    endif()
endforeach()
