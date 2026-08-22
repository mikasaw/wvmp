add_executable(wvmp_cli
    src/main.cpp
)
target_link_libraries(wvmp_cli PRIVATE
    wvmp::passes_all
    wvmp::sdk
)
wvmp_target_warnings(wvmp_cli)
