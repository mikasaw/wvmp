add_executable(wvmp_tool
    src/placeholder.cpp
)
target_link_libraries(wvmp_tool PRIVATE
    wvmp::passes_all
    wvmp::sdk
)
wvmp_target_warnings(wvmp_tool)
