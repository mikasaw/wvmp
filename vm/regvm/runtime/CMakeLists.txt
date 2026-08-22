# RegVM runtime: interpreter/runtime image generation (regvm lane workspace).
add_library(wvmp_regvm_runtime OBJECT
    src/runtime_placeholder.cpp
)
wvmp_target_warnings(wvmp_regvm_runtime)
