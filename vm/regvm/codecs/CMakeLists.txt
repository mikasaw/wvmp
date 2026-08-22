# RegVM bytecode codecs: BytecodeCodec implementations (regvm lane workspace).
add_library(wvmp_regvm_codecs OBJECT
    src/codecs_placeholder.cpp
)
wvmp_target_warnings(wvmp_regvm_codecs)
