# RegVM translator: ir::Insn -> RegVM bytecode (regvm lane workspace).
add_library(wvmp_regvm_translator OBJECT
    src/translator_placeholder.cpp
)
wvmp_target_warnings(wvmp_regvm_translator)
