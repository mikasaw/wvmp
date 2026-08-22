# RegVM ISA: opcode set / encoding tables (regvm lane workspace).
add_library(wvmp_regvm_isa OBJECT
    src/isa_placeholder.cpp
)
wvmp_target_warnings(wvmp_regvm_isa)
