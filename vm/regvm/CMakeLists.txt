# RegVM: the default register-based VM backend.
# Workspace of the regvm lane (P2): isa / translator / runtime / codecs / backend.
# Aggregated into the single public target wvmp_regvm.
add_subdirectory(isa)
add_subdirectory(translator)
add_subdirectory(runtime)
add_subdirectory(codecs)
add_subdirectory(backend)

add_library(wvmp_regvm STATIC
    $<TARGET_OBJECTS:wvmp_regvm_isa>
    $<TARGET_OBJECTS:wvmp_regvm_translator>
    $<TARGET_OBJECTS:wvmp_regvm_runtime>
    $<TARGET_OBJECTS:wvmp_regvm_codecs>
    $<TARGET_OBJECTS:wvmp_regvm_backend>
)
add_library(wvmp::regvm ALIAS wvmp_regvm)
target_link_libraries(wvmp_regvm PUBLIC wvmp::vm)
