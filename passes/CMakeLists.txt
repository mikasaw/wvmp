# Pass aggregation.
#
# Every pass is an OBJECT library and all objects are force-linked into the
# STATIC archive wvmp_passes_all: on MSVC this is what keeps the passes'
# self-registering objects (WVMP_REGISTER_PASS) from being discarded by the
# linker when nothing else references them.
#
# New passes are added as their own subdirectory entry in the list below
# (this file is owned by the coordinator; lanes do not edit it).

set(WVMP_ALL_PASSES
    pe_loader
    pe_writer
    marker_scan
    lifter
    mutate
    virtualize
    crypt
    anti_debug
    integrity_crc
    import_protect
    stub_link
)

set(WVMP_PASS_OBJECTS)
foreach(_pass IN LISTS WVMP_ALL_PASSES)
    add_subdirectory(${_pass})
    list(APPEND WVMP_PASS_OBJECTS $<TARGET_OBJECTS:wvmp_pass_${_pass}>)
endforeach()

add_library(wvmp_passes_all STATIC ${WVMP_PASS_OBJECTS})
add_library(wvmp::passes_all ALIAS wvmp_passes_all)
target_link_libraries(wvmp_passes_all PUBLIC
    wvmp::framework
    wvmp::ir
    wvmp::common
    wvmp::vm
)
