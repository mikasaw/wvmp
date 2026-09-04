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

# OBJECT 库作为 SOURCES（$<TARGET_OBJECTS:...>）消费时不传播 usage
# requirements，lifter 挂在自身 INTERFACE 上的 capstone 对象到这里就断了。
# 显式把 capstone 对象挂到聚合库接口：任何 wvmp_passes_all 的消费者
# （cli / 测试，含 WHOLE_ARCHIVE 整包链接形态）都能在链接行拿到它们；
# 对象不在归档内部，不会重复打包。
# 同理：virtualize 消费 regvm 的全部对象（M2-1 起）。
if(TARGET wvmp::capstone)
    target_link_libraries(wvmp_passes_all INTERFACE
        $<BUILD_INTERFACE:$<TARGET_OBJECTS:capstone>>)
endif()
if(TARGET wvmp_regvm_backend)
    target_link_libraries(wvmp_passes_all INTERFACE
        $<BUILD_INTERFACE:$<TARGET_OBJECTS:wvmp_regvm_isa>>
        $<BUILD_INTERFACE:$<TARGET_OBJECTS:wvmp_regvm_translator>>
        $<BUILD_INTERFACE:$<TARGET_OBJECTS:wvmp_regvm_runtime>>
        $<BUILD_INTERFACE:$<TARGET_OBJECTS:wvmp_regvm_backend>>
        # MIT-458: crypt pass 引用 xor_chain codec（encrypt_with_key /
        # create_codec），同上 OBJECT 不传播，显式挂聚合库接口。
        $<BUILD_INTERFACE:$<TARGET_OBJECTS:wvmp_regvm_codecs>>)
    # runtime 对象引用 ks_*：OBJECT 依赖的 keystone 链接同样不自动传播。
    if(TARGET wvmp::keystone)
        target_link_libraries(wvmp_passes_all INTERFACE wvmp::keystone)
    endif()
endif()
