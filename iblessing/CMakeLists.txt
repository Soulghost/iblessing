cmake_minimum_required(VERSION 3.5)

project(iblessing VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS -pthread)
set(CMAKE_C_STANDARD 11)

option(iblessing.CSR_ENABLED "System Integrity Protection Manager Option" OFF)
option(iblessing.COCOA_FOUNDATION_ENABLED "Cocoa Foundation Framework Option" OFF)

if (iblessing.PLATFORM) 
    message(STATUS "Platform to build: ${iblessing.PLATFORM}")
else()
    message(STATUS "Cannot find platform to build, set iblessing.PLATFORM to macos")
    set(iblessing.PLATFORM "macos")
endif()

if (NOT (iblessing.PLATFORM STREQUAL "macos") 
    AND
    NOT (iblessing.PLATFORM STREQUAL "linux"))
    message(FATAL_ERROR "iblessing.platform can only be macos or linux")
endif()

if (iblessing.PLATFORM STREQUAL "macos")
    message(STATUS "Enable System Integrity Protection Manager")
    set(iblessing.CSR_ENABLED ON)

    message(STATUS "Enable Cocoa Frameworks")
    set(iblessing.COCOA_FOUNDATION_ENABLED ON)
endif()

# main executable
add_executable(iblessing iblessing/main.cpp)
add_executable(iblessing-all iblessing/main.cpp)
add_library(iblessing-core SHARED iblessing-core/v2/iblessing-core.cpp)
add_library(iblessing-core-static STATIC iblessing-core/v2/iblessing-core.cpp)

# vendor libs
# target_link_libraries(iblessing ${CMAKE_SOURCE_DIR}/../submodules/capstone/libcapstone.a)
target_link_libraries(iblessing-core ${CMAKE_SOURCE_DIR}/../submodules/capstone/libcapstone.a)
target_link_libraries(iblessing-core-static ${CMAKE_SOURCE_DIR}/../submodules/capstone/libcapstone.a)

# target_link_libraries(iblessing ${CMAKE_SOURCE_DIR}/../submodules/unicorn/libunicorn.a)
target_link_libraries(iblessing-core ${CMAKE_SOURCE_DIR}/../submodules/unicorn/libunicorn.a)
target_link_libraries(iblessing-core-static ${CMAKE_SOURCE_DIR}/../submodules/unicorn/libunicorn.a)

# target_link_libraries(iblessing ${CMAKE_SOURCE_DIR}/../submodules/keystone/build/llvm/lib/libkeystone.a)
target_link_libraries(iblessing-core ${CMAKE_SOURCE_DIR}/../submodules/keystone/build/llvm/lib/libkeystone.a)
target_link_libraries(iblessing-core-static ${CMAKE_SOURCE_DIR}/../submodules/keystone/build/llvm/lib/libkeystone.a)

target_link_libraries(iblessing iblessing-core)
target_link_libraries(iblessing-all iblessing-core-static)

if ((iblessing.PLATFORM STREQUAL "linux")) 
    target_link_libraries(iblessing dl)
    target_link_libraries(iblessing-all dl)
    target_link_libraries(iblessing-core stdc++fs)
    target_link_libraries(iblessing-core-static stdc++fs)
endif()

# macro inject
if (iblessing.CSR_ENABLED) 
    target_compile_definitions(iblessing PRIVATE IB_CSR_ENABLED)
    target_compile_definitions(iblessing-all PRIVATE IB_CSR_ENABLED)
endif()

if (iblessing.COCOA_FOUNDATION_ENABLED) 
    target_compile_definitions(iblessing PRIVATE IB_COCOA_FOUNDATION_ENABLED)
    target_compile_definitions(iblessing-all PRIVATE IB_COCOA_FOUNDATION_ENABLED)
endif()

if (iblessing.PLATFORM STREQUAL "macos") 
    target_compile_definitions(iblessing PRIVATE IB_PLATFORM_DARWIN)
    target_compile_definitions(iblessing-all PRIVATE IB_PLATFORM_DARWIN)
endif()

set(iblessing.VENDOR_INCLUDES
    ${CMAKE_SOURCE_DIR}/../submodules/capstone/include
    ${CMAKE_SOURCE_DIR}/../submodules/unicorn/include
    ${CMAKE_SOURCE_DIR}/../submodules/keystone/include
)

set(iblessing.SOURCE_INCLUDES
    ${CMAKE_SOURCE_DIR}

    iblessing
    iblessing/tests
    iblessing/vendor
    iblessing/vendor/argparse
    iblessing/builtin/generator
    iblessing/builtin/serialization
    iblessing/builtin/scanner
    iblessing/builtin/scanner/domain
    iblessing/builtin/scanner/assistance/state
    iblessing/builtin/scanner/sub-scanner/objc-msg-xref

    # dirty work
    # utils
    iblessing-core/v2/util

    # infra
    iblessing-core/infra
    iblessing-core/core/polyfill
    iblessing-core/core/disasm
    iblessing-core/core/dyld
    iblessing-core/core/memory
    iblessing-core/core/runtime
    iblessing-core/core/structs
    iblessing-core/core/symtab
    iblessing-core/core/foundation

    # scanner
    iblessing-core/scanner/context
    iblessing-core/scanner/dispatcher
    iblessing-core/scanner/driver

    # v2
    iblessing-core/v2/mach-o
    iblessing-core/v2/memory
    iblessing-core/v2/dyld
    iblessing-core/v2/objc
    iblessing-core/v2/analyser/wrapper
    iblessing-core/v2/analyser/xref
)

set(iblessing-core.SOURCE_INCLUDES
    ${CMAKE_SOURCE_DIR}

    iblessing-core/
    # utils
    iblessing-core/v2/util

    # infra
    iblessing-core/infra

    # mach-o
    iblessing-core/core/polyfill
    iblessing-core/core/disasm
    iblessing-core/core/dyld
    iblessing-core/core/memory
    iblessing-core/core/runtime
    iblessing-core/core/structs
    iblessing-core/core/symtab
    iblessing-core/core/foundation

    # scanner
    iblessing-core/scanner/context
    iblessing-core/scanner/dispatcher
    iblessing-core/scanner/driver

    # v2
    iblessing-core/v2/mach-o
    iblessing-core/v2/memory
    iblessing-core/v2/dyld
    iblessing-core/v2/objc
    iblessing-core/v2/analyser/wrapper
    iblessing-core/v2/analyser/xref
)

if (iblessing.CSR_ENABLED)
    set(iblessing.SOURCE_INCLUDES ${iblessing.SOURCE_INCLUDES}
        iblessing/platform/macos
    )
endif()

set(iblessing.SOURCE_LIST
    iblessing/builtin/scanner/ObjcClassXrefScanner.cpp
    iblessing/builtin/scanner/ObjcMethodXrefScanner.cpp
    iblessing/builtin/scanner/SymbolXREFScanner.cpp
    iblessing/builtin/scanner/SymbolWrapperScanner.cpp
    iblessing/builtin/scanner/PredicateScanner.cpp
    iblessing/builtin/scanner/ObjcUnserializationScanner.cpp
    iblessing/builtin/scanner/assistance/state/ProgramState.cpp
    iblessing/builtin/scanner/assistance/state/ProgramStateManager.cpp
    iblessing/builtin/scanner/sub-scanner/objc-msg-xref/ObjcReflectionInfoManager.cpp

    # registry
    iblessing/registry/PluginRegistry.cpp

    # generator
    iblessing/builtin/generator/Generator.cpp
    iblessing/builtin/generator/GeneratorDispatcher.cpp
    iblessing/builtin/generator/IDAObjcMsgXREFGenerator.cpp
    iblessing/builtin/generator/IDASymbolWrapperNamingScriptGenerator.cpp
    iblessing/builtin/generator/ObjcMsgXREFServerGenerator.cpp
    iblessing/builtin/generator/ObjcMsgXREFStatisticsGenerator.cpp
    iblessing/builtin/generator/ObjcMsgXREFReportGenerator.cpp
    iblessing/builtin/generator/IDASymbolicScriptGenerator.cpp

    # serialization
    iblessing/builtin/serialization/ObjcMethodChainSerializationManager.cpp
    iblessing/builtin/serialization/SymbolWrapperSerializationManager.cpp
    iblessing/builtin/serialization/ObjcMethodCallSnapshotSerializationManager.cpp

    # domain
    iblessing/builtin/scanner/domain/ObjcMethodChain.cpp
    iblessing/builtin/scanner/domain/ObjcMethodCall.cpp

    # test
    iblessing/tests/Tester.cpp
    iblessing/tests/TestManager.cpp
    iblessing/tests/TestObjcMethodXrefs.cpp
)

set(iblessing-core.SOURCE_LIST
    # utils
    iblessing-core/v2/util/StringUtils.cpp

    # infra
    iblessing-core/infra/Object.cpp

    # mach-o
    iblessing-core/core/polyfill/mach-universal.cpp
    iblessing-core/core/disasm/ARM64Disasembler.cpp
    iblessing-core/core/disasm/ARM64Registers.cpp
    iblessing-core/core/disasm/ARM64ThreadState.cpp

    iblessing-core/core/dyld/DyldSimulator.cpp

    iblessing-core/core/memory/VirtualMemory.cpp
    iblessing-core/core/memory/VirtualMemoryV2.cpp

    iblessing-core/core/runtime/ARM64Runtime.cpp
    iblessing-core/core/runtime/ObjcBlock.cpp
    iblessing-core/core/runtime/ObjcClass.cpp
    iblessing-core/core/runtime/ObjcIvar.cpp
    iblessing-core/core/runtime/ObjcMethod.cpp
    iblessing-core/core/runtime/ObjcObject.cpp
    iblessing-core/core/runtime/ObjcRuntime.cpp
    iblessing-core/core/runtime/ObjcCategory.cpp
    iblessing-core/core/runtime/SimpleSimProcedure.cpp

    iblessing-core/core/structs/Foundation.cpp

    iblessing-core/core/symtab/StringTable.cpp
    iblessing-core/core/symtab/Symbol.cpp
    iblessing-core/core/symtab/SymbolTable.cpp

    iblessing-core/core/foundation/CoreFoundation.cpp

    # scanner
    iblessing-core/scanner/context/ScannerContext.cpp
    iblessing-core/scanner/context/ScannerContextManager.cpp
    iblessing-core/scanner/context/ScannerWorkDirManager.cpp
    iblessing-core/scanner/dispatcher/ScannerDispatcher.cpp
    iblessing-core/scanner/driver/ScannerDisassemblyDriver.cpp

    # v2
    iblessing-core/v2/mach-o/mach-o.cpp
    iblessing-core/v2/memory/memory.cpp
    iblessing-core/v2/dyld/dyld.cpp
    iblessing-core/v2/objc/objc.cpp
    iblessing-core/v2/analyser/wrapper/AntiWrapper.cpp
    iblessing-core/v2/analyser/wrapper/FunctionPrototype.cpp
    iblessing-core/v2/analyser/wrapper/SimpleWrapperAnalyser.cpp
    iblessing-core/v2/analyser/xref/FunctionXrefAnalyser.cpp
)

if (iblessing.CSR_ENABLED)
    set(iblessing.SOURCE_LIST ${iblessing.SOURCE_LIST}
        iblessing/platform/macos/csrutil.cpp
    )
endif()

if (iblessing.COCOA_FOUNDATION_ENABLED) 
    set(iblessing.SOURCE_LIST ${iblessing.SOURCE_LIST}
        # cocoa scanner
        iblessing/builtin/scanner/AppInfoScanner.mm
    )

    target_link_libraries(iblessing "-framework Foundation")
    target_link_libraries(iblessing-all "-framework Foundation")
endif()

target_include_directories(iblessing PRIVATE 
                           ${iblessing.SOURCE_INCLUDES}
                           ${iblessing.VENDOR_INCLUDES}
                           )
target_include_directories(iblessing-all PRIVATE 
                           ${iblessing.SOURCE_INCLUDES}
                           ${iblessing.VENDOR_INCLUDES}
                           )

target_include_directories(iblessing-core PRIVATE 
                           ${iblessing-core.SOURCE_INCLUDES}
                           ${iblessing.VENDOR_INCLUDES}
                           )
target_include_directories(iblessing-core-static PRIVATE 
                           ${iblessing-core.SOURCE_INCLUDES}
                           ${iblessing.VENDOR_INCLUDES}
                           )

target_sources(iblessing PRIVATE ${iblessing.SOURCE_LIST})
target_sources(iblessing-all PRIVATE ${iblessing.SOURCE_LIST})

target_sources(iblessing-core PRIVATE ${iblessing-core.SOURCE_LIST})
target_sources(iblessing-core-static PRIVATE ${iblessing-core.SOURCE_LIST})