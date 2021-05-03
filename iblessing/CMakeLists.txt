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

# library
add_library(iblessing-core SHARED iblessing/v2/iblessing/iblessing-core.cpp)

# vendor libs
target_link_libraries(iblessing ${CMAKE_SOURCE_DIR}/../submodules/capstone/libcapstone.a)
target_link_libraries(iblessing-core ${CMAKE_SOURCE_DIR}/../submodules/capstone/libcapstone.a)

target_link_libraries(iblessing ${CMAKE_SOURCE_DIR}/../submodules/unicorn/libunicorn.a)
target_link_libraries(iblessing-core ${CMAKE_SOURCE_DIR}/../submodules/unicorn/libunicorn.a)

target_link_libraries(iblessing ${CMAKE_SOURCE_DIR}/../submodules/keystone/build/llvm/lib/libkeystone.a)
target_link_libraries(iblessing-core ${CMAKE_SOURCE_DIR}/../submodules/keystone/build/llvm/lib/libkeystone.a)

if ((iblessing.PLATFORM STREQUAL "linux")) 
    target_link_libraries(iblessing stdc++fs)
    target_link_libraries(iblessing-core stdc++fs)
endif()

# macro inject
if (iblessing.CSR_ENABLED) 
    target_compile_definitions(iblessing PRIVATE IB_CSR_ENABLED)
endif()

if (iblessing.COCOA_FOUNDATION_ENABLED) 
    target_compile_definitions(iblessing PRIVATE IB_COCOA_FOUNDATION_ENABLED)
endif()

if (iblessing.PLATFORM STREQUAL "macos") 
    target_compile_definitions(iblessing PRIVATE IB_PLATFORM_DARWIN)
endif()

set(iblessing.VENDOR_INCLUDES
    ${CMAKE_SOURCE_DIR}/../submodules/capstone/include
    ${CMAKE_SOURCE_DIR}/../submodules/unicorn/include
    ${CMAKE_SOURCE_DIR}/../submodules/keystone/include
)

set(iblessing.SOURCE_INCLUDES
    ${CMAKE_SOURCE_DIR}

    # vendors
    iblessing/vendor/argparse
    iblessing/vendor/termcolor
    iblessing/vendor/httplib
    iblessing/vendor/rapidjson

    # infra
    iblessing/infra

    # common
    iblessing/common
    iblessing/common/macro

    # mach-o
    iblessing/core/polyfill
    iblessing/core/disasm
    iblessing/core/dyld
    iblessing/core/memory
    iblessing/core/runtime
    iblessing/core/structs
    iblessing/core/symtab
    iblessing/core/foundation

    # scanner
    iblessing/scanner
    iblessing/scanner/common
    iblessing/scanner/context
    iblessing/scanner/dispatcher
    iblessing/scanner/driver
    iblessing/scanner/assistance/state
    iblessing/scanner/sub-scanner
    iblessing/scanner/sub-scanner/objc-msg-xref

    # generator
    iblessing/generator

    # tools
    iblessing/tools
    iblessing/tools/otool

    # serialization
    iblessing/serialization

    # analyzer
    iblessing/analyzer
    iblessing/analyzer/deobfuscator

    # domain
    iblessing/domain

    # tests
    iblessing/tests

    # v2
    iblessing/v2
    iblessing/v2/example
)

if (iblessing.CSR_ENABLED)
    set(iblessing.SOURCE_INCLUDES ${iblessing.SOURCE_INCLUDES}
        iblessing/platform/macos
    )
endif()

set(iblessing.SOURCE_LIST
    # utils
    iblessing/v2/iblessing/util/StringUtils.cpp

    # infra
    iblessing/infra/Object.cpp

    # mach-o
    iblessing/core/polyfill/mach-universal.cpp
    iblessing/core/disasm/ARM64Disasembler.cpp
    iblessing/core/disasm/ARM64Registers.cpp
    iblessing/core/disasm/ARM64ThreadState.cpp

    iblessing/core/dyld/DyldSimulator.cpp

    iblessing/core/memory/VirtualMemory.cpp
    iblessing/core/memory/VirtualMemoryV2.cpp

    iblessing/core/runtime/ARM64Runtime.cpp
    iblessing/core/runtime/ObjcBlock.cpp
    iblessing/core/runtime/ObjcClass.cpp
    iblessing/core/runtime/ObjcIvar.cpp
    iblessing/core/runtime/ObjcMethod.cpp
    iblessing/core/runtime/ObjcObject.cpp
    iblessing/core/runtime/ObjcRuntime.cpp
    iblessing/core/runtime/ObjcCategory.cpp
    iblessing/core/runtime/SimpleSimProcedure.cpp

    iblessing/core/structs/Foundation.cpp

    iblessing/core/symtab/StringTable.cpp
    iblessing/core/symtab/Symbol.cpp
    iblessing/core/symtab/SymbolTable.cpp

    iblessing/core/foundation/CoreFoundation.cpp

    # scanner
    iblessing/scanner/context/ScannerContext.cpp
    iblessing/scanner/context/ScannerContextManager.cpp
    iblessing/scanner/context/ScannerWorkDirManager.cpp

    iblessing/scanner/dispatcher/ScannerDispatcher.cpp

    iblessing/scanner/driver/ScannerDisassemblyDriver.cpp

    iblessing/scanner/Scanner.cpp
    iblessing/scanner/ObjcClassXrefScanner.cpp
    iblessing/scanner/ObjcMethodXrefScanner.cpp
    iblessing/scanner/SymbolXREFScanner.cpp
    iblessing/scanner/SymbolWrapperScanner.cpp
    iblessing/scanner/PredicateScanner.cpp
    iblessing/scanner/ObjcUnserializationScanner.cpp
    iblessing/scanner/assistance/state/ProgramState.cpp
    iblessing/scanner/assistance/state/ProgramStateManager.cpp

    iblessing/scanner/sub-scanner/objc-msg-xref/ObjcReflectionInfoManager.cpp

    # generator
    iblessing/generator/Generator.cpp
    iblessing/generator/GeneratorDispatcher.cpp
    iblessing/generator/IDAObjcMsgXREFGenerator.cpp
    iblessing/generator/IDASymbolWrapperNamingScriptGenerator.cpp
    iblessing/generator/ObjcMsgXREFServerGenerator.cpp
    iblessing/generator/ObjcMsgXREFStatisticsGenerator.cpp
    iblessing/generator/ObjcMsgXREFReportGenerator.cpp
    iblessing/generator/IDASymbolicScriptGenerator.cpp

    # tools
    iblessing/tools/otool/ObjDumpTool.cpp

    # serialization
    iblessing/serialization/ObjcMethodChainSerializationManager.cpp
    iblessing/serialization/SymbolWrapperSerializationManager.cpp
    iblessing/serialization/ObjcMethodCallSnapshotSerializationManager.cpp

    # domain
    iblessing/domain/ObjcMethodChain.cpp
    iblessing/domain/ObjcMethodCall.cpp

    # test
    iblessing/tests/Tester.cpp
    iblessing/tests/TestManager.cpp
    iblessing/tests/TestObjcMethodXrefs.cpp

    # v2
    iblessing/v2/iblessing/mach-o/mach-o.cpp
    iblessing/v2/iblessing/memory/memory.cpp
    iblessing/v2/iblessing/dyld/dyld.cpp
    iblessing/v2/iblessing/objc/objc.cpp
    iblessing/v2/iblessing/analyser/wrapper/AntiWrapper.cpp
    iblessing/v2/iblessing/analyser/wrapper/FunctionPrototype.cpp
    iblessing/v2/iblessing/analyser/wrapper/SimpleWrapperAnalyser.cpp
    iblessing/v2/iblessing/analyser/xref/FunctionXrefAnalyser.cpp
    

    # examples
    iblessing/v2/example/otool.cpp
    iblessing/v2/example/classdump.cpp
)

set(iblessing-core.SOURCE_LIST
    # utils
    iblessing/v2/iblessing/util/StringUtils.cpp

    # infra
    iblessing/infra/Object.cpp

    # mach-o
    iblessing/core/polyfill/mach-universal.cpp
    iblessing/core/disasm/ARM64Disasembler.cpp
    iblessing/core/disasm/ARM64Registers.cpp
    iblessing/core/disasm/ARM64ThreadState.cpp

    iblessing/core/dyld/DyldSimulator.cpp

    iblessing/core/memory/VirtualMemory.cpp
    iblessing/core/memory/VirtualMemoryV2.cpp

    iblessing/core/runtime/ARM64Runtime.cpp
    iblessing/core/runtime/ObjcBlock.cpp
    iblessing/core/runtime/ObjcClass.cpp
    iblessing/core/runtime/ObjcIvar.cpp
    iblessing/core/runtime/ObjcMethod.cpp
    iblessing/core/runtime/ObjcObject.cpp
    iblessing/core/runtime/ObjcRuntime.cpp
    iblessing/core/runtime/ObjcCategory.cpp
    iblessing/core/runtime/SimpleSimProcedure.cpp

    iblessing/core/structs/Foundation.cpp

    iblessing/core/symtab/StringTable.cpp
    iblessing/core/symtab/Symbol.cpp
    iblessing/core/symtab/SymbolTable.cpp

    iblessing/core/foundation/CoreFoundation.cpp

    # scanner
    iblessing/scanner/context/ScannerContext.cpp
    iblessing/scanner/context/ScannerContextManager.cpp
    iblessing/scanner/context/ScannerWorkDirManager.cpp
    iblessing/scanner/dispatcher/ScannerDispatcher.cpp
    iblessing/scanner/driver/ScannerDisassemblyDriver.cpp

    # domain
    iblessing/domain/ObjcMethodChain.cpp
    iblessing/domain/ObjcMethodCall.cpp

    # v2
    iblessing/v2/iblessing/mach-o/mach-o.cpp
    iblessing/v2/iblessing/memory/memory.cpp
    iblessing/v2/iblessing/dyld/dyld.cpp
    iblessing/v2/iblessing/objc/objc.cpp
    iblessing/v2/iblessing/analyser/wrapper/AntiWrapper.cpp
    iblessing/v2/iblessing/analyser/wrapper/FunctionPrototype.cpp
    iblessing/v2/iblessing/analyser/wrapper/SimpleWrapperAnalyser.cpp
    iblessing/v2/iblessing/analyser/xref/FunctionXrefAnalyser.cpp
)

if (iblessing.CSR_ENABLED)
    set(iblessing.SOURCE_LIST ${iblessing.SOURCE_LIST}
        iblessing/platform/macos/csrutil.cpp
    )
endif()

if (iblessing.COCOA_FOUNDATION_ENABLED) 
    set(iblessing.SOURCE_LIST ${iblessing.SOURCE_LIST}
        # cocoa scanner
        iblessing/scanner/AppInfoScanner.mm
    )

    target_link_libraries(iblessing "-framework Foundation")
endif()

target_include_directories(iblessing PRIVATE 
                           ${iblessing.SOURCE_INCLUDES}
                           ${iblessing.VENDOR_INCLUDES}
                           )

target_include_directories(iblessing-core PRIVATE 
                           ${iblessing.SOURCE_INCLUDES}
                           ${iblessing.VENDOR_INCLUDES}
                           )

target_sources(iblessing PRIVATE ${iblessing.SOURCE_LIST})
target_sources(iblessing-core PRIVATE ${iblessing-core.SOURCE_LIST})
