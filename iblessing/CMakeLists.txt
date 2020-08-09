cmake_minimum_required(VERSION 3.5)

project(iblessing VERSION 1.0)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)

# main executable
add_executable(iblessing iblessing/main.cpp)

# vendor libs
target_link_libraries(iblessing ${CMAKE_SOURCE_DIR}/../submodules/capstone/libcapstone.a)
target_link_libraries(iblessing ${CMAKE_SOURCE_DIR}/../submodules/unicorn/libunicorn.a)

set(iblessing.VENDOR_INCLUDES
    ${CMAKE_SOURCE_DIR}/../submodules/capstone/include
    ${CMAKE_SOURCE_DIR}/../submodules/unicorn/include
)

set(iblessing.SOURCE_INCLUDES
    ${CMAKE_SOURCE_DIR}

    # vendors
    iblessing/vendor/argparse
    iblessing/vendor/termcolor
    iblessing/vendor/httplib
    iblessing/vendor/rapidjson

    # utils
    iblessing/util

    # infra
    iblessing/infra

    # common
    iblessing/common
    iblessing/common/macro

    # mach-o
    iblessing/mach-o/disasm
    iblessing/mach-o/dyld
    iblessing/mach-o/memory
    iblessing/mach-o/runtime
    iblessing/mach-o/structs
    iblessing/mach-o/symtab

    # scanner
    iblessing/scanner
    iblessing/scanner/common
    iblessing/scanner/context
    iblessing/scanner/dispatcher
    iblessing/scanner/driver

    # generator
    iblessing/generator

    # serialization
    iblessing/serialization

    # analyzer
    iblessing/analyzer
    iblessing/analyzer/deobfuscator

    # domain
    iblessing/domain

    # platform-specific
    iblessing/platform/macos
)

set(iblessing.SOURCE_LIST
    # utils
    iblessing/util/StringUtils.cpp

    # infra
    iblessing/infra/Object.cpp

    # mach-o
    iblessing/mach-o/disasm/ARM64Disasembler.cpp
    iblessing/mach-o/disasm/ARM64Registers.cpp
    iblessing/mach-o/disasm/ARM64ThreadState.cpp

    iblessing/mach-o/dyld/DyldSimulator.cpp

    iblessing/mach-o/memory/VirtualMemory.cpp
    iblessing/mach-o/memory/VirtualMemoryV2.cpp

    iblessing/mach-o/runtime/ARM64Runtime.cpp
    iblessing/mach-o/runtime/ObjcBlock.cpp
    iblessing/mach-o/runtime/ObjcClass.cpp
    iblessing/mach-o/runtime/ObjcIvar.cpp
    iblessing/mach-o/runtime/ObjcMethod.cpp
    iblessing/mach-o/runtime/ObjcObject.cpp
    iblessing/mach-o/runtime/ObjcRuntime.cpp

    iblessing/mach-o/structs/Foundation.cpp

    iblessing/mach-o/symtab/StringTable.cpp
    iblessing/mach-o/symtab/Symbol.cpp
    iblessing/mach-o/symtab/SymbolTable.cpp

    # scanner
    iblessing/scanner/context/ScannerContext.cpp
    iblessing/scanner/context/ScannerContextManager.cpp

    iblessing/scanner/dispatcher/ScannerDispatcher.cpp

    iblessing/scanner/driver/ScannerDisassemblyDriver.cpp

    iblessing/scanner/Scanner.cpp
    iblessing/scanner/ObjcClassXrefScanner.cpp
    iblessing/scanner/ObjcMethodXrefScanner.cpp
    iblessing/scanner/SymbolXREFScanner.cpp
    iblessing/scanner/SymbolWrapperScanner.cpp
    iblessing/scanner/PredicateScanner.cpp

    # generator
    iblessing/generator/Generator.cpp
    iblessing/generator/GeneratorDispatcher.cpp
    iblessing/generator/IDAObjcMsgXREFGenerator.cpp
    iblessing/generator/IDASymbolWrapperNamingScriptGenerator.cpp
    iblessing/generator/ObjcMsgXREFServerGenerator.cpp
    iblessing/generator/ObjcMsgXREFStatisticsGenerator.cpp

    # serialization
    iblessing/serialization/ObjcMethodChainSerializationManager.cpp
    iblessing/serialization/SymbolWrapperSerializationManager.cpp

    # analyzer
    iblessing/analyzer/deobfuscator/AntiWrapper.cpp
    iblessing/analyzer/deobfuscator/FunctionPrototype.cpp

    # domain
    iblessing/domain/ObjcMethodChain.cpp

    # platform-specific
    iblessing/platform/macos/csrutil.cpp
)

target_include_directories(iblessing PRIVATE 
                           ${iblessing.SOURCE_INCLUDES}
                           ${iblessing.VENDOR_INCLUDES}
                           )
target_sources(iblessing PRIVATE ${iblessing.SOURCE_LIST})