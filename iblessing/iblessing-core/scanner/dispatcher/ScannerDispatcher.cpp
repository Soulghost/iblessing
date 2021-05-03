//
//  ScannerDispatcher.cpp
//  iblessing
//
//  Created by soulghost on 2020/6/28.
//  Copyright © 2020 soulghost. All rights reserved.
//

#include "ScannerDispatcher.hpp"

#include <iostream>
#include <fstream>
#include <cstdio>
#include <set>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <sys/unistd.h>
#include <sys/mman.h>

#include <iblessing-core/v2/util/termcolor.h>
#include <iblessing-core/v2/util/StringUtils.h>

#include "ScannerContextManager.hpp"
//#include "PredicateScanner.hpp"
//#include "ObjcMethodXrefScanner.hpp"
//#include "ObjcClassXrefScanner.hpp"
//#include "SymbolWrapperScanner.hpp"
//#include "SymbolXREFScanner.hpp"
//#include "ObjcUnserializationScanner.hpp"

#include <iblessing-core/v2/mach-o/mach-o.hpp>
#include <iblessing-core/v2/memory/memory.hpp>
#include <iblessing-core/v2/objc/objc.hpp>
#include <iblessing-core/v2/dyld/dyld.hpp>

using namespace std;
using namespace iblessing;

ScannerDispatcher* ScannerDispatcher::_instance = nullptr;
ScannerDispatcher* ScannerDispatcher::getInstance() {
    if (ScannerDispatcher::_instance == nullptr) {
        ScannerDispatcher::_instance = new ScannerDispatcher();
    }
    return ScannerDispatcher::_instance;
}

static bool fexists(string filename) {
    std::ifstream ifile(filename);
    return (bool)ifile;
}

ScannerDispatcher::ScannerDispatcher() {
//#ifdef IB_COCOA_FOUNDATION_ENABLED
//    this->registerScanner("app-info", []() {
//        return new AppInfoScanner("app-info", "extract app infos");
//    });
//#endif
//

//
//    this->registerScanner("predicate", []() {
//        return new PredicateScanner("predicate", "scan for NSPredicate xrefs and sql injection surfaces");
//    });
//
//    this->registerScanner("objc-class-xref", []() {
//        return new ObjcClassXrefScanner("objc-class-xref", "scan for class xrefs");
//    });
//

//
//
//    this->registerScanner("objc-insecure-unserialization", []() {
//        return new ObjcUnserializationScanner("objc-insecure-unserialization", "objc insecure unserialization scanner");
//    });
}

vector<Scanner *> ScannerDispatcher::allScanners() {
    vector<Scanner *> scanners;
    for (auto it = scannerMap.begin(); it != scannerMap.end(); it++) {
        scanners.push_back(it->second());
    }
    return scanners;
}

void ScannerDispatcher::registerScanner(string scannerId, ScannerProvider provider) {
    scannerMap[scannerId] = provider;
}

int ScannerDispatcher::start(std::string scannerId, std::map<std::string, std::string> options, std::string inputPath, std::string outputPath) {
    Scanner *s = prepareForScanner(scannerId, options, inputPath, outputPath);
    if (!s) {
        return 1;
    }
    
    s->jobs = jobs;
    int ret = s->start();
    delete s;
    return ret;
}


Scanner* ScannerDispatcher::prepareForScanner(std::string scannerId, std::map<std::string, std::string> options, std::string inputPath, std::string outputPath, shared_ptr<ScannerDisassemblyDriver> disasmDriver) {
    // input validate
    if (!fexists(inputPath)) {
        cout << termcolor::red << "[-] ScannerDispatcher Error: input file " << inputPath << " not exist";
        cout << termcolor::reset << endl;
    }
    
    // scanner validate
    // FIXME: hardcode
    if (scannerMap.find(scannerId) == scannerMap.end()) {
        cout << termcolor::red << "[-] ScannerDispatcher Error: cannot find scanner " << scannerId;
        cout << termcolor::reset << endl;
        return nullptr;
    }
    
    // here we go
    Scanner *s = scannerMap[scannerId]();
    
    // open file
    if (s->isBinaryScanner) {
        shared_ptr<MachO> macho = MachO::createFromFile(inputPath);
        assert(macho->loadSync() == IB_SUCCESS);
        s->macho = macho;
//
//        shared_ptr<Memory> memory = Memory::createFromMachO(macho);
//        assert(memory->loadSync() == IB_SUCCESS);
        
//        s->macho = macho;
//        s->memory = memory;
        
//        // load binary context
//        ScannerContextManager *contextMgr = ScannerContextManager::globalManager();
//        ScannerContext *context = contextMgr->getContextByBinaryPath(inputPath);
//        if (!context) {
//            cout << termcolor::red << "[-] ScannerDispatcher Error: cannot load binary context for file " << inputPath;
//            cout << termcolor::reset << endl;
//            return nullptr;
//        }
        
        // load driver
        if (disasmDriver) {
            s->disasmDriver = disasmDriver;
        }
    }
    
    // bind context
    s->dispatcher = this;
    
    // bind options
    s->inputPath = inputPath;
    vector<string> pathComponents = StringUtils::split(inputPath, '/');
    s->fileName = pathComponents[pathComponents.size() - 1];
    s->outputPath = outputPath;
    s->options = options;
    return s;
}
