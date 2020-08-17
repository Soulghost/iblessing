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

#include "termcolor.h"
#include "StringUtils.h"

#include "ScannerContextManager.hpp"
#include "PredicateScanner.hpp"
#include "ObjcMethodXrefScanner.hpp"
#include "ObjcClassXrefScanner.hpp"
#include "SymbolWrapperScanner.hpp"
#include "SymbolXREFScanner.hpp"
#include "ObjcUnserializationScanner.hpp"

#ifdef IB_COCOA_FOUNDATION_ENABLED
#include "AppInfoScanner.hpp"
#endif

using namespace std;
using namespace iblessing;

static bool fexists(string filename) {
    std::ifstream ifile(filename);
    return (bool)ifile;
}

ScannerDispatcher::ScannerDispatcher() {
#ifdef IB_COCOA_FOUNDATION_ENABLED
    this->registerScanner("app-info", []() {
        return new AppInfoScanner("app-info", "extract app infos");
    });
#endif
    
    this->registerScanner("objc-msg-xref", []() {
        return new ObjcMethodXrefScanner("objc-msg-xref", "generate objc_msgSend xrefs record");
    });
    
    this->registerScanner("predicate", []() {
        return new PredicateScanner("predicate", "scan for NSPredicate xrefs and sql injection surfaces");
    });
    
    this->registerScanner("objc-class-xref", []() {
        return new ObjcClassXrefScanner("objc-class-xref", "scan for class xrefs");
    });
    
    this->registerScanner("symbol-wrapper", []() {
        return new SymbolWrapperScanner("symbol-wrapper", "detect symbol wrappers");
    });
    
    this->registerScanner("symbol-xref", []() {
        return new SymbolXREFScanner("symbol-xref", "symbol xref scanner");
    });
    
    this->registerScanner("objc-insecure-unserialization", []() {
        return new ObjcUnserializationScanner("objc-insecure-unserialization", "objc insecure unserialization scanner");
    });
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


Scanner* ScannerDispatcher::prepareForScanner(std::string scannerId, std::map<std::string, std::string> options, std::string inputPath, std::string outputPath, ScannerDisassemblyDriver *driver) {
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
        // load binary context
        ScannerContextManager *contextMgr = ScannerContextManager::globalManager();
        ScannerContext *context = contextMgr->getContextByBinaryPath(inputPath);
        if (!context) {
            cout << termcolor::red << "[-] ScannerDispatcher Error: cannot load binary context for file " << inputPath;
            cout << termcolor::reset << endl;
            return nullptr;
        }
        
        // load driver
        if (driver) {
            s->driver = driver;
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
