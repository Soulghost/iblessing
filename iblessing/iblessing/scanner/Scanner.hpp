//
//  Scanner.hpp
//  iblessing
//
//  Created by soulghost on 2020/6/28.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef Scanner_hpp
#define Scanner_hpp

#include "Object.hpp"
#include "ScannerDisassemblyDriver.hpp"
#include <map>
#include <string>

NS_IB_BEGIN

class Scanner {
public:
    Scanner(std::string identifier, std::string desc, bool isBinaryScanner = true):
        identifier(identifier),
        desc(desc),
        isBinaryScanner(isBinaryScanner),
        driver(nullptr)
    {}
    
    virtual ~Scanner() {};
    std::map<std::string, std::string> options;
    std::string inputPath;
    std::string outputPath;
    std::string fileName;
    std::string identifier;
    std::string desc;
    int jobs;
    bool isBinaryScanner;
    
    // FIXME: buggy design pattern
    void *dispatcher;
    ScannerDisassemblyDriver *driver;
    
    virtual int start() = 0;
};

NS_IB_END

#endif /* Scanner_hpp */
