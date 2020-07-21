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
#include <map>
#include <string>

class Scanner {
public:
    Scanner(std::string identifier, std::string desc, bool isBinaryScanner = true):
        identifier(identifier),
        desc(desc),
        isBinaryScanner(isBinaryScanner)
    {}
    
    virtual ~Scanner() {};
    std::map<std::string, std::string> options;
    std::string inputPath;
    std::string outputPath;
    std::string fileName;
    std::string identifier;
    std::string desc;
    bool isBinaryScanner;
    
    void *dispatcher;
    
    virtual int start() = 0;
};

#endif /* Scanner_hpp */
