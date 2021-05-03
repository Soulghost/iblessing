//
//  Generator.hpp
//  iblessing
//
//  Created by soulghost on 2020/7/19.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef Generator_hpp
#define Generator_hpp

#include <iblessing-core/infra/Object.hpp>
#include <map>
#include <string>

class Generator {
public:
    Generator(std::string identifier, std::string desc):
        identifier(identifier),
        desc(desc)
    {}
    
    virtual ~Generator() {};
    std::map<std::string, std::string> options;
    std::string inputPath;
    std::string outputPath;
    std::string fileName;
    std::string identifier;
    std::string desc;
    
    virtual int start() = 0;
};

#endif /* Generator_hpp */
