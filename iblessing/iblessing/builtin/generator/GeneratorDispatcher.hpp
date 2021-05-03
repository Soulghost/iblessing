//
//  GeneratorDispatcher.hpp
//  iblessing
//
//  Created by soulghost on 2020/7/19.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef GeneratorDispatcher_hpp
#define GeneratorDispatcher_hpp

#include <map>
#include <vector>
#include <string>
#include "Generator.hpp"
#include <functional>

NS_IB_BEGIN;

typedef std::function<Generator* (void)> GeneratorProvider;

class GeneratorDispatcher {
public:
    GeneratorDispatcher();
    void registerGenerator(std::string generatorId, GeneratorProvider provider);
    int start(std::string generatorId, std::map<std::string, std::string> options, std::string inputPath, std::string outputPath);
    Generator* prepareForGenerator(std::string scannerId, std::map<std::string, std::string> options, std::string inputPath, std::string outputPath);
    std::vector<Generator *> allGenerators();
    
private:
    std::map<std::string, GeneratorProvider> generatorMap;
};

NS_IB_END;

#endif /* GeneratorDispatcher_hpp */
