//
//  IDASymbolWrapperNamingScriptGenerator.hpp
//  iblessing
//
//  Created by soulghost on 2020/7/30.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef IDASymbolWrapperNamingScriptGenerator_hpp
#define IDASymbolWrapperNamingScriptGenerator_hpp

#include "Generator.hpp"
#include "ObjcMethodChain.hpp"
#include <map>

NS_IB_BEGIN

class IDASymbolWrapperNamingScriptGenerator : public Generator {
public:
    IDASymbolWrapperNamingScriptGenerator(std::string name, std::string desc): Generator(name, desc) {}
    
    virtual ~IDASymbolWrapperNamingScriptGenerator() {};
    virtual int start();
};

NS_IB_END

#endif /* IDASymbolWrapperNamingScriptGenerator_hpp */
