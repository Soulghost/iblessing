//
//  IDASymbolicScriptGenerator.hpp
//  iblessing
//
//  Created by Soulghost on 2020/8/15.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef IDASymbolicScriptGenerator_hpp
#define IDASymbolicScriptGenerator_hpp

#include "Generator.hpp"

NS_IB_BEGIN

class IDASymbolicScriptGenerator : public Generator {
public:
    IDASymbolicScriptGenerator(std::string name, std::string desc): Generator(name, desc) {}
    
    virtual ~IDASymbolicScriptGenerator() {};
    virtual int start();
};

NS_IB_END

#endif /* IDASymbolicScriptGenerator_hpp */
