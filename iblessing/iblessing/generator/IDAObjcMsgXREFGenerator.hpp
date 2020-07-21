//
//  IDAObjcMsgXREFGenerator.hpp
//  iblessing
//
//  Created by soulghost on 2020/7/19.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef IDAObjcMsgXREFGenerator_hpp
#define IDAObjcMsgXREFGenerator_hpp

#include "Generator.hpp"
#include "ObjcMethodChain.hpp"
#include <map>

NS_IB_BEGIN

class IDAObjMsgXREFGenerator : public Generator {
public:
    IDAObjMsgXREFGenerator(std::string name, std::string desc): Generator(name, desc) {}
    
    virtual ~IDAObjMsgXREFGenerator() {};
    virtual int start();
    
private:
    std::map<std::string, MethodChain *> sel2chain;
    bool loadMethodChains();
};

NS_IB_END

#endif /* IDAObjcMsgXREFGenerator_hpp */
