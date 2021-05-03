//
//  ObjcMsgXREFServerGenerator.hpp
//  iblessing
//
//  Created by soulghost on 2020/7/22.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef ObjcMsgXREFServerGenerator_hpp
#define ObjcMsgXREFServerGenerator_hpp

#include "Generator.hpp"
#include "ObjcMethodChain.hpp"
#include <map>

NS_IB_BEGIN

class ObjcMsgXREFServerGenerator : public Generator {
public:
    ObjcMsgXREFServerGenerator(std::string name, std::string desc): Generator(name, desc) {}
    
    virtual ~ObjcMsgXREFServerGenerator() {};
    virtual int start();
    
private:
    std::map<std::string, MethodChain *> sel2chain;
    bool loadMethodChains();
};

NS_IB_END

#endif /* ObjcMsgXREFServerGenerator_hpp */
