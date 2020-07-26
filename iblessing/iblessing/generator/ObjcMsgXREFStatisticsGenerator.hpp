//
//  ObjcMsgXREFStatisticsGenerator.hpp
//  iblessing
//
//  Created by soulghost on 2020/7/25.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef ObjcMsgXREFStatisticsGenerator_hpp
#define ObjcMsgXREFStatisticsGenerator_hpp

#include "Generator.hpp"
#include "ObjcMethodChain.hpp"
#include <map>
#include <string>

NS_IB_BEGIN

class ObjcMsgXREFStatisticsGenerator : public Generator {
public:
    ObjcMsgXREFStatisticsGenerator(std::string name, std::string desc): Generator(name, desc) {}
    
    virtual ~ObjcMsgXREFStatisticsGenerator() {};
    virtual int start();
    
private:
    std::map<std::string, MethodChain *> sel2chain;
    std::map<std::string, MethodChain *> loadMethodChains(std::string path);
};

NS_IB_END

#endif /* ObjcMsgXREFStatisticsGenerator_hpp */
