//
//  ObjcMsgXREFReportGenerator.hpp
//  iblessing
//
//  Created by soulghost on 2020/8/10.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef ObjcMsgXREFReportGenerator_hpp
#define ObjcMsgXREFReportGenerator_hpp

#include "Generator.hpp"
#include "ObjcMethodChain.hpp"
#include <map>

NS_IB_BEGIN

class ObjcMsgXREFReportGenerator : public Generator {
public:
    ObjcMsgXREFReportGenerator(std::string name, std::string desc): Generator(name, desc) {}
    
    virtual ~ObjcMsgXREFReportGenerator() {};
    virtual int start();
    
private:
    std::map<std::string, MethodChain *> sel2chain;
    bool loadMethodChains();
};

NS_IB_END

#endif /* ObjcMsgXREFReportGenerator_hpp */
