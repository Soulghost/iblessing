//
//  ObjcReflectionInfo.hpp
//  iblessing
//
//  Created by Soulghost on 2020/11/28.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef ObjcReflectionInfo_hpp
#define ObjcReflectionInfo_hpp

#include <iblessing-core/infra/Object.hpp>
#include <vector>
#include <map>
#include <set>

NS_IB_BEGIN

struct ObjcReflectionCallArg {
    std::string type;
    std::string value;
    bool resolved;
    
    ObjcReflectionCallArg(std::string type, std::string value, bool resolved) {
        this->type = type;
        this->value = value;
        this->resolved = resolved;
    }
};

struct ObjcReflectionCall {
    uint64_t pc;
    std::string callerDesc;
    std::vector<ObjcReflectionCallArg> args;
    bool resolved;
};

struct ObjcReflectionCallStatistics {
    uint64_t resolvedCount;
    uint64_t totalCount;
};

class ObjcReflectionInfo {
public:
    std::map<std::string, std::pair<std::vector<ObjcReflectionCall>, ObjcReflectionCallStatistics>> callMap;
    std::set<uint64_t> visitedPc;
    
    void addCall(std::string name, ObjcReflectionCall &call) {
        if (visitedPc.find(call.pc) != visitedPc.end()) {
            return;
        }
        
        std::pair<std::vector<ObjcReflectionCall>, ObjcReflectionCallStatistics> &callsInfo = callMap[name];
        callsInfo.first.push_back(call);
        callsInfo.second.totalCount++;
        if (call.resolved) {
            callsInfo.second.resolvedCount++;
        }
    }
};

NS_IB_END

#endif /* ObjcReflectionInfo_hpp */
