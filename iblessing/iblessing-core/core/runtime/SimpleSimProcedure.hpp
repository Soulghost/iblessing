//
//  SimpleSimProcedure.hpp
//  iblessing
//
//  Created by soulghost on 2021/1/22.
//  Copyright © 2021 soulghost. All rights reserved.
//

#ifndef SimpleSimProcedure_hpp
#define SimpleSimProcedure_hpp

#include <iblessing-core/infra/Object.hpp>
#include <vector>
#include <map>

NS_IB_BEGIN

struct SimProcedureMethod {
    std::string name;
    std::string prefix;
    std::string type;
    std::string value;
    std::string rawValue;
    std::vector<std::string> argTypes;
};

struct SimProcedureEvalResult {
    bool success;
    bool isObjc;
    std::string value;
    std::string rawValue;
    std::string prefix;
    std::vector<std::string> argTypes;
    
    static SimProcedureEvalResult failed() {
        SimProcedureEvalResult res;
        res.success = false;
        return res;
    }
};

class SimpleSimProcedure : Object {
public:
    static SimpleSimProcedure* getInstance();
    
    // className -> <methodName, [type, ]>
    std::map<std::string, std::map<std::string, SimProcedureMethod>> simMethods;
    
    int loadSimpleSimProcedure(std::string filePath);
    int load();
    SimProcedureEvalResult evalMethod(std::string className, std::string sel);
    
private:
    static SimpleSimProcedure* _instance;
};

NS_IB_END

#endif /* SimpleSimProcedure_hpp */
