//
//  SimpleSimProcedure.cpp
//  iblessing
//
//  Created by soulghost on 2021/1/22.
//  Copyright © 2021 soulghost. All rights reserved.
//

#include "SimpleSimProcedure.hpp"
#include <fstream>
#include <iblessing-core/v2/util/termcolor.h>
#include <iblessing-core/v2/util/StringUtils.h>
#include <iblessing-core/vendor/rapidjson/document.h>
#include <iblessing-core/vendor/rapidjson/document.h>
#include <iblessing-core/vendor/rapidjson/writer.h>
#include <iblessing-core/vendor/rapidjson/stringbuffer.h>
#include <iblessing-core/vendor/rapidjson/istreamwrapper.h>

using namespace std;
using namespace iblessing;
using namespace rapidjson;

SimpleSimProcedure* SimpleSimProcedure::_instance = nullptr;

SimpleSimProcedure* SimpleSimProcedure::getInstance() {
    if (!SimpleSimProcedure::_instance) {
        SimpleSimProcedure::_instance = new SimpleSimProcedure();
    }
    return SimpleSimProcedure::_instance;
}

int SimpleSimProcedure::load() {
    return loadSimpleSimProcedure("./iblessing-simple-simprocedure.json");
}

int SimpleSimProcedure::loadSimpleSimProcedure(string filePath) {
    ifstream ss(filePath);
    if (!ss.is_open()) {
//        cout << termcolor::red << StringUtils::format("Error: cannot load simprocedure file from %s", filePath.c_str());
//        cout << termcolor::reset << endl;
        return 1;
    }
    
    IStreamWrapper isw{ss};
    Document doc;
    doc.ParseStream(isw);
    
    if (doc.HasParseError()) {
        cout << termcolor::red << StringUtils::format("Error: cannot parse json file from %s", filePath.c_str());
        cout << termcolor::reset << endl;
        return 1;
    }
    
    if (doc.HasMember("t")) {
        string type = doc["t"].GetString();
        if (type != "simprocedure") {
            cout << termcolor::red << StringUtils::format("Error: the format of the json file is not simprocedure, it is %s", type.c_str());
            cout << termcolor::reset << endl;
            return 1;
        }
    }
    
    string version = "?";
    if (doc.HasMember("v")) {
        version = doc["v"].GetString();
    }
    
    printf("[+] Load SimProcedure JSON with version %s\n", version.c_str());
    simMethods.clear();
    if (!doc.HasMember("cls")) {
        cout << termcolor::red << StringUtils::format("Error: invalid simprocedure, cls not found");
        cout << termcolor::reset << endl;
        return 1;
    }
    
    if (!doc["cls"].IsObject()) {
        cout << termcolor::red << StringUtils::format("Error: cls is not a object");
        cout << termcolor::reset << endl;
        return 1;
    }
    
    for (auto it = doc["cls"].MemberBegin(); it != doc["cls"].MemberEnd(); it++) {
        assert(it->name.IsString());
        assert(it->value.IsObject());
        
        string className = it->name.GetString();
        auto methodsObj = it->value.GetObject();
        for (auto mit = methodsObj.MemberBegin(); mit != methodsObj.MemberEnd(); mit++) {
            assert(mit->name.IsString());
            assert(mit->value.IsObject());
            
            string methodName = mit->name.GetString();
            auto methodObj = mit->value.GetObject();
            assert(methodObj.HasMember("t") && methodObj["t"].IsString());
            assert(methodObj.HasMember("r") && methodObj["r"].IsString());
            assert(methodObj.HasMember("a") && methodObj["a"].IsArray());
            
            string returnType = methodObj["t"].GetString();
            string returnTypeName = methodObj["r"].GetString();
            if (returnType == "cm" || returnType == "im") {
                SimProcedureMethod m;
                m.name = methodName;
                m.type = returnType;
                m.prefix = (returnType == "cm" ? "+" : "-");
                m.value = returnTypeName.substr(0, returnTypeName.length() - 1);
                m.rawValue = returnTypeName;
                for (auto it = methodObj["a"].Begin(); it != methodObj["a"].End(); it++) {
                    m.argTypes.push_back(it->GetString());
                }
                simMethods[className][methodName] = m;
            }
        }
    }
    return 0;
}

SimProcedureEvalResult SimpleSimProcedure::evalMethod(string className, string sel) {
    if (simMethods.find(className) == simMethods.end()) {
        return SimProcedureEvalResult::failed();
    }
    
    auto &methods = simMethods[className];
    if (methods.find(sel) == methods.end()) {
        return SimProcedureEvalResult::failed();
    }
    
    SimProcedureEvalResult res;
    SimProcedureMethod &m = methods[sel];
    res.isObjc = m.type == "cm" || m.type == "im";
    res.value = m.value;
    res.rawValue = m.rawValue;
    res.argTypes = m.argTypes;
    res.prefix = m.prefix;
    res.success = true;
    return res;
}
