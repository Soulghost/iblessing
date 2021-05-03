//
//  ObjcRelectionInfoManager.cpp
//  iblessing
//
//  Created by Soulghost on 2020/11/28.
//  Copyright © 2020 soulghost. All rights reserved.
//

#include "ObjcReflectionInfoManager.hpp"
#include "ObjcMethodCallSnapshotSerializationManager.hpp"
#include <iblessing-core/vendor/httplib/httplib.h>
#include <iblessing-core/vendor/rapidjson/document.h>
#include <iblessing-core/vendor/rapidjson/document.h>
#include <iblessing-core/vendor/rapidjson/writer.h>
#include <iblessing-core/vendor/rapidjson/stringbuffer.h>
#include <iblessing-core/v2/util/termcolor.h>
#include <iblessing-core/v2/util/StringUtils.h>

using namespace std;
using namespace iblessing;

static rapidjson::Value jsonString(string str, rapidjson::Document::AllocatorType &allocator) {
    if (StringUtils::countNonPrintablecharacters(str.c_str(), 1000) > 0) {
        str = "<<unprintable>>";
    }
    
    rapidjson::Value stringValue(rapidjson::kStringType);
    stringValue.SetString(str.c_str(), allocator);
    return stringValue;
}

bool ObjcReflectionInfoManager::syncToDisk() {
    return syncToDisk(reportPath);
}

bool ObjcReflectionInfoManager::syncToDisk(string path) {
    ofstream ss(path);
    if (!ss.is_open()) {
        cout << termcolor::red;
        cout << StringUtils::format("  [!] cannot open output file %s\n", path.c_str());
        cout << termcolor::reset << endl;
        return false;
    }
    ss.clear();
    
    rapidjson::Document d;
    d.SetObject();
    rapidjson::Document::AllocatorType &allocator = d.GetAllocator();
    rapidjson::Value reflectionCallsInfos(rapidjson::kObjectType);
    
    for (auto it = this->info.callMap.begin(); it != this->info.callMap.end(); it++) {
        string callName = it->first;
        vector<ObjcReflectionCall> &calls = it->second.first;
        ObjcReflectionCallStatistics &stat = it->second.second;
        
        rapidjson::Value reflectionCallsInfo(rapidjson::kObjectType);
        reflectionCallsInfo.AddMember("total", stat.totalCount, allocator);
        reflectionCallsInfo.AddMember("resolved", stat.resolvedCount, allocator);
        
        rapidjson::Value reflectionCalls(rapidjson::kArrayType);
        for (ObjcReflectionCall &call : calls) {
            rapidjson::Value reflectionCall(rapidjson::kObjectType);
            reflectionCall.AddMember("r", call.resolved, allocator);
            reflectionCall.AddMember("pc", jsonString(StringUtils::format("0x%llx", call.pc), allocator), allocator);
            reflectionCall.AddMember("caller", jsonString(call.callerDesc, allocator), allocator);
            rapidjson::Value reflectionCallArgs(rapidjson::kArrayType);
            for (ObjcReflectionCallArg &arg : call.args) {
                rapidjson::Value reflectionCallArg(rapidjson::kObjectType);
                reflectionCallArg.AddMember("type", jsonString(arg.type, allocator), allocator);
                reflectionCallArg.AddMember("value", jsonString(arg.value, allocator), allocator);
                reflectionCallArg.AddMember("resolved", arg.resolved, allocator);
                
                reflectionCallArgs.PushBack(reflectionCallArg, allocator);
            }
            reflectionCall.AddMember("args", reflectionCallArgs, allocator);
            reflectionCalls.PushBack(reflectionCall, allocator);
        }
        reflectionCallsInfo.AddMember("calls", reflectionCalls, allocator);
        reflectionCallsInfos.AddMember(jsonString(callName, allocator), reflectionCallsInfo, allocator);
    }
    
    d.AddMember("version", "0.1", allocator);
    d.AddMember("infos", reflectionCallsInfos, allocator);
    
    rapidjson::StringBuffer strbuf;
    rapidjson::Writer<rapidjson::StringBuffer> writer(strbuf);
    d.Accept(writer);
    ss << strbuf.GetString();
    ss.close();
    return true;
}
