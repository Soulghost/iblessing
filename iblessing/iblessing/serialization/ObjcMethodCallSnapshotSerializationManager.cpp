//
//  ObjcMethodCallSnapshotSerializationManager.cpp
//  iblessing
//
//  Created by Soulghost on 2020/10/24.
//  Copyright © 2020 soulghost. All rights reserved.
//

#include "ObjcMethodCallSnapshotSerializationManager.hpp"
#include "../vendor/httplib/httplib.h"
#include "../vendor/rapidjson/document.h"
#include "../vendor/rapidjson/document.h"
#include "../vendor/rapidjson/writer.h"
#include "../vendor/rapidjson/stringbuffer.h"
#include "termcolor.h"
#include "ObjcClass.hpp"
#include "StringUtils.h"

using namespace std;

static rapidjson::Value jsonString(string str, rapidjson::Document::AllocatorType &allocator) {
    if (StringUtils::countNonPrintablecharacters(str.c_str(), 1000) > 0) {
        str = "<<unprintable>>";
    }
    
    rapidjson::Value stringValue(rapidjson::kStringType);
    stringValue.SetString(str.c_str(), allocator);
    return stringValue;
}

using namespace std;
using namespace iblessing;

bool ObjcMethodCallSnapshotSerializationManager::storeAsJSON(string path, map<uint64_t, set<ObjcMethodCall>> callSnapshots) {
    ofstream ss(path);
    if (!ss.is_open()) {
        cout << termcolor::red;
        cout << StringUtils::format("  [!] cannot open output file %s\n", path.c_str());
        cout << termcolor::reset << endl;
        return false;
    }
    ss.clear();
    
    vector<pair<uint64_t, set<ObjcMethodCall>>> snapshotPairs(callSnapshots.begin(), callSnapshots.end());
    std::sort(snapshotPairs.begin(), snapshotPairs.end(), [](pair<uint64_t, set<ObjcMethodCall>> &a, pair<uint64_t, set<ObjcMethodCall>> &b) {
        return a.first < b.first;
    });
    
    rapidjson::Document d;
    d.SetObject();
    rapidjson::Document::AllocatorType &allocator = d.GetAllocator();
    rapidjson::Value allMethodsCallSnapshots(rapidjson::kArrayType);
    for (pair<uint64_t, set<ObjcMethodCall>> &snapshotPair : snapshotPairs) {
        uint64_t chainId = snapshotPair.first;
        set<ObjcMethodCall> &calls = snapshotPair.second;
        if (calls.size() == 0) {
            continue;
        }
        
        rapidjson::Value chainObject(rapidjson::kObjectType);
        chainObject.AddMember("id", chainId, allocator);
        
        ObjcMethodCall anyCall = *next(calls.begin(), 0);
        chainObject.AddMember("cls", jsonString(anyCall.method->classInfo->className, allocator), allocator);
        chainObject.AddMember("clsa", anyCall.method->classInfo->address, allocator);
        chainObject.AddMember("m", jsonString(anyCall.method->desc(), allocator), allocator);
        chainObject.AddMember("ma", anyCall.method->imp, allocator);
        
        rapidjson::Value callObjects(rapidjson::kArrayType);
        for (ObjcMethodCall call : calls) {
            rapidjson::Value argsObject(rapidjson::kArrayType);
            for (ObjcMethodCallArg arg : call.args) {
                rapidjson::Value argObject(rapidjson::kObjectType);
                argObject.AddMember("e", jsonString(arg.typeEncoding, allocator), allocator);
                argObject.AddMember("t", jsonString(arg.typeName, allocator), allocator);
                argObject.AddMember("v", jsonString(arg.value, allocator), allocator);
                argObject.AddMember("r", arg.resolved, allocator);
                argObject.AddMember("p", arg.isPrimaryType, allocator);
                argsObject.PushBack(argObject, allocator);
            }
            callObjects.PushBack(argsObject, allocator);
        }
        chainObject.AddMember("calls", callObjects, allocator);
        allMethodsCallSnapshots.PushBack(chainObject, allocator);
    }
    d.AddMember("snapshots", allMethodsCallSnapshots, allocator);
    d.AddMember("version", jsonString("0.1", allocator), allocator);

    rapidjson::StringBuffer strbuf;
    rapidjson::Writer<rapidjson::StringBuffer> writer(strbuf);
    d.Accept(writer);
    ss << strbuf.GetString();
    ss.close();
    return true;
}
