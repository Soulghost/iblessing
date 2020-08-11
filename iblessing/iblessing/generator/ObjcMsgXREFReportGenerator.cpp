//
//  ObjcMsgXREFReportGenerator.cpp
//  iblessing
//
//  Created by soulghost on 2020/8/10.
//  Copyright © 2020 soulghost. All rights reserved.
//

#include "ObjcMsgXREFReportGenerator.hpp"
#include "ObjcMethodChainSerializationManager.hpp"
#include <fstream>
#include "../vendor/httplib/httplib.h"
#include "../vendor/rapidjson/document.h"
#include "../vendor/rapidjson/document.h"
#include "../vendor/rapidjson/writer.h"
#include "../vendor/rapidjson/stringbuffer.h"
#include "termcolor.h"

using namespace std;
using namespace httplib;
using namespace iblessing;

static rapidjson::Value jsonString(const char *str, rapidjson::Document::AllocatorType &allocator) {
    rapidjson::Value stringValue(rapidjson::kStringType);
    stringValue.SetString(str, allocator);
    return stringValue;
}

static rapidjson::Value produceMethodRefs(set<pair<MethodChain *, uint64_t>> &methodRefs, rapidjson::Document::AllocatorType &allocator) {
    rapidjson::Value methodRefsObject(rapidjson::kArrayType);
    for (pair<MethodChain *, uint64_t> methodRef : methodRefs) {
        rapidjson::Value methodRefObject(rapidjson::kObjectType);
        MethodChain *chain = methodRef.first;
        if (!chain) {
            continue;
        }
        uint64_t callerAddr = methodRef.second;
        methodRefObject.AddMember("id", chain->chainId, allocator);
        methodRefObject.AddMember("addr", jsonString(StringUtils::format("0x%llx", callerAddr).c_str(), allocator), allocator);
        methodRefsObject.PushBack(methodRefObject, allocator);
    }
    return methodRefsObject;
}

int ObjcMsgXREFReportGenerator::start() {
    cout << "[*] start ObjcMsgXREFReportGenerator" << endl;
    string reportPath = StringUtils::path_join(outputPath, fileName + "_objc_msg_xrefs.iblessing.json");
    ofstream ss(reportPath);
    if (!ss.is_open()) {
        cout << termcolor::red;
        cout << StringUtils::format("  [!] cannot open output file %s\n", reportPath.c_str());
        cout << termcolor::reset << endl;
        return 1;
    }
    ss.clear();
    
    bool filterUnprintable = true;
    if (options.find("unprintable") != options.end()) {
        string unprintable = options["unprintable"];
        int opt = atoi(unprintable.c_str());
        filterUnprintable = opt >= 1;
    }
    
    if (!loadMethodChains()) {
        cout << termcolor::red;
        cout << StringUtils::format("  [!] failed to parse %s\n", inputPath.c_str());
        cout << termcolor::reset << endl;
        return 1;
    }
    
    rapidjson::Document d;
    d.SetObject();
    rapidjson::Document::AllocatorType &allocator = d.GetAllocator();
    
    rapidjson::Value allMethodsObject(rapidjson::kArrayType);
    
    vector<pair<string, MethodChain *>> methods(sel2chain.begin(), sel2chain.end());
    std::sort(methods.begin(), methods.end(), [](pair<std::string, MethodChain *> &a, pair<std::string, MethodChain *> &b) {
        return a.second->chainId < b.second->chainId;
    });
    
    uint64_t filterCount = 0;
    for (auto it = methods.begin(); it != methods.end(); it++) {
        const char *cmd = it->first.c_str();
        MethodChain *chain = it->second;
        rapidjson::Value methodObject(rapidjson::kObjectType);
        methodObject.AddMember("id", chain->chainId, allocator);
        if (filterUnprintable && StringUtils::countNonPrintablecharacters(cmd, 1000) > 0) {
            cmd = "<<unprintable>>";
            filterCount++;
        }
        methodObject.AddMember("sel", jsonString(cmd, allocator), allocator);
        methodObject.AddMember("imp", jsonString(StringUtils::format("0x%llx", chain->impAddr).c_str(), allocator), allocator);
        methodObject.AddMember("preMethods", produceMethodRefs(chain->prevMethods, allocator), allocator);
        methodObject.AddMember("postMethods", produceMethodRefs(chain->nextMethods, allocator), allocator);
        allMethodsObject.PushBack(methodObject, allocator);
    }
    
    d.AddMember("version", jsonString("0.2", allocator), allocator);
    d.AddMember("methods", allMethodsObject, allocator);
    
    rapidjson::StringBuffer strbuf;
    rapidjson::Writer<rapidjson::StringBuffer> writer(strbuf);
    d.Accept(writer);
    ss << strbuf.GetString();
    ss.close();
    if (filterCount > 0) {
        cout << "  [*] filter ";
        cout << termcolor::green << filterCount << termcolor::reset;
        cout << " unprintable method expr(s)" << endl;
    }
    printf("  [*] saved to %s\n", reportPath.c_str());
    return 0;
}

bool ObjcMsgXREFReportGenerator::loadMethodChains() {
    sel2chain = ObjcMethodChainSerializationManager::loadMethodChain(inputPath);
    if (sel2chain.empty()) {
        return false;
    }
    
    printf("\t[+] load storage from disk succeeded!\n");
    return true;
}
