//
//  IDAObjcMsgXREFGenerator.cpp
//  iblessing
//
//  Created by soulghost on 2020/7/19.
//  Copyright © 2020 soulghost. All rights reserved.
//

#include "IDAObjcMsgXREFGenerator.hpp"
#include <fstream>
#include "../serialization/ObjcMethodChainSerializationManager.hpp"
#include "../vendor/httplib/httplib.h"
#include "../vendor/rapidjson/document.h"
#include "../vendor/rapidjson/document.h"
#include "../vendor/rapidjson/writer.h"
#include "../vendor/rapidjson/stringbuffer.h"
#include "termcolor.h"

using namespace std;
using namespace iblessing;

static void findAllPath(MethodChain *current, vector<pair<MethodChain *, uint64_t>> result, vector<vector<pair<MethodChain *, uint64_t>>> &results);
static void findAllPathNext(MethodChain *current, vector<pair<MethodChain *, uint64_t>> result, vector<vector<pair<MethodChain *, uint64_t>>> &results, int maxDepth);

int IDAObjMsgXREFGenerator::start() {
    cout << "[*] start IDAObjMsgXREFGenerator" << endl;
    
    string scriptsPath = StringUtils::path_join(outputPath, fileName + "_ida_objc_msg_xrefs.iblessing.py");
    ofstream ss(scriptsPath);
    ss.clear();
    
    if (!loadMethodChains()) {
        cout << termcolor::red;
        cout << StringUtils::format("  [!] failed to parse %s\n", inputPath.c_str());
        cout << termcolor::reset << endl;
        return 1;
    }
    
    cout << "  [*] Generating XREF Scripts ..." << endl;
    ss << "def add_objc_xrefs():";
    for (auto it = sel2chain.begin(); it != sel2chain.end(); it++) {
        MethodChain *current = it->second;
        if (current->impAddr == 0) {
            continue;
        }
        for (auto it = current->prevMethods.begin(); it != current->prevMethods.end(); it++) {
            MethodChain *prev = it->first;
            uint64_t callerAddr = it->second;
            if (callerAddr == 0) {
                callerAddr = prev->impAddr;
            }
            // add xref(preCallerAddr, cur->impAddr)
            ss << StringUtils::format("\n    ida_xref.add_cref(0x%llx, 0x%llx, XREF_USER)",
                                             callerAddr,
                                             current->impAddr);
        }
    }
    
    ss << "\n\nif __name__ == '__main__':\n";
    ss << "    add_objc_xrefs()\n";
    
    printf("  [*] saved to %s\n", scriptsPath.c_str());
    ss.close();
    return 0;
}

bool IDAObjMsgXREFGenerator::loadMethodChains() {
    sel2chain = ObjcMethodChainSerializationManager::loadMethodChain(inputPath);
    if (sel2chain.empty()) {
        return false;
    }
    
    printf("\t [+] load storage from disk succeeded!\n");
    return true;
    
    using namespace httplib;

    Server svr;

//    svr.Get("/hi", [](const Request& req, Response& res) {
//      res.set_content("Hello World!", "text/plain");
//    });
//
//    svr.Get(R"(/numbers/(\d+))", [&](const Request& req, Response& res) {
//      auto numbers = req.matches[1];
//      res.set_content(numbers, "text/plain");
//    });
    
    svr.Get("/method", [&](const Request& req, Response& res) {
        rapidjson::Document d;
        d.SetObject();
        rapidjson::Document::AllocatorType &allocator = d.GetAllocator();
        
        bool success = true;
        string message = "";
        rapidjson::Value allLinks(rapidjson::kArrayType);
        bool preMode = true;
        if (req.has_param("mode")) {
            string mode = req.get_param_value("mode");
            if (mode == "next") {
                preMode = false;
            }
        }
        
        int maxDepth = 3;
        if (req.has_param("maxDepth")) {
            string maxDepStr = req.get_param_value("maxDepth");
            maxDepth = atoi(maxDepStr.c_str());
        }
        if (req.has_param("sel")) {
            string methodExpr = req.get_param_value("sel");
            MethodChain *chain = sel2chain[methodExpr];
            printf("[*] try to find pre call chains for %s -> %p\n", methodExpr.c_str(), chain);
            vector<vector<pair<MethodChain *, uint64_t>>> results;
            if (chain) {
                if (preMode) {
                    findAllPath(chain, {{chain, 0}}, results);
                } else {
                    findAllPathNext(chain, {{chain, 0}}, results, maxDepth);
                }
            }
            
            for (vector<pair<MethodChain *, uint64_t>> result : results) {
                if (preMode) {
                    reverse(result.begin(), result.end());
                }
                bool first = true;
                printf("\t");
                
                rapidjson::Value links(rapidjson::kArrayType);
                for (pair<MethodChain *, uint64_t> entry : result) {
                    printf("%s%s[%s %s]",
                           first ? "" : " -> ",
                           entry.first->prefix.c_str(),
                           entry.first->className.c_str(),
                           entry.first->methodName.c_str());
                    {
                        rapidjson::Value stringValue(rapidjson::kStringType);
                        string link = StringUtils::format("%s[%s %s]",
                                                          entry.first->prefix.c_str(),
                                                          entry.first->className.c_str(),
                                                          entry.first->methodName.c_str());
                        stringValue.SetString(link.c_str(), allocator);
                        links.PushBack(stringValue, allocator);
                    }
                    first = false;
                }
                printf("\n");
                allLinks.PushBack(links, allocator);
            }
        }
        d.AddMember("success", success, allocator);
        d.AddMember("alllinks", allLinks, allocator);
        {
            rapidjson::Value stringValue(rapidjson::kStringType);
            stringValue.SetString(message.c_str(), allocator);
            d.AddMember("message", stringValue, allocator);
        }
        
        rapidjson::StringBuffer strbuf;
        rapidjson::Writer<rapidjson::StringBuffer> writer(strbuf);
        d.Accept(writer);
        res.set_content(strbuf.GetString(), "application/json");
    });

//    svr.Get("/body-header-param", [](const Request& req, Response& res) {
//      if (req.has_header("Content-Length")) {
//        auto val = req.get_header_value("Content-Length");
//      }
//      if (req.has_param("key")) {
//        auto val = req.get_param_value("key");
//      }
//      res.set_content(req.body, "text/plain");
//    });
//
//    svr.Get("/stop", [&](const Request& req, Response& res) {
//      svr.stop();
//    });

    svr.listen("127.0.0.1", 2345);
    return true;
}

static void findAllPath(MethodChain *current, vector<pair<MethodChain *, uint64_t>> result, vector<vector<pair<MethodChain *, uint64_t>>> &results) {
    if (current->prevMethods.size() == 0) {
        results.push_back(result);
        return;
    }
    for (auto it = current->prevMethods.begin(); it != current->prevMethods.end(); it++) {
        if (std::find(result.begin(), result.end(), *it) != result.end()) {
            continue;
        }
        result.push_back(*it);
        findAllPath(it->first, result, results);
        result.pop_back();
    }
}

static void findAllPathNext(MethodChain *current, vector<pair<MethodChain *, uint64_t>> result, vector<vector<pair<MethodChain *, uint64_t>>> &results, int maxDepth) {
    if (current->nextMethods.size() == 0 || result.size() >= maxDepth) {
        results.push_back(result);
        return;
    }
    for (auto it = current->nextMethods.begin(); it != current->nextMethods.end(); it++) {
        if (std::find(result.begin(), result.end(), *it) != result.end()) {
            continue;
        }
        result.push_back(*it);
        findAllPathNext(it->first, result, results, maxDepth);
        result.pop_back();
    }
}
