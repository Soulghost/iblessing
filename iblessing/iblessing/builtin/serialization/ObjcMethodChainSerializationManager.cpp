//
//  ObjcMethodChainSerializationManager.cpp
//  iblessing
//
//  Created by soulghost on 2020/7/21.
//  Copyright © 2020 soulghost. All rights reserved.
//

#include "ObjcMethodChainSerializationManager.hpp"
#include <fstream>
#include <algorithm>
#include <iblessing-core/v2/util/StringUtils.h>

using namespace std;
using namespace iblessing;

string ObjcMethodChainSerializationManager::currentVersion = "0.2";

bool ObjcMethodChainSerializationManager::storeMethodChain(std::string path, std::map<string, MethodChain *> &sel2chain) {
    vector<pair<string, MethodChain *>> chainPairs(sel2chain.begin(), sel2chain.end());
    
    // sort map by id
    sort(chainPairs.begin(), chainPairs.end(), [](pair<string, MethodChain *> &a, pair<string, MethodChain *> &b) {
        return a.second->chainId < b.second->chainId;
    });
    
    ofstream ss(path);
    if (!ss.is_open()) {
        return false;
    }
    
    ss.clear();
    ss << StringUtils::format("iblessing methodchains,ver:%s;", currentVersion.c_str()) << endl;
    ss << "chainId,sel,prefix,className,methodName,prevMethods,nextMethods" << endl;
    for (pair<string, MethodChain *> &chainPair : chainPairs) {
        string sel = chainPair.first;
        MethodChain *chain = chainPair.second;
        ss << StringUtils::format("%lld,0x%llx,%s,%s,%s,%s", chain->chainId,
                                                      chain->impAddr,
                                                      sel.c_str(),
                                                      chain->prefix.c_str(),
                                                      chain->className.c_str(),
                                                      chain->methodName.c_str());
        if (chain->prevMethods.size() > 0) {
            bool first = true;
            for (auto it = chain->prevMethods.begin(); it != chain->prevMethods.end(); it++) {
                if (__builtin_expect(first, false)) {
                    ss << StringUtils::format(",[%lld#0x%llx",
                                              it->first->chainId,
                                              it->second);
                } else {
                    ss << StringUtils::format("@%lld#0x%llx",
                                              it->first->chainId,
                                              it->second);
                }
                first = false;
            }
            ss << "]";
        } else {
            ss << ",[]";
        }
        
        if (chain->nextMethods.size() > 0) {
            bool first = true;
            for (auto it = chain->nextMethods.begin(); it != chain->nextMethods.end(); it++) {
                if (__builtin_expect(first, false)) {
                    ss << StringUtils::format(",[%lld#0x%llx",
                                              it->first->chainId,
                                              it->second);
                } else {
                    ss << StringUtils::format("@%lld#0x%llx",
                                              it->first->chainId,
                                              it->second);
                }
                first = false;
            }
            ss << "]";
        } else {
            ss << ",[]";
        }
        ss << endl;
    }
    ss.close();
    return true;
}

std::string ObjcMethodChainSerializationManager::detectMethodChainVersion(std::string path) {
    ifstream file(path);
    if (file.fail()) {
        return "";
    }
    
    string line;
    getline(file, line);
    
    // iblessing methodchains,ver:%s;
    vector<string> parts = StringUtils::split(line, ',');
    if (parts.size() < 2) {
        return "";
    }
    
    parts = StringUtils::split(parts[1], ':');
    if (parts.size() < 2 || parts[0] != "ver") {
        return "";
    }
    string verExpr = parts[1];
    if (!StringUtils::has_suffix(verExpr, ";")) {
        return "";
    }
    
    verExpr = verExpr.substr(0, verExpr.size() - 1);
//    printf("  [*] load method-chain db for version %s\n", line.c_str());
    return verExpr;
}

std::map<std::string, MethodChain *> ObjcMethodChainSerializationManager::loadMethodChain(std::string path) {
    string verExpr = detectMethodChainVersion(path);
    if (verExpr != currentVersion) {
        printf("  [!] report version mismatch, current %s, input %s, please regenerate the report\n", currentVersion.c_str(), verExpr.c_str());
        return {};
    }
    
    ifstream file(path);
    if (file.fail()) {
        return {};
    }
    
    string line;
    int cnt = 0;
    map<uint64_t, MethodChain *> id2instance;
    std::map<std::string, MethodChain *> sel2chain;
    while (getline(file, line)) {
        if (__builtin_expect(cnt == 0, false)) {
            // version matching
            printf("  [*] load method-chain db for version %s\n", line.c_str());
            cnt++;
            continue;
        } else if (__builtin_expect(cnt == 1, false)) {
            // table keys
            printf("  [*] table keys %s\n", line.c_str());
            cnt++;
            continue;
        }
        
        // load entries
        vector<string> cols = StringUtils::split(line, ',');
        if (cols.size() != 8) {
            printf("\t[-] bad line %s\n", line.c_str());
            cnt++;
            continue;
        }
        
        uint64_t chainId = atol(cols[0].c_str());
        uint64_t impAddr = strtol(cols[1].c_str(), NULL, 16);
        string &sel = cols[2];
        string &prefix = cols[3];
        string &className = cols[4];
        string &methodName = cols[5];
        string &prevMethodsDesc = cols[6];
        string &nextMethodsDesc = cols[7];
        
        if (sel.length() == 0) {
            printf("  [-] bad line %s\n", line.c_str());
            cnt++;
            continue;
        }
        
        MethodChain *chain = new MethodChain();
        chain->chainId = chainId;
        chain->impAddr = impAddr;
        chain->prefix = prefix;
        chain->className = className;
        chain->methodName = methodName;
        if (prevMethodsDesc.length() > 2) {
            vector<string> ids = StringUtils::split(prevMethodsDesc.substr(1, prevMethodsDesc.length() - 2), '@');
            for (string id : ids) {
                vector<string> parts = StringUtils::split(id, '#');
                if (parts.size() != 2) {
                    printf("  [-] bad id %s\n", id.c_str());
                    cnt++;
                    continue;
                }
                MethodChain *chainPlaceholder = (MethodChain *)atol(parts[0].c_str());
                uint64_t callerAddr = strtol(parts[1].c_str(), NULL, 16);
                chain->prevMethods.insert({chainPlaceholder, callerAddr});
            }
        }
        if (nextMethodsDesc.length() > 2) {
            vector<string> ids = StringUtils::split(nextMethodsDesc.substr(1, nextMethodsDesc.length() - 2), '@');
            for (string id : ids) {
                vector<string> parts = StringUtils::split(id, '#');
                if (parts.size() != 2) {
                    printf("  [-] bad id %s\n", id.c_str());
                    cnt++;
                    continue;
                }
                MethodChain *chainPlaceholder = (MethodChain *)atol(parts[0].c_str());
                uint64_t callerAddr = strtol(parts[1].c_str(), NULL, 16);
                chain->nextMethods.insert({chainPlaceholder, callerAddr});
            }
        }
        sel2chain[sel] = chain;
        id2instance[chainId] = chain;
        cnt++;
    }
    
    for (auto it = sel2chain.begin(); it != sel2chain.end(); it++) {
        MethodChain *chain = it->second;
        if (chain->prevMethods.size() > 0) {
            set<pair<MethodChain *, uint64_t>> realChains;
            for (auto it = chain->prevMethods.begin(); it != chain->prevMethods.end(); it++) {
                realChains.insert({id2instance[(uint64_t)it->first], it->second});
            }
            chain->prevMethods = realChains;
        }
        if (chain->nextMethods.size() > 0) {
            set<pair<MethodChain *, uint64_t>> realChains;
            for (auto it = chain->nextMethods.begin(); it != chain->nextMethods.end(); it++) {
                realChains.insert({id2instance[(uint64_t)it->first], it->second});
            }
            chain->nextMethods = realChains;
        }
    }
    return sel2chain;
}
