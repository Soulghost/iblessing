//
//  SymbolWrapperSerializationManager.cpp
//  iblessing
//
//  Created by soulghost on 2020/7/28.
//  Copyright © 2020 soulghost. All rights reserved.
//

#include "SymbolWrapperSerializationManager.hpp"
#include <sstream>
#include <fstream>

using namespace std;
using namespace iblessing;

std::string SymbolWrapperSerializationManager::currentVersion = "0.1";

bool SymbolWrapperSerializationManager::createReportFromAntiWrapper(std::string path, AntiWrapper &antiWrapper, map<std::string, FunctionProtoType> &symbol2proto) {
    ofstream fs(path);
    if (!fs.is_open()) {
        return false;
    }
    
    fs.clear();
    fs << StringUtils::format("iblessing symbol-wrappers,ver:%s;", currentVersion.c_str()) << endl;
    fs << "wrapperId;address;name;prototype" << endl;
    uint64_t wid = 0;
    for (auto it = antiWrapper.simpleWrapperMap.begin();
         it != antiWrapper.simpleWrapperMap.end();
         it++) {
        AntiWrapperBlock &wrapper = it->second;
        if (symbol2proto.find(wrapper.symbolName) != symbol2proto.end()) {
            FunctionProtoType proto = symbol2proto[wrapper.symbolName];
            stringstream ss;
            ss << proto.returnType << " __usercall f@<x0>(";
            int i = 0;
            for (i = 0; i < proto.nArgs; i++) {
                // find real src
                AntiWrapperRegLink sourceLink = wrapper.regLinkGraph.x[i].getRootSource();
                if (i > 0) {
                    ss << ", ";
                }
                ss << StringUtils::format("%s@<%s>", proto.argTypes[i].c_str(), sourceLink.getIDAExpr().c_str());
            }
            
            // if function is variadic, check follow-up reg transforms
            if (proto.variadic) {
                for (; i <= 7; i++) {
                    AntiWrapperRegLink current = wrapper.regLinkGraph.x[i];
                    if (current.active) {
                        ss << ", " << StringUtils::format("%s@<%s>", "uint64_t", current.getRootSource().getIDAExpr().c_str());
                    } else {
                        break;
                    }
                }
                ss << ", ...";
            }
            
            ss << ")";
            string idaFuncProto = ss.str();
            fs << (wid++) << ";" << StringUtils::format("0x%llx", it->first);
            fs << ";" << it->second.symbolName << ";" << idaFuncProto << endl;
//            printf("\t[+] generate ida prototype for %s's wrapper at 0x%llx: %s\n",
//                   wrapper.symbolName.c_str(),
//                   wrapper.startAddr,
//                   idaFuncProto.c_str());
        }
    }
    
    fs.close();
    return true;
}

vector<SymbolWrapperInfo> SymbolWrapperSerializationManager::loadWrapperInfosFromReport(std::string path) {
    string verExpr = detectReportVersion(path);
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
    vector<SymbolWrapperInfo> wrapperInfos;
    while (getline(file, line)) {
        if (__builtin_expect(cnt == 0, false)) {
            // version matching
            printf("  [*] load symbol-wrappers db for version %s\n", line.c_str());
            cnt++;
            continue;
        } else if (__builtin_expect(cnt == 1, false)) {
            // table keys
            printf("  [*] table keys %s\n", line.c_str());
            cnt++;
            continue;
        }
        
        // load entries
        vector<string> cols = StringUtils::split(line, ';');
        if (cols.size() != 4) {
            printf("\t[-] bad line %s\n", line.c_str());
            cnt++;
            continue;
        }
        SymbolWrapperInfo info;
        info.address = strtol(cols[1].c_str(), nullptr, 16);
        info.name = cols[2];
        info.prototype = cols[3];
        wrapperInfos.push_back(info);
    }
    return wrapperInfos;
}

string SymbolWrapperSerializationManager::detectReportVersion(std::string path) {
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
//    printf("  [*] load symbol-wrapper db for version %s\n", line.c_str());
    return verExpr;
}
