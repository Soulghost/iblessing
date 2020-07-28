//
//  SymbolWrapperSerializationManager.cpp
//  iblessing
//
//  Created by soulghost on 2020/7/28.
//  Copyright © 2020 soulghost. All rights reserved.
//

#include "SymbolWrapperSerializationManager.hpp"
#include <sstream>

using namespace std;
using namespace iblessing;

std::string SymbolWrapperSerializationManager::currentVersion = "0.1";

bool SymbolWrapperSerializationManager::createReportFromAntiWrapper(std::string path, AntiWrapper &antiWrapper, map<std::string, FunctionProtoType> &symbol2proto) {
    for (auto it = antiWrapper.simpleWrapperMap.begin();
         it != antiWrapper.simpleWrapperMap.end();
         it++) {
        AntiWrapperBlock &wrapper = it->second;
        if (symbol2proto.find(wrapper.symbolName) != symbol2proto.end()) {
            FunctionProtoType proto = symbol2proto[wrapper.symbolName];
            stringstream ss;
            ss << proto.returnType << " __usercall f@<x0>(";
            for (int i = 0; i < proto.nArgs; i++) {
                // find real src
                AntiWrapperRegLink sourceLink = wrapper.regLinkGraph.x[i].getRootSource();
                if (i > 0) {
                    ss << ", ";
                }
                ss << StringUtils::format("%s@<%s>", proto.argTypes[i].c_str(), sourceLink.getIDAExpr().c_str());
            }
            if (proto.variadic) {
                ss << ", ...";
            }
            ss << ")";
            string idaFuncProto = ss.str();
            printf("\t[+] generate ida prototype for %s's wrapper at 0x%llx: %s\n",
                   wrapper.symbolName.c_str(),
                   wrapper.startAddr,
                   idaFuncProto.c_str());
        }
    }
    return true;
}

std::string SymbolWrapperSerializationManager::detectReportVersion(std::string path) {
    return "";
}
