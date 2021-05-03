//
//  SymbolWrapperSerializationManager.hpp
//  iblessing
//
//  Created by soulghost on 2020/7/28.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef SymbolWrapperSerializationManager_hpp
#define SymbolWrapperSerializationManager_hpp

#include <map>
#include <iblessing-core/v2/analyser/wrapper/AntiWrapper.hpp>
#include <iblessing-core/v2/analyser/wrapper/FunctionPrototype.hpp>

NS_IB_BEGIN

typedef struct SymbolWrapperInfo {
    uint64_t address;
    std::string name;
    std::string prototype;
} SymbolWrapperInfo;

class SymbolWrapperSerializationManager {
public:
    static std::string currentVersion;
    static bool createReportFromAntiWrapper(std::string path, AntiWrapper &antiWrapper, std::map<std::string, FunctionProtoType> &symbol2proto);
    static std::string detectReportVersion(std::string path);
    static std::vector<SymbolWrapperInfo> loadWrapperInfosFromReport(std::string path);
};

NS_IB_END

#endif /* SymbolWrapperSerializationManager_hpp */
