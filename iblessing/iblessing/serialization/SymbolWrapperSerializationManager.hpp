//
//  SymbolWrapperSerializationManager.hpp
//  iblessing
//
//  Created by soulghost on 2020/7/28.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef SymbolWrapperSerializationManager_hpp
#define SymbolWrapperSerializationManager_hpp

#include "AntiWrapper.hpp"
#include "FunctionPrototype.hpp"
#include <map>

NS_IB_BEGIN

class SymbolWrapperSerializationManager {
public:
    static std::string currentVersion;
    static bool createReportFromAntiWrapper(std::string path, AntiWrapper &antiWrapper, std::map<std::string, FunctionProtoType> &symbol2proto);
    static std::string detectReportVersion(std::string path);
};

NS_IB_END

#endif /* SymbolWrapperSerializationManager_hpp */
