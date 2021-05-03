//
//  ObjcMethodChainSerializationManager.hpp
//  iblessing
//
//  Created by soulghost on 2020/7/21.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef ObjcMethodChainSerializationManager_hpp
#define ObjcMethodChainSerializationManager_hpp

#include "ObjcMethodChain.hpp"
#include <map>

NS_IB_BEGIN

class ObjcMethodChainSerializationManager {
public:
    static std::string currentVersion;
    static bool storeMethodChain(std::string path, std::map<std::string, MethodChain *> &sel2chain);
    static std::string detectMethodChainVersion(std::string path);
    static std::map<std::string, MethodChain *> loadMethodChain(std::string path);
};

NS_IB_END

#endif /* ObjcMethodChainSerializationManager_hpp */
