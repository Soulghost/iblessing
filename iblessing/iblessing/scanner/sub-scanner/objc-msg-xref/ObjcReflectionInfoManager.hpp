//
//  ObjcRelectionInfoManager.hpp
//  iblessing
//
//  Created by Soulghost on 2020/11/28.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef ObjcReflectionInfoManager_hpp
#define ObjcReflectionInfoManager_hpp

#include "ObjcReflectionInfo.hpp"

NS_IB_BEGIN

class ObjcReflectionInfoManager {
public:
    ObjcReflectionInfo info;
    std::string reportPath;
    
    bool syncToDisk();
    bool syncToDisk(std::string path);
};

NS_IB_END

#endif /* ObjcRelectionInfoManager_hpp */
