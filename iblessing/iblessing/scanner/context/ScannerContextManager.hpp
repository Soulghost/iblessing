//
//  ScannerContext.hpp
//  iblessing
//
//  Created by Soulghost on 2020/8/8.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef ScannerContextManager_hpp
#define ScannerContextManager_hpp

#include "ScannerContext.hpp"
#include <map>

NS_IB_BEGIN

class ScannerContextManager {
public:
    static ScannerContextManager* globalManager();
    ScannerContext* getContextByBinaryPath(std::string binaryPath);
    
private:
    static ScannerContextManager *_instance;
    std::map<std::string, ScannerContext *> contextMap;
};

NS_IB_END

#endif /* ScannerContextManager_hpp */
