//
//  ScannerContext.hpp
//  iblessing
//
//  Created by Soulghost on 2020/8/8.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef ScannerContext_hpp
#define ScannerContext_hpp

#include "Object.hpp"
#include "ScannerCommon.hpp"
#include <string>

NS_IB_BEGIN

class ScannerContext {
public:
    std::string getBinaryPath();
    scanner_err setupWithBinaryPath(std::string binaryPath);
    
private:
    std::string binaryPath;
};

NS_IB_END

#endif /* ScannerContext_hpp */
