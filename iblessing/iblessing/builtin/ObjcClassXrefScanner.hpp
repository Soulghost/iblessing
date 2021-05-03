//
//  ObjcClassXrefScanner.hpp
//  iblessing
//
//  Created by soulghost on 2020/7/8.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef ObjcClassXrefScanner_hpp
#define ObjcClassXrefScanner_hpp

#include "Scanner.hpp"

NS_IB_BEGIN

class ObjcClassXrefScanner : public Scanner {
public:
    ObjcClassXrefScanner(std::string name, std::string desc): Scanner(name, desc) {}
    
    virtual ~ObjcClassXrefScanner() {};
    virtual int start();
};

NS_IB_END

#endif /* ObjcClassXrefScanner_hpp */
