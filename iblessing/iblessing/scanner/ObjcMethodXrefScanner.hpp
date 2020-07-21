//
//  ObjcMethodXrefScanner.hpp
//  iblessing
//
//  Created by soulghost on 2020/5/15.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef ObjcMethodXrefScanner_hpp
#define ObjcMethodXrefScanner_hpp

#include "Object.hpp"
#include <mach-o/loader.h>
#include <vector>
#include <string>
#include "Scanner.hpp"

NS_IB_BEGIN

class ObjcMethodXrefScanner : public Scanner {
public:
    ObjcMethodXrefScanner(std::string name, std::string desc): Scanner(name, desc) {}
    virtual ~ObjcMethodXrefScanner() {};
    virtual int start();
};

NS_IB_END


#endif /* ObjcMethodXrefScanner_hpp */
