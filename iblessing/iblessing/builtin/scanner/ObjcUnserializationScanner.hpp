//
//  ObjcUnserializationScanner.hpp
//  iblessing
//
//  Created by Soulghost on 2020/8/16.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef ObjcUnserializationScanner_hpp
#define ObjcUnserializationScanner_hpp

#include <iblessing-core/scanner/Scanner.hpp>

NS_IB_BEGIN

class ObjcUnserializationScanner : public Scanner {
public:
    ObjcUnserializationScanner(std::string name, std::string desc): Scanner(name, desc) {}
    
    virtual ~ObjcUnserializationScanner() {};
    virtual int start();
};

NS_IB_END

#endif /* ObjcUnserializationScanner_hpp */
