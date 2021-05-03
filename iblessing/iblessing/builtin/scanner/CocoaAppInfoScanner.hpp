//
//  CocoaAppInfoScanner.hpp
//  iblessing
//
//  Created by soulghost on 2020/8/10.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef CocoaAppInfoScanner_hpp
#define CocoaAppInfoScanner_hpp

#include <iblessing-core/scanner/Scanner.hpp>

NS_IB_BEGIN

class CocoaAppInfoScanner : public Scanner {
public:
    CocoaAppInfoScanner(std::string name, std::string desc): Scanner(name, desc, false) {}
    
    virtual ~CocoaAppInfoScanner() {};
    virtual int start();
};

NS_IB_END

#endif /* CocoaAppInfoScanner_hpp */
