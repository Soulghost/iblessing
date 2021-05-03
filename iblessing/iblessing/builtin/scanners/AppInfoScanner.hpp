//
//  AppInfoScanner.hpp
//  iblessing
//
//  Created by soulghost on 2020/7/19.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef AppInfoScanner_hpp
#define AppInfoScanner_hpp

#include "Scanner.hpp"

NS_IB_BEGIN

class AppInfoScanner : public Scanner {
public:
    AppInfoScanner(std::string name, std::string desc): Scanner(name, desc, false) {}
    
    virtual ~AppInfoScanner() {};
    virtual int start();
};

NS_IB_END

#endif /* AppInfoScanner_hpp */
