//
//  SymbolWrapperScanner.hpp
//  iblessing
//
//  Created by soulghost on 2020/7/16.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef SymbolWrapperScanner_hpp
#define SymbolWrapperScanner_hpp

#include <iblessing-core/scanner/Scanner.hpp>
#include <pthread.h>
#include <iblessing-core/v2/vendor/unicorn/unicorn.h>
#include <map>

NS_IB_BEGIN

class SymbolWrapperScanner : public Scanner {
public:
    SymbolWrapperScanner(std::string name, std::string desc): Scanner(name, desc) {}
    
    virtual ~SymbolWrapperScanner() {};
    virtual int start();
};

NS_IB_END

#endif /* SymbolWrapperScanner_hpp */
