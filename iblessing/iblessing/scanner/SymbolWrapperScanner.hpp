//
//  SymbolWrapperScanner.hpp
//  iblessing
//
//  Created by soulghost on 2020/7/16.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef SymbolWrapperScanner_hpp
#define SymbolWrapperScanner_hpp

#include "Scanner.hpp"
#include "AntiWrapper.hpp"
#include <pthread.h>
#include <unicorn/unicorn.h>
#include <map>
#include "FunctionPrototype.hpp"

NS_IB_BEGIN

class SymbolWrapperScanner : public Scanner {
public:
    AntiWrapper antiWrapper;
    pthread_mutex_t wrapperLock;
    uc_engine *uc;
    uc_context *ctx;
    std::map<std::string, FunctionProtoType> symbol2proto;
    
    SymbolWrapperScanner(std::string name, std::string desc): Scanner(name, desc) {
        init();
    }
    
    virtual ~SymbolWrapperScanner() {};
    virtual int start();
    
private:
    void init();
};

NS_IB_END

#endif /* SymbolWrapperScanner_hpp */
