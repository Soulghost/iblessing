//
//  PredicateScanner.hpp
//  iblessing
//
//  Created by soulghost on 2020/4/27.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef PredicateScanner_hpp
#define PredicateScanner_hpp

#include <iblessing-core/infra/Object.hpp>
#include <vector>
#include <iblessing-core/scanner/Scanner.hpp>

NS_IB_BEGIN

class PredicateScanner : public Scanner {
public:
    PredicateScanner(std::string name, std::string desc): Scanner(name, desc) {}
    
    virtual ~PredicateScanner() {};
    virtual int start();
};

NS_IB_END

#endif /* PredicateScanner_hpp */
