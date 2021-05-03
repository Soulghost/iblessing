//
//  SymbolXREFScanner.hpp
//  iblessing
//
//  Created by Soulghost on 2020/8/2.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef SymbolXREFScanner_hpp
#define SymbolXREFScanner_hpp

#include <iblessing-core/scanner/Scanner.hpp>
#include <map>
#include <set>

NS_IB_BEGIN

class SymbolXREFScanner : public Scanner {
public:
    SymbolXREFScanner(std::string name, std::string desc): Scanner(name, desc) {}
    
    virtual ~SymbolXREFScanner() {};
    virtual int start();
    
private:
    void init();
};

NS_IB_END

#endif /* SymbolXREFScanner_hpp */
