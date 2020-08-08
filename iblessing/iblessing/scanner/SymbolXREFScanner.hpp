//
//  SymbolXREFScanner.hpp
//  iblessing
//
//  Created by Soulghost on 2020/8/2.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef SymbolXREFScanner_hpp
#define SymbolXREFScanner_hpp

#include "Scanner.hpp"
#include <map>
#include <set>

NS_IB_BEGIN

struct SymbolXREF {
    std::string name;
    uint64_t startAddr;
    uint64_t endAddr;
    std::set<uint64_t> xrefAddrs;
    
    bool operator < (const SymbolXREF &rhs) const {
        return startAddr < rhs.startAddr;
    }
};

class SymbolXREFScanner : public Scanner {
public:
    std::map<std::string, std::set<SymbolXREF>> xrefs;
    
    SymbolXREFScanner(std::string name, std::string desc): Scanner(name, desc) {}
    
    virtual ~SymbolXREFScanner() {};
    virtual int start();
    
private:
    std::map<std::string, std::set<SymbolXREF>> currentXREFs = {};
    uint64_t funcStartCursor = 0;
    uint8_t progressCur = 0;
    void init();
};

NS_IB_END

#endif /* SymbolXREFScanner_hpp */
