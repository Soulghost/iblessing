//
//  StringTable.hpp
//  iblessing
//
//  Created by soulghost on 2020/2/20.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef StringTable_hpp
#define StringTable_hpp

#include <iblessing-core/infra/Object.hpp>
#include <map>
#include <iblessing-core/v3/dyld/dyld-sharedcache-loader.hpp>

NS_IB_BEGIN

class StringTable : public Object {
public:
    uint64_t vmaddr;
    uint8_t *stringData;
    uint64_t stringDataSize;
    
    virtual ~StringTable();
    static StringTable* getInstance();
    
    void buildStringTable(uint64_t vmaddr, uint8_t *data, uint64_t size);
    std::string getStringAtIndex(uint64_t index);
    
    static std::shared_ptr<StringTable> makeOrGetSharedStringTable(DyldLinkContext linkContext, uint64_t addr, uint64_t size);
    
private:
    static StringTable *_instance;
    std::map<uint64_t, std::string> index2Names;
    
//    StringTable();
};

NS_IB_END

#endif /* StringTable_hpp */
