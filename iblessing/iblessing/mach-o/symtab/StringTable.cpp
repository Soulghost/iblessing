//
//  StringTable.cpp
//  iblessing
//
//  Created by soulghost on 2020/2/20.
//  Copyright © 2020 soulghost. All rights reserved.
//

#include "StringTable.hpp"

using namespace iblessing;

StringTable* StringTable::_instance = nullptr;

StringTable::~StringTable() {
    
}

StringTable* StringTable::getInstance() {
    if (StringTable::_instance == nullptr) {
        StringTable::_instance = new StringTable();
    }
    return StringTable::_instance;
}

void StringTable::buildStringTable(uint64_t vmaddr, uint8_t *data, uint64_t size) {
    uint64_t cur = 0;
    this->vmaddr = vmaddr;
    stringData = data;
    stringDataSize = size;
    while (cur < size) {
        const char *symName = (const char *)data;
        uint64_t slen = strlen(symName);
        index2Names[cur] = std::string(symName);
        
        cur += slen + 1;
        data += slen + 1;
    }
}

std::string StringTable::getStringAtIndex(uint64_t index) {
    if (index2Names.find(index) == index2Names.end()) {
        if (index < stringDataSize) {
            return (const char *)(stringData + index);
        }
        assert(false);
    }
    return index2Names[index];
}
