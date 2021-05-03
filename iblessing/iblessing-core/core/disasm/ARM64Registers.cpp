//
//  ARM64Registers.cpp
//  iblessing
//
//  Created by soulghost on 2020/2/23.
//  Copyright © 2020 soulghost. All rights reserved.
//

#include "ARM64Registers.hpp"
#include <iblessing-core/v2/util/StringUtils.h>

using namespace std;
using namespace iblessing;

#pragma mark - ARM64Register
string ARM64Register::getDesc() {
    return "r?";
}

string ARM64Register::getValueDesc() {
    return "?";
}

uint64_t ARM64Register::getValue() {
    assert(false);
    return 0;
}

void ARM64Register::setValue(void *data, uint64_t size) {
    void *valueToFree = this->value;
    
    if (size > this->size) {
        // chunk src and assign
        void *dst = malloc(this->size);
        memcpy(dst, data, this->size);
        this->value = dst;
        available = true;
    } else {
        void *dst = malloc(this->size);
        bzero(dst, this->size);
        memcpy(dst, data, size);
        this->value = dst;
        available = true;
    }
    
    if (valueToFree && valueToFree != this->value) {
        free(valueToFree);
    }
}

bool ARM64Register::movFrom(ARM64Register *other) {
    if (!other->available) {
        available = false;
        return false;
    }
    
    // for apple's opt mark: mov x29, x29
    if (this == other) {
        return true;
    }
    
    this->setValue(other->value, other->size);
    return true;
}

#pragma mark - ARM64RegisterX
string ARM64RegisterX::getDesc() {
    return StringUtils::format("x%d", num);
}

string ARM64RegisterX::getValueDesc() {
    return StringUtils::format("0x%llx", getValue());
}

uint64_t ARM64RegisterX::getValue() {
    assert(!longRegister);
    if (__builtin_expect(this->size == 8, true)) {
        // x mode
        return *reinterpret_cast<uint64_t *>(value);
    }
    // w mode
    return *reinterpret_cast<uint32_t *>(value);
}

ARM64RegisterX* ARM64RegisterX::setW() {
    this->size = 4;
    return this;
}

ARM64RegisterX* ARM64RegisterX::setX() {
    this->size = 8;
    return this;
}

void ARM64RegisterX::invalidate() {
    available = false;
}

#pragma mark - ARM64RegisterSP
string ARM64RegisterSP::getDesc() {
    return StringUtils::format("sp");
}

string ARM64RegisterSP::getValueDesc() {
    return StringUtils::format("0x%llx", getValue());
}

uint64_t ARM64RegisterSP::getValue() {
    return *reinterpret_cast<uint64_t *>(value);
}

void ARM64RegisterSP::invalidate() {
    available = false;
}

#pragma mark - ARM64RegisterD
string ARM64RegisterD::getDesc() {
    return StringUtils::format("d%d", num);
}

string ARM64RegisterD::getValueDesc() {
    return StringUtils::format("0x%llx", getValue());
}

uint64_t ARM64RegisterD::getValue() {
    assert(!longRegister);
    return *reinterpret_cast<uint64_t *>(value);
}

void ARM64RegisterD::invalidate() {
    available = false;
}

