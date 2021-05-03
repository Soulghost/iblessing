//
//  ARM64Registers.hpp
//  iblessing
//
//  Created by soulghost on 2020/2/23.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef ARM64Registers_hpp
#define ARM64Registers_hpp

#include <iblessing-core/infra/Object.hpp>

NS_IB_BEGIN

typedef enum ARM64RegisterType {
    ARM64_REG_TYPE_SP,
    ARM64_REG_TYPE_X,
    ARM64_REG_TYPE_D
} ARM64RegisterType;

class ARM64Register {
public:
    bool available;
    bool longRegister;
    ARM64RegisterType type;
    std::string comment;
    
    uint64_t size;
    void *value;
    
    ARM64Register(bool available, uint64_t size, ARM64RegisterType type, std::string comment) :
        available(available),
        longRegister(false),
        comment(comment),
        size(size),
        value(0)
    {}
    
    virtual std::string getDesc();
    virtual std::string getValueDesc();
    virtual uint64_t getValue();
    virtual void setValue(void *data, uint64_t size);
    virtual bool movFrom(ARM64Register *other);
    virtual void invalidate() = 0;
};

class ARM64RegisterX : public ARM64Register {
public:
    int num;
    
    ARM64RegisterX() : ARM64Register(false, 8, ARM64_REG_TYPE_X, "") {}
    
    ARM64RegisterX(int num) : ARM64RegisterX() {
        this->num = num;
    }
    
    ARM64RegisterX* setW();
    ARM64RegisterX* setX();
    virtual std::string getDesc();
    virtual std::string getValueDesc();
    virtual uint64_t getValue();
    virtual void invalidate();
};

class ARM64RegisterSP : public ARM64Register {
public:
    ARM64RegisterSP(uint64_t value) : ARM64Register(true, 8, ARM64_REG_TYPE_SP, "") {
        setValue(&value, 8);
    }
    
    virtual std::string getDesc();
    virtual std::string getValueDesc();
    virtual uint64_t getValue();
    virtual void invalidate();
};

class ARM64RegisterD : public ARM64Register {
public:
    int num;
    
    ARM64RegisterD() : ARM64Register(false, 8, ARM64_REG_TYPE_D, "") {
    
    }
    ARM64RegisterD(int num) : ARM64RegisterD() {
        this->num = num;
    }
    
    virtual std::string getDesc();
    virtual std::string getValueDesc();
    virtual uint64_t getValue();
    virtual void invalidate();
};

NS_IB_END

#endif /* ARM64Registers_hpp */
