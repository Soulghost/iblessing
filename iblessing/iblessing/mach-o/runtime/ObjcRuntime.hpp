//
//  ObjcRuntime.hpp
//  iblessing
//
//  Created by soulghost on 2020/2/25.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef ObjcRuntime_hpp
#define ObjcRuntime_hpp

#include "Object.hpp"
#include "Vector.hpp"
#include <unordered_map>
#include "ObjcObject.hpp"
#include "ObjcMethod.hpp"
#include "ObjcBlock.hpp"
#include "ObjcCategory.hpp"
#include <set>

NS_IB_BEGIN

class ObjcRuntime {
public:
    std::unordered_map<uint64_t, ObjcClassRuntimeInfo *> address2RuntimeInfo;
    std::unordered_map<ObjcClassRuntimeInfo *, uint64_t> runtimeInfo2address;
    std::unordered_map<uint64_t, ObjcClassRuntimeInfo *> externalClassRuntimeInfo;
    std::unordered_map<std::string, ObjcClassRuntimeInfo *> name2ExternalClassRuntimeInfo;
    std::unordered_map<uint64_t, ObjcClassRuntimeInfo *> ivarInstanceTrickAddress2RuntimeInfo;
    std::unordered_map<uint64_t, ObjcClassRuntimeInfo *> heapInstanceTrickAddress2RuntimeInfo;
    std::unordered_map<std::string, uint64_t> classList;
    std::unordered_map<uint64_t, std::string> address2className;
    
    uint64_t catlist_addr;
    uint64_t catlist_size;
    std::vector<std::shared_ptr<ObjcCategory>> categoryList;
    
    // block
    std::set<uint64_t> blockISAs;
    std::unordered_map<uint64_t, ObjcBlock *> invoker2block;
    
    static ObjcRuntime* getInstance();
    ObjcClassRuntimeInfo* getClassInfoByAddress(uint64_t address, bool needRealize = true);
    ObjcClassRuntimeInfo* evalReturnForIvarGetter(ObjcClassRuntimeInfo *targetClass, std::string getterSEL);
    void loadClassList(uint64_t vmaddr, uint64_t size);
    void loadCatList(uint64_t vmaddr, uint64_t size);
    uint64_t getClassAddrByName(std::string className);
    ObjcClassRuntimeInfo* getClassInfoByName(std::string className);
    bool isClassObjectAtAddress(uint64_t address);
    bool isValidClassInfo(ObjcClassRuntimeInfo *info);
    bool isExistMethod(std::string methodPrefix, std::string classExpr, std::string detectedSEL);
    ObjcMethod* inferNearestMethod(std::string methodPrefix, std::string classExpr, std::string detectedSEL);
    
private:
    ObjcRuntime();
    static ObjcRuntime *_instance;
};

NS_IB_END

#endif /* ObjcRuntime_hpp */
