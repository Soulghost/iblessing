//
//  ObjcMethodCallSnapshotSerializationManager.hpp
//  iblessing
//
//  Created by Soulghost on 2020/10/24.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef ObjcMethodCallSnapshotSerializationManager_hpp
#define ObjcMethodCallSnapshotSerializationManager_hpp

#include "ObjcMethodCall.hpp"
#include <map>
#include <set>

NS_IB_BEGIN

class ObjcMethodCallSnapshotSerializationManager {
public:
    static bool storeAsJSON(std::string path, std::map<uint64_t, std::set<ObjcMethodCall>> callSnapshots);
};

NS_IB_END

#endif /* ObjcMethodCallSnapshotSerializationManager_hpp */
