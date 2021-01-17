//
//  ObjDumpTool.hpp
//  iblessing
//
//  Created by soulghost on 2021/1/16.
//  Copyright © 2021 soulghost. All rights reserved.
//

#ifndef ObjDumpTool_hpp
#define ObjDumpTool_hpp

#include "Object.hpp"

NS_IB_BEGIN

class ObjDumpTool {
public:
    int dumpTextSection(std::string filePath);
};

NS_IB_END

#endif /* ObjDumpTool_hpp */
