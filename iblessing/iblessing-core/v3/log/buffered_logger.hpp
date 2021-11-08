//
//  buffered_logger.hpp
//  iblessing-core
//
//  Created by soulghost on 2021/11/5.
//  Copyright © 2021 soulghost. All rights reserved.
//

#ifndef buffered_logger_hpp
#define buffered_logger_hpp

#include <iblessing-core/v2/common/ibtypes.h>
#include <string>

NS_IB_BEGIN

class BufferedLogger {
public:
    BufferedLogger();
    
    static BufferedLogger* globalLogger();
    void purgeBuffer(uint64_t limit);
    void printBuffer();
    void append(std::string content);
    std::string getBuffer();
  
protected:
    static BufferedLogger *_globalInstance;
    std::string buffer;
    
};

NS_IB_END

#endif /* buffered_logger_hpp */
