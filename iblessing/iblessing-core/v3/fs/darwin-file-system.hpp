//
//  darwin-file-system.hpp
//  iblessing-core
//
//  Created by soulghost on 2021/11/15.
//  Copyright © 2021 soulghost. All rights reserved.
//

#ifndef darwin_file_system_hpp
#define darwin_file_system_hpp

#include <iblessing-core/v2/common/ibtypes.h>
#include <iblessing-core/v2/vendor/unicorn/unicorn.h>
#include <map>
#include <memory>

NS_IB_BEGIN

class DarwinFile {
public:    
    std::string path;
    int fd;
    uint64_t seek;
    char *buf;
    uint64_t size;
};

class DarwinFileSystem {
public:
    DarwinFileSystem(uc_engine *uc);
    
    int open(char *path, int oflags);
    int read(int fd, uint64_t bufferAddr, int count);
    int write(int fd, uint64_t bufferAddr, int count);
    int close(int fd);
    bool has(int fd);
    
protected:
    uc_engine *uc;
    int fdCounter;
    std::map<int, std::shared_ptr<DarwinFile>> fd2file;
};

NS_IB_END

#endif /* darwin_file_system_hpp */
