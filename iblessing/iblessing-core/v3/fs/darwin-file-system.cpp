//
//  darwin-file-system.cpp
//  iblessing-core
//
//  Created by soulghost on 2021/11/15.
//  Copyright © 2021 soulghost. All rights reserved.
//

#include "darwin-file-system.hpp"

using namespace std;
using namespace iblessing;

DarwinFileSystem::DarwinFileSystem(uc_engine *uc) {
    this->uc = uc;
    this->fdCounter = 1000;
}

int DarwinFileSystem::open(char *path, int oflags) {
    if (strcmp(path, "/etc/master.passwd") == 0) {
        shared_ptr<DarwinFile> f = make_shared<DarwinFile>();
        f->path = string(path);
        f->fd = (this->fdCounter++);
        f->seek = 0;
        f->buf = strdup("root:p5Z3vjjEfs.bQ:0:0::0:0:System Administrator:/var/root:/bin/sh");
        f->size = strlen(f->buf);
    }
    return 0;
}

int DarwinFileSystem::read(int fd, uint64_t bufferAddr, int count) {
    return 0;
}

int DarwinFileSystem::write(int fd, uint64_t bufferAddr, int count) {
    return 0;
}

int DarwinFileSystem::close(int fd) {
    return 0;
}
