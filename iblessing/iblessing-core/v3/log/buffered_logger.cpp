//
//  buffered_logger.cpp
//  iblessing-core
//
//  Created by soulghost on 2021/11/5.
//  Copyright © 2021 soulghost. All rights reserved.
//

#include "buffered_logger.hpp"

#define DefaultPurgeLimit (1 * 1024 * 1024)

using namespace std;
using namespace iblessing;

BufferedLogger* BufferedLogger::_globalInstance = nullptr;

BufferedLogger* BufferedLogger::globalLogger() {
    if (_globalInstance == nullptr) {
        _globalInstance = new BufferedLogger();
    }
    return _globalInstance;
}

BufferedLogger::BufferedLogger() {
    buffer = "";
}

void BufferedLogger::purgeBuffer(uint64_t limit) {
    if (buffer.length() <= limit) {
        return;
    }
    buffer = "";
}

void BufferedLogger::append(string content) {
    if (buffer.length() + content.length() > DefaultPurgeLimit) {
        purgeBuffer(0);
    }
    buffer += content;
//    printBuffer();
}

void BufferedLogger::printBuffer() {
    printf("%s", buffer.c_str());
    buffer = "";
}

std::string BufferedLogger::getBuffer() {
    return buffer;
}
