/****************************************************************************
Copyright (c) 2008-2010 Ricardo Quesada
Copyright (c) 2010-2012 cocos2d-x.org
Copyright (c) 2011      Zynga Inc.
Copyright (c) 2013-2016 Chukong Technologies Inc.
Copyright (c) 2017-2018 Xiamen Yaji Software Co., Ltd.

http://www.cocos2d-x.org

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
****************************************************************************/

#include "StringUtils.h"
#include <sstream>
#include <cassert>
#include <stdarg.h>
#include <string.h>

namespace StringUtils {
/*--- This a C++ universal sprintf in the future.
**  @pitfall: The behavior of vsnprintf between VS2013 and VS2015/2017 is different
**      VS2013 or Unix-Like System will return -1 when buffer not enough, but VS2015/2017 will return the actural needed length for buffer at this station
**      The _vsnprintf behavior is compatible API which always return -1 when buffer isn't enough at VS2013/2015/2017
**      Yes, The vsnprintf is more efficient implemented by MSVC 19.0 or later, AND it's also standard-compliant, see reference: http://www.cplusplus.com/reference/cstdio/vsnprintf/
*/
std::string format(const char* format, ...)
{
#define CC_VSNPRINTF_BUFFER_LENGTH 512
    va_list args;
    std::string buffer(CC_VSNPRINTF_BUFFER_LENGTH, '\0');

    va_start(args, format);
    int nret = vsnprintf(&buffer.front(), buffer.length() + 1, format, args);
    va_end(args);

    if (nret >= 0) {
        if ((unsigned int)nret < buffer.length()) {
            buffer.resize(nret);
        }
        else if ((unsigned int)nret > buffer.length()) { // VS2015/2017 or later Visual Studio Version
            buffer.resize(nret);

            va_start(args, format);
            nret = vsnprintf(&buffer.front(), buffer.length() + 1, format, args);
            va_end(args);

            assert(nret == buffer.length());
        }
        // else equals, do nothing.
    }
    else { // less or equal VS2013 and Unix System glibc implement.
        do {
            buffer.resize(buffer.length() * 3 / 2);

            va_start(args, format);
            nret = vsnprintf(&buffer.front(), buffer.length() + 1, format, args);
            va_end(args);

        } while (nret < 0);

        buffer.resize(nret);
    }

    return buffer;
}

std::vector<std::string> split(std::string s, char sep) {
    std::stringstream ss(s);
    std::string component;
    std::vector<std::string> ret;
    while (getline(ss, component, sep)) {
        ret.push_back(component);
    }
    return ret;
}

std::string path_join(std::string a, std::string b) {
    if (a[a.length() - 1] == '/') {
        return a + b;
    }
    return a + "/" + b;
}

bool has_suffix(const std::string &str, const std::string &suffix)
{
    return str.size() >= suffix.size() &&
           str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
}

int countNonPrintablecharacters(const char *str, int limit) {
    if (str == nullptr) {
        return 0;
    }
    
    int count = std::min((int)strlen(str), limit);
    int total = 0;
    for (int i = 0; i < count; i++) {
        char c = str[i];
        if (!(c >= 0x20 && c <= 0x7E)) {
            total++;
        }
    }
    return total;
}

};
