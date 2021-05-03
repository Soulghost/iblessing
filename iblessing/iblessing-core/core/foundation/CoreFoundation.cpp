//
//  CoreFoundation.cpp
//  iblessing
//
//  Created by Soulghost on 2020/8/13.
//  Copyright © 2020 soulghost. All rights reserved.
//

#include "CoreFoundation.hpp"
#include <iblessing-core/v2/util/StringUtils.h>
#include <sstream>
#include <set>
#include <map>
#include <stack>
#include <iblessing-core/v2/util/termcolor.h>

using namespace std;
using namespace iblessing;

static bool is_number(char c) {
    return c >= '0' && c <= '9';
}

vector<string> CoreFoundation::argumentsFromSignature(const char *signaure) {
    static set<char> primaryTypes{
        'c', 'i', 's', 'l', 'q',
        'C', 'I', 'S', 'L', 'Q',
        'f', 'd', 'B', 'v'
    };
    
    static map<char, char> bMap{
        {'[', '}'},
        {'{', '}'},
        {'(', ')'},
    };
    
    vector<string> args;
    size_t len = strlen(signaure);
    
    // "@\"NSString\"56@?0i8@\"BlockSubB\"12B20^B24^i32#40@\"BlockSubA\"48"
    // "v16@?0@\"BlockSubA\"8"
    // "v32@?0@8Q16^B24"
    
    // deadlock
    // RxBaseApplicationDelegate application:handleActionWithIdentifier:forRemoteNotification:withResponseInfo:completionHandler:
    // v24@?0@\"<RxApplicationService>\"8@?<v@?>16
    
    size_t lastIndex = 0;
    int duplicateCount = 0;
    for (size_t i = 0; i < strlen(signaure);) {
        lastIndex = i;
        
        char c = signaure[i];
        
        // check for primary type
        if (primaryTypes.find(c) != primaryTypes.end()) {
            args.push_back(StringUtils::format("%c", c));
            i++;
        }
        
        // check for pointer type
        if (c == '*' || c == '#' || c == ':') {
            args.push_back(StringUtils::format("%c", c));
            i++;
        } else if (c == '^') {
            stringstream ss;
            while (i < len && !is_number(signaure[i])) {
                ss << signaure[i];
                i++;
            }
            args.push_back(ss.str());
        } else if (bMap.find(c) != bMap.end()) {
            stack<char> stk;
            stringstream ss;
            
            stk.push(c);
            ss << c;
            i++;
            
            char begin = c;
            char end = bMap[c];
            while (!stk.empty() && i < len) {
                char c = signaure[i];
                if (c == begin) {
                    stk.push(c);
                } else if (c == end) {
                    stk.pop();
                }
                ss << c;
                i++;
            }
            args.push_back(ss.str());
        }
        
        // check for objects
        if (c == '@') {
            if (i < len - 1 && signaure[i + 1] == '"') {
                // objc class instance pointer
                // move to string
                i += 2;
                stringstream ss;
                ss << '@';
                while (i < len && signaure[i] != '"') {
                    ss << signaure[i];
                    i++;
                }
                args.push_back(ss.str());
                
                // consume "
                i++;
            } else if (i < len - 1 && signaure[i + 1] == '?') {
                // objc block pointer
                args.push_back("@?");
                
                // consume @?
                i += 2;
            } else {
                args.push_back("id");
                // consume @
                i++;
            }
        }
        
        
        // slide to nums
        while (i < len && !is_number(signaure[i])) {
            i++;
        }
        
        // skip offset or size nums
        while (i < len && is_number(signaure[i])) {
            i++;
        }
        
        if (i == lastIndex) {
            duplicateCount++;
            if (duplicateCount > 100) {
                cout << endl;
                cout << termcolor::red << "[-] Oh, there is a deadlock in signature compute, ";
                cout << "the signature is " << signaure << termcolor::reset;
                cout << endl;
                exit(1);
            }
        } else {
            duplicateCount = 0;
        }
    }
    
    return args;
}

string CoreFoundation::resolveTypeEncoding(string &typeEncoding) {
    static map<string, string> primaryTypes{
        {"c", "char"},
        {"i", "int"},
        {"s", "short"},
        {"l", "long"},
        {"q", "long long"},
        {"C", "unsigned char"},
        {"I", "unsigned int"},
        {"S", "unsigned short"},
        {"L", "unsigned long"},
        {"Q", "unsigned long long"},
        {"f", "float"},
        {"d", "double"},
        {"B", "bool"},
        {"v", "void"},
        {"*", "char *"},
    };
    if (primaryTypes.find(typeEncoding) != primaryTypes.end()) {
        return primaryTypes[typeEncoding];
    }
    
    return typeEncoding;
}
