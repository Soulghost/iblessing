//
//  TestObjcMethodXrefs.cpp
//  iblessing
//
//  Created by Soulghost on 2020/8/16.
//  Copyright © 2020 soulghost. All rights reserved.
//

#include "TestObjcMethodXrefs.hpp"
#include <iblessing-core/v2/util/StringUtils.h>
#include "ObjcMethodChainSerializationManager.hpp"
#include <iblessing-core/v2/util/termcolor.h>

#include <cstdio>
#include <unistd.h>

using namespace std;
using namespace iblessing;

// callerMethodName, [{calleeClassName, calleeMethodName}]
typedef map<string, vector<pair<string, string>>> MethodTestSet;

static void greenMessage(string msg) {
    cout << termcolor::green << msg << termcolor::reset << endl;
}

struct TestObjcMethodXrefsComparator {
    bool operator() (const MethodChain *lhs, const MethodChain *rhs) const {
        if (lhs->className != rhs->className) {
            return lhs->className < rhs->className;
        }
        
        if (lhs->methodName != rhs->methodName) {
            return lhs->methodName < rhs->methodName;
        }
        
        return lhs->impAddr < rhs->impAddr;
    }
};

static string testMethodNameFromMethodChain(MethodChain *chain) {
    return chain->prefix + chain->methodName;
}

static bool testOnClass(MethodChain *rootClass, MethodTestSet testSet, map<string, MethodChain *> &sel2chain) {
    bool success = true;
    set<MethodChain *, TestObjcMethodXrefsComparator> rootMethods;
    for (auto it = sel2chain.begin(); it != sel2chain.end(); it++) {
        string &className = it->second->className;
        if (className == rootClass->className) {
            rootMethods.insert(it->second);
        }
    }
    for (MethodChain *method : rootMethods) {
        string methodName = testMethodNameFromMethodChain(method);
        if (testSet.find(methodName) != testSet.end()) {
            vector<pair<string, string>> _tests = testSet[methodName];
            set<pair<string, string>> tests(_tests.begin(), _tests.end());
            for (auto it = method->prevMethods.begin(); it != method->prevMethods.end(); it++) {
                pair<string, string> expr = {it->first->className, testMethodNameFromMethodChain(it->first)};
                tests.erase(expr);
                greenMessage(StringUtils::format("  [+] find %s.%s -> %s.%s", expr.first.c_str(), expr.second.c_str(), method->className.c_str(), methodName.c_str()));
            }
            
            if (tests.empty()) {
                testSet.erase(methodName);
            } else {
                vector<pair<string, string>> __tests(tests.begin(), tests.end());
                testSet[methodName] = __tests;
            }
        }
    }
    if (!testSet.empty()) {
        cout << termcolor::red << "  [-] Error: missing xrefs:" << endl;
        for (auto it = testSet.begin(); it != testSet.end(); it++) {
            for (auto it2 = it->second.begin(); it2 != it->second.end(); it2++) {
                cout << StringUtils::format("    - %s.%s -> %s.%s", it2->first.c_str(), it2->second.c_str(), rootClass->className.c_str(), it->first.c_str());
                cout << endl;
                success = false;
            }
        }
        cout << termcolor::reset;
    }
    return success;
}

bool TestObjcMethodXrefs::start() {
    printf("[*] Test objc_msgSend xrefs\n");
    size_t size = pathconf(".", _PC_PATH_MAX);
    char *buf = (char *)malloc((size_t)size);
    char *path = getcwd(buf, (size_t)size);
    string workDir = string(path);
    free(buf);
    
    string inputPath = StringUtils::path_join(workDir, "iblessing-sample.benchmark_method-xrefs.iblessing.txt");
    printf("  [*] set inputPath as %s\n", inputPath.c_str());
    map<string, MethodChain *> sel2chain = ObjcMethodChainSerializationManager::loadMethodChain(inputPath);
    if (sel2chain.empty()) {
        cout << termcolor::red << "[-] Error: cannot find " << inputPath;
        cout << termcolor::reset << endl;
        return false;
    }
    
    // find the root class and subs
    MethodChain *root = nullptr, *blockSubA = nullptr, *blockSubB = nullptr;
    for (auto it = sel2chain.begin(); it != sel2chain.end(); it++) {
        string &className = it->second->className;
        if (className == "IBSRoot") {
            root = it->second;
        } else if (className == "BlockSubA") {
            blockSubA = it->second;
        } else if (className == "BlockSubB") {
            blockSubB = it->second;
        }
    }
    
    if (!root || !blockSubA || !blockSubB) {
        cout << termcolor::red << "  [-] Error: ";
        cout << StringUtils::format("cannot find IBSRoot %p, or BlockSubA %p, or BlockSubB %p", root, blockSubA, blockSubB);
        cout << termcolor::reset << endl;
        return false;
    }
    
    greenMessage("  [+] Test passed: find all primary classes");
    
    bool success = true;
    
    // test on root
    MethodTestSet rootTestSet{
        {
            "+rootClassMethodCallFromPrimary", {
                {"IBSCallTester", "+testPrimaryCallToRootClassMethodAncestor"}
            }
        },
        {
            "+rootClassMethodCallFromReflection", {
                {"IBSCallTester", "+testReflectionCallToRootClassMethodAncestor"}
            }
        },
        {
            "+rootClassMethodCallFromInstanceClass", {
                {"IBSCallTester", "+testInstanceCallToRootClassMethodAncestor"}
            }
        },
        {
            "+rootClassMethodCallFromBlockArgs", {
                {"iblessing_SubClass", "+sub_0x100005bb4"}
            }
        },
        {
            "-rootInstanceMethodCallFromIvar", {
                {"IBSCallTester", "-testIvarCall"}
            }
        },
        {
            "-rootInstanceMethodCallFromAllocate", {
                {"IBSCallTester", "-testAllocateCall"}
            }
        },
        {
            "-rootInstanceMethodCallFromBlockArgs", {
                {"iblessing_SubClass", "+sub_0x100005bb4"}
            }
        }
    };
    success &= testOnClass(root, rootTestSet, sel2chain);
    
    // test on blockSubA
    MethodTestSet blockSubATestSet{
        {
            "-testAllocateCapture", {
                {"iblessing_SubClass", "+sub_0x10000562c"},
                {"iblessing_SubClass", "+sub_0x1000059e0"}
            }
        },
        {
            "-testCallFromBlockArg", {
                {"iblessing_SubClass", "+sub_0x10000562c"},
                {"iblessing_SubClass", "+sub_0x100005bb4"},
                {"iblessing_SubClass", "+sub_0x100005de4"}
            }
        },
    };
    success &= testOnClass(blockSubA, blockSubATestSet, sel2chain);
    
    // test on blockSubB
    MethodTestSet blockSubBTestSet{
        {
            "-testCallFromblockArg", {
                {"iblessing_SubClass", "+sub_0x100005bb4"},
                {"iblessing_SubClass", "+sub_0x100005de4"},
            }
        },
    };
    success &= testOnClass(blockSubB, blockSubBTestSet, sel2chain);
    
    return success;
}
