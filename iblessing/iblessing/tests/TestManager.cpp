//
//  TestManager.cpp
//  iblessing
//
//  Created by Soulghost on 2020/8/16.
//  Copyright © 2020 soulghost. All rights reserved.
//

#include "TestManager.hpp"
#include "Tester.hpp"
#include "TestObjcMethodXrefs.hpp"

#include <vector>

using namespace std;
using namespace iblessing;

bool TestManager::testAll() {
    bool success = true;
    
    static vector<Tester *> tests{
        new TestObjcMethodXrefs()
    };
    
    for (Tester *test : tests) {
        if (!test->start()) {
            success = false;
            break;
        }
    }
    
    for (Tester *test : tests) {
        delete test;
    }
    return success;
}
