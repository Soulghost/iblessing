//
//  IDAObjcMsgXREFGenerator.cpp
//  iblessing
//
//  Created by soulghost on 2020/7/19.
//  Copyright © 2020 soulghost. All rights reserved.
//

#include "IDAObjcMsgXREFGenerator.hpp"
#include <fstream>
#include "../serialization/ObjcMethodChainSerializationManager.hpp"
#include "../vendor/httplib/httplib.h"
#include "../vendor/rapidjson/document.h"
#include "../vendor/rapidjson/document.h"
#include "../vendor/rapidjson/writer.h"
#include "../vendor/rapidjson/stringbuffer.h"
#include "termcolor.h"

using namespace std;
using namespace iblessing;

int IDAObjMsgXREFGenerator::start() {
    cout << "[*] start IDAObjMsgXREFGenerator" << endl;
    
    string scriptsPath = StringUtils::path_join(outputPath, fileName + "_ida_objc_msg_xrefs.iblessing.py");
    ofstream ss(scriptsPath);
    ss.clear();
    
    if (!loadMethodChains()) {
        cout << termcolor::red;
        cout << StringUtils::format("  [!] failed to parse %s\n", inputPath.c_str());
        cout << termcolor::reset << endl;
        return 1;
    }
    
    cout << "  [*] Generating XREF Scripts ..." << endl;
    ss << "def add_objc_xrefs():";
    for (auto it = sel2chain.begin(); it != sel2chain.end(); it++) {
        MethodChain *current = it->second;
        
        // ignore import symbol since IDA can build them
        if (current->impAddr == 0 ||
            current->className == "iblessing_ImportSymbol") {
            continue;
        }
        
        for (auto it = current->prevMethods.begin(); it != current->prevMethods.end(); it++) {
            MethodChain *prev = it->first;
            if (prev->className == "iblessing_ImportSymbol") {
                continue;
            }
            
            uint64_t callerAddr = it->second;
            if (callerAddr == 0) {
                callerAddr = prev->impAddr;
            }
            // add xref(preCallerAddr, cur->impAddr)
            ss << StringUtils::format("\n    ida_xref.add_cref(0x%llx, 0x%llx, XREF_USER)",
                                             callerAddr,
                                             current->impAddr);
        }
    }
    
    ss << "\n\nif __name__ == '__main__':\n";
    ss << "    add_objc_xrefs()\n";
    
    printf("  [*] saved to %s\n", scriptsPath.c_str());
    ss.close();
    return 0;
}

bool IDAObjMsgXREFGenerator::loadMethodChains() {
    sel2chain = ObjcMethodChainSerializationManager::loadMethodChain(inputPath);
    if (sel2chain.empty()) {
        return false;
    }
    
    printf("\t[+] load storage from disk succeeded!\n");
    return true;
}
