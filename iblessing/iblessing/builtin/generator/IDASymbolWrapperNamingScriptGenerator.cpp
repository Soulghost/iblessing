//
//  IDASymbolWrapperNamingScriptGenerator.cpp
//  iblessing
//
//  Created by soulghost on 2020/7/30.
//  Copyright © 2020 soulghost. All rights reserved.
//

#include "IDASymbolWrapperNamingScriptGenerator.hpp"
#include "SymbolWrapperSerializationManager.hpp"
#include <fstream>
#include <iblessing-core/v2/util/termcolor.h>

using namespace std;
using namespace iblessing;

int IDASymbolWrapperNamingScriptGenerator::start() {
    cout << "[*] start IDAObjMsgXREFGenerator" << endl;
    
    string scriptsPath = StringUtils::path_join(outputPath, fileName + "_ida_symbol_wrapper_naming.iblessing.py");
    ofstream ss(scriptsPath);
    if (!ss.is_open()) {
        cout << termcolor::red;
        cout << StringUtils::format("  [!] cannot open output file %s\n", scriptsPath.c_str());
        cout << termcolor::reset << endl;
        return 1;
    }
    ss.clear();
    
    std::vector<SymbolWrapperInfo> wrapperInfos = SymbolWrapperSerializationManager::loadWrapperInfosFromReport(inputPath);
    if (wrapperInfos.size() == 0) {
        cout << termcolor::red;
        cout << StringUtils::format("  [!] failed to parse %s\n", inputPath.c_str());
        cout << termcolor::reset << endl;
        return 1;
    }
    
    cout << "  [*] Generating Naming Scripts ..." << endl;
    ss << "def namingWrappers():";
    for (SymbolWrapperInfo &info : wrapperInfos) {
        string name = info.name;
        string proto = info.prototype;
        uint64_t addr = info.address;
        ss << StringUtils::format("\n    idc.set_name(0x%llx, '%s', ida_name.SN_FORCE)",
                                  addr, name.c_str());
        
        ss << StringUtils::format("\n    idc.apply_type(0x%llx, idc.parse_decl('%s', idc.PT_SILENT))", addr, proto.c_str());
    }
    
    ss << "\n\nif __name__ == '__main__':\n";
    ss << "    namingWrappers()\n";
    
    printf("  [*] saved to %s\n", scriptsPath.c_str());
    ss.close();
    return 0;
}
