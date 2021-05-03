//
//  IDASymbolicScriptGenerator.cpp
//  iblessing
//
//  Created by Soulghost on 2020/8/15.
//  Copyright © 2020 soulghost. All rights reserved.
//

#include "IDASymbolicScriptGenerator.hpp"
#include <fstream>

#include <iblessing-core/v2/util/termcolor.h>
#include <iblessing-core/v2/util/StringUtils.h>

using namespace std;
using namespace iblessing;

int IDASymbolicScriptGenerator::start() {
    cout << "[*] start IDASymbolicScriptGenerator" << endl;
    
    string mode;
    char delimiter = 0;
    int addrIdx = -1, nameIdx = -1;
    if (options.find("mode") != options.end()) {
        mode = options["mode"];
    } else {
        if (options.find("addrIdx") != options.end()) {
            addrIdx = atoi(options["addrIdx"].c_str());
        }
        if (options.find("nameIdx") != options.end()) {
            nameIdx = atoi(options["nameIdx"].c_str());
        }
        if (options.find("delimiter") != options.end()) {
            delimiter = options["delimiter"][0];
        }
    }
    
    if (mode.length() > 0) {
        bool validMode = false;
        if (mode == "jtool2") {
            delimiter = '|';
            addrIdx = 0;
            nameIdx = 1;
            validMode = true;
        }
        
        if (validMode) {
            printf("  [+] setup %s mode, delimiter=%c, addrIdx=%d, nameIdx=%d\n", mode.c_str(), delimiter, addrIdx, nameIdx);
        } else {
            cout << termcolor::red << "[-] invalid mode: " << mode << ", valid modes are: jtool2";
            cout << termcolor::reset << endl;
            return 1;
        }
    }

    if (delimiter == 0 || addrIdx == -1 || nameIdx == -1) {
        cout << termcolor::red << StringUtils::format("[-] invalid input, check delimiter %c, addrIdx %d, nameIdx %d", delimiter, addrIdx, nameIdx);
        cout << termcolor::reset << endl;
        return 1;
    }
    
    printf("  [+] using delimiter=%c, addrIdx=%d, nameIdx=%d\n", delimiter, addrIdx, nameIdx);
    
    ifstream file(inputPath);
    if (file.fail()) {
        cout << termcolor::red;
        cout << StringUtils::format("  [!] cannot open input file %s\n", inputPath.c_str());
        cout << termcolor::reset << endl;
        return 1;
    }
    
    string scriptPath = StringUtils::path_join(outputPath, fileName + "_ida_symbolic.py");
    ofstream ss(scriptPath);
    if (!ss.is_open()) {
        cout << termcolor::red;
        cout << StringUtils::format("  [!] cannot open output file %s\n", scriptPath.c_str());
        cout << termcolor::reset << endl;
        return 1;
    }
    ss.clear();
    
    ss << "# -*- coding: utf-8 -*-\n";
    ss << "# Powered by iblessing (https://github.com/Soulghost/iblessing)\n\n";
    ss << "import idc\n\n";
    
    ss << "def ib_setname(addr, name):\n";
    ss << "  orig_name = ida_name.get_name(addr)\n";
    ss << "  if len(orig_name) == 0 or orig_name.startswith('sub_'):\n";
    ss << "    idc.create_insn(addr)\n";
    ss << "    ida_funcs.add_func(addr)\n";
    ss << "    idc.set_name(addr, name, idc.SN_NOWARN)\n";
    ss << "\n\n";
    
    ss << "def ib_symbolic():\n";
    string line;
    int maxIdx = std::max(addrIdx, nameIdx);
    while (getline(file, line)) {
        vector<string> parts = StringUtils::split(line, delimiter);
        if (maxIdx >= parts.size()) {
            printf("  [-] bad line %s\n", line.c_str());
            continue;
        }
        
        string name = parts[nameIdx];
        string addr = parts[addrIdx];
        ss << "  ib_setname(" << addr << ",\"" << name << "\")\n";
    }
    ss << "\n";
    ss << "if __name__ == \"__main__\":\n";
    ss << "  ib_symbolic()\n";
    ss << "\n";
    printf("  [*] saved to %s\n", scriptPath.c_str());
    return 0;
}
