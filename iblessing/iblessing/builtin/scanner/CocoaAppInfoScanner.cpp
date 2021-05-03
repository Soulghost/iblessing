//
//  CocoaAppInfoScanner.cpp
//  iblessing
//
//  Created by soulghost on 2020/8/10.
//  Copyright © 2020 soulghost. All rights reserved.
//

#include "CocoaAppInfoScanner.hpp"
#include <iblessing-core/v2/util/StringUtils.h>
#include <iblessing-core/v2/util/termcolor.h>
#include <sstream>
#include <dirent.h>
#include <vector>

using namespace std;
using namespace iblessing;

int CocoaAppInfoScanner::start() {
    cout << "[*] start Cocoa App Info Scanner" << endl;
    
    string bundlePath = inputPath;
    string outputFilePath;
    string infoName;
    if (options.find("infoName") != options.end()) {
        infoName = options["infoName"];
        if (!StringUtils::has_suffix(infoName, ".plist")) {
            infoName = infoName + ".plist";
        }
        printf("  [*] specific info.plist name to %s", infoName.c_str());
    }
    
    outputFilePath = StringUtils::path_join(outputPath, fileName + "_info.iblessing.txt");
    stringstream report;
    
    // list files
    DIR *dirp = opendir(bundlePath.c_str());
    if (dirp == NULL) {
        cout << termcolor::red;
        cout << "[-] error: file not exist at path " << bundlePath;
        cout << termcolor::reset << endl;
        return 1;
    }
    
    struct dirent *dp;
    vector<string> plistFiles;
    string infoPath;
    if (infoName.length() == 0) {
        bool findDefaultInfoFile = false;
        while ((dp = readdir(dirp)) != NULL) {
            string fileName = string(dp->d_name);
            if (StringUtils::has_suffix(fileName, ".plist")) {
                plistFiles.push_back(fileName);
                if (fileName == "Info.plist") {
                    findDefaultInfoFile = true;
                }
            }
        }
        closedir(dirp);
        
        if (findDefaultInfoFile) {
            cout << termcolor::white;
            cout << "[+] find default plist file Info.plist!";
            cout << termcolor::reset << endl;
            infoPath = StringUtils::path_join(bundlePath, "Info.plist");
        }
    } else {
        infoPath = StringUtils::path_join(bundlePath, infoName);
    }
    return 0;
}
