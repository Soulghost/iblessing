//
//  ScannerWorkDirManager.cpp
//  iblessing
//
//  Created by soulghost on 2020/9/25.
//  Copyright © 2020 soulghost. All rights reserved.
//

#include "ScannerWorkDirManager.hpp"
#include "StringUtils.h"
#include <experimental/filesystem>
#include <sys/stat.h>

using namespace std;
using namespace iblessing;
namespace fs = std::experimental::filesystem;

ScannerWorkDirManager::ScannerWorkDirManager(string workDir) {
    if (!StringUtils::has_prefix(workDir, "/tmp/")) {
        workDir = "/tmp/";
    }
    
    this->workDir = workDir;
}

string ScannerWorkDirManager::getWorkDir() {
    return this->workDir;
}

int ScannerWorkDirManager::resetWorkDir() {
    if (!cleanFolder() && !createWorkDirIfNeeded()) {
        return 0;
    }
    return 1;
}

int ScannerWorkDirManager::createWorkDirIfNeeded() {
    if (!fs::exists(workDir)) {
        if (mkdir(workDir.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH ) != 0) {
            return 1;
        }
        return 0;
    }
    return 0;
}

int ScannerWorkDirManager::cleanFolder() {
    if (fs::exists(workDir)) {
        if (fs::remove_all(workDir)) {
            return 0;
        } else {
            return 1;
        }
    }
    return 0;
}

int ScannerWorkDirManager::createShadowFile(std::string filePath, char **shadowPathOut /** OUT */) {
    fs::path originPath = filePath;
    
    string fileName = originPath.filename();
    fs::path shadowPath = StringUtils::path_join(workDir, fileName);
    
    try {
        fs::copy(originPath, shadowPath);
        *shadowPathOut = strdup(shadowPath.c_str());
    } catch (fs::filesystem_error e) {
        return 1;
    }
    return 0;
}
