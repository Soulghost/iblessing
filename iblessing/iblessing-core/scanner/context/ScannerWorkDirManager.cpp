//
//  ScannerWorkDirManager.cpp
//  iblessing
//
//  Created by soulghost on 2020/9/25.
//  Copyright © 2020 soulghost. All rights reserved.
//

#include "ScannerWorkDirManager.hpp"
#include <iblessing-core/v2/util/StringUtils.h>

#ifdef IB_PLATFORM_DARWIN
#include <filesystem>
#else
#include <experimental/filesystem>
#endif

#include <sys/stat.h>

using namespace std;
using namespace iblessing;

#ifdef IB_PLATFORM_DARWIN
namespace fs = std::filesystem;
#else
namespace fs = std::experimental::filesystem;
#endif

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

std::vector<std::string> ScannerWorkDirManager::findAllObjectFiles(std::set<std::string> excludeFiles) {
    vector<std::string> files;
    for (auto &p : fs::directory_iterator(workDir)) {
        string fileName = p.path().filename();
        if (excludeFiles.find(fileName) != excludeFiles.end()) {
            continue;;
        }
        
        if (p.path().has_extension() && p.path().extension() == ".o") {
            files.push_back(p.path());
        }
    }
    return files;
}
