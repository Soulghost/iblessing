//
//  ScannerWorkDirManager.hpp
//  iblessing
//
//  Created by soulghost on 2020/9/25.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef ScannerWorkDirManager_hpp
#define ScannerWorkDirManager_hpp

#include <iblessing-core/infra/Object.hpp>
#include <vector>
#include <set>

NS_IB_BEGIN

class ScannerWorkDirManager {
public:
    std::string getWorkDir();
    ScannerWorkDirManager(std::string workDir);
    int resetWorkDir();
    int createWorkDirIfNeeded();
    int cleanFolder();
    int createShadowFile(std::string filePath, char **shadowPathOut /** OUT */);
    std::vector<std::string> findAllObjectFiles(std::set<std::string> excludeFiles = {});
    
private:
    std::string workDir;
};

NS_IB_END


#endif /* ScannerWorkDirManager_hpp */
