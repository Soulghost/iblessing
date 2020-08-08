//
//  ScannerDispatcher.hpp
//  iblessing
//
//  Created by soulghost on 2020/6/28.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef ScannerDispatcher_hpp
#define ScannerDispatcher_hpp

#include <map>
#include <vector>
#include <string>
#include "Object.hpp"
#include "Scanner.hpp"

NS_IB_BEGIN;

typedef std::function<Scanner* (void)> ScannerProvider;

class ScannerDispatcher {
public:
    int jobs;
    
    ScannerDispatcher();
    void registerScanner(std::string scannerId, ScannerProvider provider);
    int start(std::string scannerId, std::map<std::string, std::string> options, std::string inputPath, std::string outputPath);
    Scanner* prepareForScanner(std::string scannerId, std::map<std::string, std::string> options, std::string inputPath, std::string outputPath, ScannerDisassemblyDriver *driver = nullptr);
    std::vector<Scanner *> allScanners();
    
private:
    std::map<std::string, ScannerProvider> scannerMap;
};

NS_IB_END;

#endif /* ScannerDispatcher_hpp */
