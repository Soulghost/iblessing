//
//  AppInfoScanner.cpp
//  iblessing
//
//  Created by soulghost on 2020/7/19.
//  Copyright © 2020 soulghost. All rights reserved.
//

#import <Foundation/Foundation.h>
#include "AppInfoScanner.hpp"
#include <iblessing-core/v2/util/termcolor.h>
#include <iblessing-core/v2/util/StringUtils.h>
#include <iblessing-core/scanner/dispatcher/ScannerDispatcher.hpp>
#include <dirent.h>
#include <vector>
#include <array>

using namespace std;
using namespace iblessing;

__attribute__((constructor))
static void registry() {
    ScannerDispatcher::getInstance()->registerScanner("app-info", []() {
        return new AppInfoScanner("app-info", "extract app infos");
    });
}

int AppInfoScanner::start() {
    cout << "[*] start App Info Scanner" << endl;
    
    string bundlePath = inputPath;
    string outputFilePath;
    string infoName;
    bool privacyScan = false;
    if (options.find("infoName") != options.end()) {
        infoName = options["infoName"];
        if (!StringUtils::has_suffix(infoName, ".plist")) {
            infoName = infoName + ".plist";
        }
        printf("  [*] specific info.plist name to %s", infoName.c_str());
    }
    
    if (options.find("privacy") != options.end()){
        string temp = options["privacy"];
        if (!temp.compare("true")){
            privacyScan = true;
        }
    }
    
    outputFilePath = StringUtils::path_join(outputPath, fileName + "_info.iblessing.txt");
    NSMutableString *finalReport = @"iblessing app info report".mutableCopy;
    
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
    
    NSDictionary *infoPlist = [NSDictionary dictionaryWithContentsOfFile:[NSString stringWithUTF8String:infoPath.c_str()]];
    if (!infoPlist) {
        cout << termcolor::yellow;
        cout << "[-] warn: cannot find info.plist, try to specific it by -d 'infoName=<info.plist>'";
        cout << termcolor::reset << endl;
        return 1;
    }
    
    NSMutableSet<NSString *> *deepLinks = [NSMutableSet set];
    NSArray *urlTypes = infoPlist[@"CFBundleURLTypes"];
    NSDictionary *httpsConfigs = infoPlist[@"NSAppTransportSecurity"];
    NSDictionary *appCallOutSchemes = infoPlist[@"LSApplicationQueriesSchemes"];
    NSString *bundleId = infoPlist[@"CFBundleIdentifier"];
    NSString *bundleName = infoPlist[@"CFBundleName"];
    NSString *displayName = infoPlist[@"CFBundleDisplayName"] ?: bundleName;
    NSString *version = infoPlist[@"CFBundleShortVersionString"];
    NSString *buildVersion = infoPlist[@"BuildMachineOSBuild"];
    NSString *binaryName = infoPlist[@"CFBundleExecutable"];
    
    NSString *versionMessage = [NSString stringWithFormat:@"Name: %@(%@)\nVersion: %@(%@)\nExecutableName: %@", displayName, bundleName, version, buildVersion, binaryName];
    cout << "[*] find version info: ";
    cout << [versionMessage UTF8String];
    cout << endl;
    [finalReport appendFormat:@"\nAppInfo: %@", versionMessage];
    
    if (bundleId) {
        cout << "[*] Bundle Identifier: ";
        cout << [bundleId UTF8String];
        cout << endl;
        [finalReport appendFormat:@"\nBundle Identifier: %@", bundleId];
    }
    
    if(privacyScan) {
        int cnt = 0;
        NSMutableSet<NSString *> *privacy = [NSMutableSet set];
        map<string, string>::iterator iter;
        iter = PrivacyMap.begin();
        
        cout << termcolor::yellow;
        cout << "[+] app privacy request scan :";
        cout << termcolor::reset << endl;
        
        while(iter != PrivacyMap.end()){
            NSString *cur = infoPlist[[NSString stringWithCString:iter->first.c_str() encoding:[NSString defaultCStringEncoding]]];
            if(cur){
                cout << " |--";
                cout << termcolor::red;
                cout << iter->second;
                cout << termcolor::reset << endl;
                cout << "   |-- description : " << [cur UTF8String] << endl;
                cnt += 1;
                [privacy addObject: [NSString stringWithCString:iter->first.c_str() encoding:[NSString defaultCStringEncoding]]];
            }
            iter++;
        }
        
        if (cnt > 0){
            [finalReport appendFormat:@"\nPrivacy request count : %d", cnt];
            for (NSString *item : privacy) {
                [finalReport appendFormat:@"\n - %@", item];
            }
        }
    }
    
    if (httpsConfigs) {
        BOOL allowHTTP = [httpsConfigs[@"NSAllowsArbitraryLoads"] boolValue];
        if (allowHTTP) {
            cout << termcolor::yellow;
            cout << "[*] the app allows HTTP requests";
            [finalReport appendFormat:@"\n[*] the app allows HTTP requests"];
        }
        
        NSDictionary *exceptionDomains = httpsConfigs[@"NSExceptionDomains"];
        if (!exceptionDomains) {
            cout << " **without** exception domains!";
            cout << termcolor::reset << endl;
            [finalReport appendFormat:@" **without** exception domains!"];
        } else {
            cout << " with some exception domains, they are:";
            cout << termcolor::reset << endl;
            [finalReport appendFormat:@" with some exception domains, they are:\n"];
            NSArray *domains = exceptionDomains.allKeys;
            string padding = " |-- ";
            for (NSString *domain : domains) {
                cout << padding << StringUtils::format("%-24s", domain.UTF8String);
                [finalReport appendFormat:@"- %-24s", domain.UTF8String];
                
                NSDictionary *configs = exceptionDomains[domain];
                BOOL includeSubdomains = [configs[@"NSIncludesSubdomains"] boolValue];
                BOOL allowHTTP = [configs[@"NSThirdPartyExceptionAllowsInsecureHTTPLoads"] boolValue];
                cout << " (subdomains: ";
                [finalReport appendFormat:@" (subdomains: "];
                
                if (includeSubdomains) {
                    cout << termcolor::green << "Y" << termcolor::reset;
                    [finalReport appendFormat:@"Y"];
                } else {
                    cout << termcolor::red << "N" << termcolor::reset;
                    [finalReport appendFormat:@"N"];
                }
                cout << ", allowHTTP: ";
                [finalReport appendFormat:@", allowHTTP: "];
                if (allowHTTP) {
                    cout << termcolor::green << "Y" << termcolor::reset;
                    [finalReport appendFormat:@"Y"];
                } else {
                    cout << termcolor::red << "N" << termcolor::reset;
                    [finalReport appendFormat:@"N"];
                }
                cout << ")";
                cout << termcolor::reset << endl;
                [finalReport appendFormat:@")\n"];
            }
        }
    }
    
    if (urlTypes) {
        for (NSDictionary *urlType : urlTypes) {
            NSArray *schemes = urlType[@"CFBundleURLSchemes"];
            [deepLinks addObjectsFromArray:schemes];
        }
        if (deepLinks.count > 0) {
            cout << termcolor::green;
            cout << "[+] find app deeplinks";
            cout << termcolor::reset << endl;
            [finalReport appendFormat:@"\n[+] find app deeplinks"];
            string padding = " |-- ";
            for (NSString *deeplink in deepLinks) {
                cout << padding << deeplink.UTF8String << "://" << endl;
                [finalReport appendFormat:@"\n- %@://", deeplink];
            }
        }
    }
    
    if (appCallOutSchemes.count > 0) {
        cout << termcolor::green;
        cout << "[*] find app callout whitelist";
        cout << termcolor::reset << endl;
        [finalReport appendFormat:@"\n\n[*] find app callout whitelist"];
        string padding = " |-- ";
        for (NSString *scheme in appCallOutSchemes) {
            cout << padding << scheme.UTF8String << "://" << endl;
            [finalReport appendFormat:@"\n- %@://", scheme];
        }
    }
    
    string binaryPath = StringUtils::path_join(bundlePath, binaryName.UTF8String);
    string command = "/usr/bin/strings " + binaryPath;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(command.c_str(), "r"), pclose);
    string stringsInBinary;
    if (pipe) {
        std::array<char, 128> buffer;
        while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
            stringsInBinary += buffer.data();
        }
    }
    
    NSString *allStringSeq = [[NSString alloc] initWithUTF8String:stringsInBinary.c_str()];
    NSArray *allStrings = [allStringSeq componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]];
    cout << "[+] find " << termcolor::green << allStrings.count << termcolor::reset;
    cout << " string literals in binary" << endl;
    [finalReport appendFormat:@"\n\n[+] find %@ string literals in binary", @(allStrings.count)];
    
    NSMutableSet *commonURLs = [NSMutableSet set];
    NSMutableSet *otherDeepLinkURLs = [NSMutableSet set];
    NSMutableSet *selfDeepLinkURLs = [NSMutableSet set];
    printf("[*] process with string literals, this maybe take some time\n");
    for (NSInteger i = 0; i < allStrings.count; i++) {
        NSString *stringLiteral = allStrings[i];
        NSRegularExpression *regexp = [NSRegularExpression regularExpressionWithPattern:@"^[a-zA-Z][a-zA-Z0-9]*://" options:NSRegularExpressionCaseInsensitive error:nil];
        NSArray<NSTextCheckingResult *> *results = [regexp matchesInString:stringLiteral options:0 range:NSMakeRange(0, stringLiteral.length)];
        if (results.count > 0) {
            if ([stringLiteral hasPrefix:@"http"] ||
                [stringLiteral hasPrefix:@"https"]) {
                [commonURLs addObject:stringLiteral];
            } else {
                // find self deeplinks
                NSString *scheme = [stringLiteral componentsSeparatedByString:@"://"][0];
                if ([deepLinks containsObject:scheme]) {
                    [selfDeepLinkURLs addObject:stringLiteral];
                } else {
                    [otherDeepLinkURLs addObject:stringLiteral];
                }
            }
        }
    }
    
    if (selfDeepLinkURLs.count > 0) {
        cout << termcolor::yellow;
        cout << "[+] find self deeplinks URLs:";
        cout << termcolor::reset << endl;
        [finalReport appendFormat:@"\n[+] self deeplinks URLs:"];
        string padding = " |-- ";
        for (NSString *deeplinkURL in selfDeepLinkURLs) {
            cout << padding << deeplinkURL.UTF8String << endl;
            [finalReport appendFormat:@"\n- %@", deeplinkURL];
        }
    }
    
    if (otherDeepLinkURLs.count > 0) {
        cout << termcolor::yellow;
        cout << "[+] find other deeplinks URLs:";
        cout << termcolor::reset << endl;
        [finalReport appendFormat:@"\n\n[+] other deeplinks URLs:"];
        string padding = " |-- ";
        for (NSString *deeplinkURL in otherDeepLinkURLs) {
            cout << padding << deeplinkURL.UTF8String << endl;
            [finalReport appendFormat:@"\n- %@", deeplinkURL];
        }
    }
    
    if (commonURLs.count > 0) {
        bool writeToPath = false;
        if (outputFilePath.length() > 0) {
            NSString *outputFileFinal = [[NSString alloc] initWithCString:outputFilePath.c_str() encoding:NSUTF8StringEncoding];
            printf("[*] write report to path %s\n", outputFileFinal.UTF8String);
            [finalReport appendFormat:@"\n\n[+] common urls:\n"];
            [finalReport appendString:[[commonURLs allObjects] componentsJoinedByString:@"\n"]];
            
            NSError *error = nil;
            [finalReport writeToFile:outputFileFinal atomically:YES encoding:NSUTF8StringEncoding error:&error];
            if (error) {
                cout << termcolor::yellow;
                cout << "[+] warn: write to file error " << error.description.UTF8String;
                cout << termcolor::reset << endl;
            } else {
                writeToPath = true;
            }
        }
        
        if (!writeToPath) {
            NSString *commonURLFile = [NSString stringWithFormat:@"%@_urls_%@.txt", binaryName, @([NSDate date].timeIntervalSince1970)];
            NSString *writePath = [@"/tmp" stringByAppendingPathComponent:commonURLFile];
            cout << termcolor::yellow;
            cout << "[+] dump common urls to " << writePath.UTF8String;
            cout << termcolor::reset << endl;
            [[[commonURLs allObjects] componentsJoinedByString:@"\n"] writeToFile:writePath atomically:YES encoding:NSUTF8StringEncoding error:nil];
        }
    }
    return 0;
}
