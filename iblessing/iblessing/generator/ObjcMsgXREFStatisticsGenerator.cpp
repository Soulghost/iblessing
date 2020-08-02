//
//  ObjcMsgXREFStatisticsGenerator.cpp
//  iblessing
//
//  Created by soulghost on 2020/7/25.
//  Copyright © 2020 soulghost. All rights reserved.
//

#include "ObjcMsgXREFStatisticsGenerator.hpp"
#include "ObjcMethodChainSerializationManager.hpp"
#include <fstream>
#include "../vendor/httplib/httplib.h"
#include "../vendor/rapidjson/document.h"
#include "../vendor/rapidjson/document.h"
#include "../vendor/rapidjson/writer.h"
#include "../vendor/rapidjson/stringbuffer.h"
#include "termcolor.h"

using namespace std;
using namespace httplib;
using namespace iblessing;

static map<string, MethodChain *> buildCommonChains(map<string, MethodChain *> &orig) {
    map<string, MethodChain *> newChain;
    for (auto it = orig.begin(); it != orig.end(); it++) {
        newChain[it->second->getCompareKey()] = it->second;
    }
    return newChain;
}

int ObjcMsgXREFStatisticsGenerator::start() {
    printf("[*] start ObjcMsgXREFStatisticsGenerator\n");
    
    bool isDiffMode = false;
    map<string, MethodChain *> diffChains = {};
    if (options.find("diff") != options.end()) {
        string diffPath = options["diff"];
        printf("[*] diff with file at %s\n", diffPath.c_str());
        isDiffMode = true;
        diffChains = loadMethodChains(diffPath);
        if (diffChains.empty()) {
            cout << termcolor::red;
            cout << StringUtils::format("  [!] failed to parse file %s to diff chains\n", inputPath.c_str());
            cout << termcolor::reset << endl;
            return 1;
        }
    }
    
    map<string, MethodChain *> currentChains = loadMethodChains(inputPath);
    if (currentChains.empty()) {
        cout << termcolor::red;
        cout << StringUtils::format("  [!] failed to parse file %s to current chains\n", inputPath.c_str());
        cout << termcolor::reset << endl;
        return 1;
    }
    
    if (!isDiffMode) {
        // single mode
        int totalPre = 0;
        int totalPost = 0;
        for (auto it = currentChains.begin(); it != currentChains.end(); it++) {
            MethodChain *chain = it->second;
            totalPre += chain->prevMethods.size();
            totalPost += chain->nextMethods.size();
        }
        cout << "  [*] find ";
        cout << termcolor::green << totalPre << termcolor::reset;
        cout << " pre-refs and ";
        cout << termcolor::green << totalPost << termcolor::reset;
        cout << " post-refs" << endl;
        return 0;
    }
    
    // rebuild by common key
    currentChains = buildCommonChains(currentChains);
    diffChains = buildCommonChains(diffChains);
    
    // diff mode
    // [{chain, {delta-pre, delta-next}}] (delta = cur - differ)
    vector<pair<MethodChain *, pair<int, int>>> prePostChanges;
    map<string, MethodChain *> newMethods;
    map<string, MethodChain *> missingMethods;
    int curTotalPre = 0, curTotalPost = 0;
    int diffTotalPre = 0, diffTotalPost = 0;
    for (auto it = currentChains.begin(); it != currentChains.end(); it++) {
        MethodChain *current = it->second;
        curTotalPre += current->prevMethods.size();
        curTotalPost += current->nextMethods.size();
        
        if (diffChains.find(it->first) == diffChains.end())  {
            // find new methods
            newMethods[it->first] = current;
            continue;
        }
        
        // compare between them
        MethodChain *differ = diffChains[it->first];
        int deltaPre = (int)current->prevMethods.size() - (int)differ->prevMethods.size();
        int deltaPost = (int)current->nextMethods.size() - (int)differ->nextMethods.size();
        if (deltaPre != 0 || deltaPost != 0) {
            prePostChanges.push_back({current, {deltaPre, deltaPost}});
        }
    }
    
    // scan for deleted
    for (auto it = diffChains.begin(); it != diffChains.end(); it++) {
        diffTotalPre += it->second->prevMethods.size();
        diffTotalPost += it->second->nextMethods.size();
        
        if (currentChains.find(it->first) == currentChains.end()) {
            missingMethods[it->first] = it->second;
        }
    }
    
    // output report
    cout << "  [*] find ";
    cout << termcolor::green << curTotalPre << termcolor::reset;
    cout << " pre-refs and ";
    cout << termcolor::green << curTotalPost << termcolor::reset;
    cout << " post-refs in current chains" << endl;
    
    cout << "  [*] find ";
    cout << termcolor::green << diffTotalPre << termcolor::reset;
    cout << " pre-refs and ";
    cout << termcolor::green << diffTotalPost << termcolor::reset;
    cout << " post-refs in diff chains" << endl;
    
    if (prePostChanges.empty()) {
        printf("  [*] no pre-post xref count changes\n");
    } else {
        printf("  [*] pre-post xref count changes:\n");
        printf("      SEL        Pre       Post\n");
        for (pair<MethodChain *, pair<int, int>> &change : prePostChanges) {
            cout << "      " << change.first->getCommonDesc();
            if (change.second.first > 0) {
                cout << termcolor::green << "        ↑";
            } else if (change.second.first < 0) {
                cout << termcolor::red << "        ↓";
            }
            cout << StringUtils::format("%d", change.second.first);
            cout << termcolor::reset << "    ";
            
            if (change.second.second > 0) {
                cout << termcolor::green << "  ↑";
            } else if (change.second.second < 0) {
                cout << termcolor::red << "  ↓";
            }
            cout << StringUtils::format("%d", change.second.second);
            cout << termcolor::reset << endl;
        }
    }
    
    printf("\n");
    
    if (newMethods.empty()) {
        printf("  [*] no new methods\n");
    } else {
        cout << "  [*] find ";
        cout << termcolor::green << newMethods.size() << termcolor::reset;
        cout << " new methods" << endl;
        
//        for (auto it = newMethods.begin(); it != newMethods.end(); it++) {
//            printf("    %s\n", it->second->getCommonDesc().c_str());
//        }
    }
    
    if (missingMethods.empty()) {
        printf("  [*] no missing methods\n");
    } else {
        cout << "  [*] find ";
        cout << termcolor::green << missingMethods.size() << termcolor::reset;
        cout << " missing methods" << endl;
        
//        for (auto it = missingMethods.begin(); it != missingMethods.end(); it++) {
//            printf("    %s\n", it->second->getCommonDesc().c_str());
//        }
    }
    return 0;
}

map<std::string, MethodChain *> ObjcMsgXREFStatisticsGenerator::loadMethodChains(string path) {
    map<std::string, MethodChain *> chains = ObjcMethodChainSerializationManager::loadMethodChain(path);
    return chains;
}
