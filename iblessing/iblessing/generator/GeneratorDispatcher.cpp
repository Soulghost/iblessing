//
//  GeneratorDispatcher.cpp
//  iblessing
//
//  Created by soulghost on 2020/7/19.
//  Copyright © 2020 soulghost. All rights reserved.
//

#include "GeneratorDispatcher.hpp"
#include <fstream>
#include "termcolor.h"
#include "StringUtils.h"

#include "IDAObjcMsgXREFGenerator.hpp"
#include "ObjcMsgXREFServerGenerator.hpp"
#include "ObjcMsgXREFStatisticsGenerator.hpp"
#include "IDASymbolWrapperNamingScriptGenerator.hpp"

using namespace std;
using namespace iblessing;

static bool fexists(string filename) {
    std::ifstream ifile(filename);
    return (bool)ifile;
}

GeneratorDispatcher::GeneratorDispatcher() {
    registerGenerator("ida-objc-msg-xref", []() {
        return new IDAObjMsgXREFGenerator("ida-objc-msg-xref", "generator ida scripts to add objc_msgSend xrefs from objc-msg-xref scanner's report");
    });
    
    registerGenerator("objc-msg-xref-server", []() {
        return new ObjcMsgXREFServerGenerator("objc-msg-xref-server", "server to query objc-msg xrefs");
    });
    
    registerGenerator("objc-msg-xref-statistic", []() {
        return new ObjcMsgXREFStatisticsGenerator("objc-msg-xref-statistic", "statistics among objc-msg-send reports");
    });
    
    registerGenerator("ida-symbol-wrapper-naming", []() {
        return new IDASymbolWrapperNamingScriptGenerator("ida-symbol-wrapper-naming", "generate ida symbol naming and prototype changing script from symbol-wrapper's report");
    });
}

vector<Generator *> GeneratorDispatcher::allGenerators() {
    vector<Generator *> generators;
    for (auto it = generatorMap.begin(); it != generatorMap.end(); it++) {
        generators.push_back(it->second());
    }
    return generators;
}

void GeneratorDispatcher::registerGenerator(string generatorId, GeneratorProvider provider) {
    generatorMap[generatorId] = provider;
}

int GeneratorDispatcher::start(std::string generatorId, std::map<std::string, std::string> options, std::string inputPath, std::string outputPath) {
    Generator *g = prepareForGenerator(generatorId, options, inputPath, outputPath);
    if (!g) {
        return 1;
    }
    
    int ret = g->start();
    delete g;
    return ret;
}


Generator* GeneratorDispatcher::prepareForGenerator(std::string generatorId, std::map<std::string, std::string> options, std::string inputPath, std::string outputPath) {
    // input validate
    if (!fexists(inputPath)) {
        cout << termcolor::red << "Error: input file " << inputPath << " not exist" << termcolor::reset << endl;
    }
    
    // scanner validate
    // FIXME: hardcode
    if (generatorMap.find(generatorId) == generatorMap.end()) {
        cout << termcolor::red << "Error: cannot find scanner " << generatorId << endl;
        return nullptr;
    }
    
    // here we go
    Generator *g = generatorMap[generatorId]();
    
    // bind options
    g->inputPath = inputPath;
    vector<string> pathComponents = StringUtils::split(inputPath, '/');
    g->fileName = pathComponents[pathComponents.size() - 1];
    g->outputPath = outputPath;
    g->options = options;
    return g;
}
