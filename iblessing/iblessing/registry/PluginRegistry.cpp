//
//  PluginRegistry.cpp
//  iblessing
//
//  Created by Soulghost on 2021/5/5.
//  Copyright © 2021 soulghost. All rights reserved.
//

#include "PluginRegistry.h"
#include <cstdio>
#include <iblessing-core/v2/util/StringUtils.h>
#include <iblessing-core/v2/util/termcolor.h>
#ifdef IB_PLATFORM_DARWIN
#include <filesystem>
#else
#include <experimental/filesystem>
#endif

#include <dlfcn.h>
#include <cassert>

#ifdef IB_PLATFORM_DARWIN
namespace fs = std::filesystem;
#else
namespace fs = std::experimental::filesystem;
#endif

using namespace std;

void registerPlugins() {
    size_t size = pathconf(".", _PC_PATH_MAX);
    char *buf = (char *)malloc((size_t)size);
    char *path = getcwd(buf, (size_t)size);
    string currentPath = string(path);
    free(buf);
    
    string pluginsPath = StringUtils::path_join(currentPath, "Plugins");
    if (!fs::exists(pluginsPath)) {
        return;
    }
    
    printf("[+] scan and load plugins in %s\n", pluginsPath.c_str());
    vector<string> plugins;
#ifdef IB_PLATFORM_DARWIN
    string pluginExt = ".dylib";
#else
    string pluginExt = ".so";
#endif
    for (auto &p : fs::directory_iterator(pluginsPath)) {
        string fileName = p.path().filename();
        if (!StringUtils::has_suffix(fileName, pluginExt)) {
            continue;
        }
        
        plugins.push_back(StringUtils::path_join(pluginsPath, fileName));
    }
    
    for (string plugin : plugins) {
        void *handle = dlopen(plugin.c_str(), RTLD_NOW);
        if (handle) {
            cout << termcolor::bold << termcolor::yellow;
            cout << "[+] load plugin at " + plugin;
            cout << termcolor::reset << endl;
        } else {
            cout << termcolor::red;
            cout << "[-] failed to load plugin at " + plugin;
            cout << ", " << dlerror() << termcolor::reset << endl;
            assert(false);
        }
    }
}
