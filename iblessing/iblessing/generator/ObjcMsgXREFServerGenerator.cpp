//
//  ObjcMsgXREFServerGenerator.cpp
//  iblessing
//
//  Created by soulghost on 2020/7/22.
//  Copyright © 2020 soulghost. All rights reserved.
//

#include "ObjcMsgXREFServerGenerator.hpp"
#include "ObjcMethodChainSerializationManager.hpp"
#include <fstream>
#include "../vendor/httplib/httplib.h"
#include "../vendor/rapidjson/document.h"
#include "../vendor/rapidjson/document.h"
#include "../vendor/rapidjson/writer.h"
#include "../vendor/rapidjson/stringbuffer.h"
#include "termcolor.h"
#include <pthread.h>

using namespace std;
using namespace httplib;
using namespace iblessing;

extern const char *_objc_msg_xref_pageData;

static void findAllPath(MethodChain *current, vector<pair<MethodChain *, uint64_t>> result, vector<vector<pair<MethodChain *, uint64_t>>> &results);
static void findAllPathNext(MethodChain *current, vector<pair<MethodChain *, uint64_t>> result, vector<vector<pair<MethodChain *, uint64_t>>> &results, int maxDepth);

int ObjcMsgXREFServerGenerator::start() {
    cout << "[*] start ObjcMsgXREFServerGenerator" << endl;
    
    if (!loadMethodChains()) {
        cout << termcolor::red;
        cout << StringUtils::format("  [!] failed to parse %s\n", inputPath.c_str());
        cout << termcolor::reset << endl;
        return 1;
    }
    
    string host;
    uint32_t port;
    if (options.find("host") != options.end()) {
        host = options["host"];
    } else {
        host = "127.0.0.1";
    }
    
    if (options.find("port") != options.end()) {
        port = atoi(options["port"].c_str());
    } else {
        port = 2345;
    }
    
    Server svr;
    svr.Get("/", [&](const Request& req, Response& res) {
        res.set_content(_objc_msg_xref_pageData, "text/html");
    });
    svr.Get("/method", [&](const Request& req, Response& res) {
        rapidjson::Document d;
        d.SetObject();
        rapidjson::Document::AllocatorType &allocator = d.GetAllocator();
        
        bool success = true;
        string message = "";
        rapidjson::Value allLinks(rapidjson::kArrayType);
        bool preMode = true;
        if (req.has_param("mode")) {
            string mode = req.get_param_value("mode");
            if (mode == "next") {
                preMode = false;
            }
        }
        
        int maxDepth = 3;
        if (req.has_param("maxDepth")) {
            string maxDepStr = req.get_param_value("maxDepth");
            maxDepth = atoi(maxDepStr.c_str());
        }
        if (req.has_param("sel")) {
            string methodExpr = req.get_param_value("sel");
            MethodChain *chain = sel2chain[methodExpr];
//            printf("[*] try to find pre call chains for %s -> %p\n", methodExpr.c_str(), chain);
            vector<vector<pair<MethodChain *, uint64_t>>> results;
            if (chain) {
                if (preMode) {
                    findAllPath(chain, {{chain, 0}}, results);
                } else {
                    findAllPathNext(chain, {{chain, 0}}, results, maxDepth);
                }
            }
            
            std::set<MethodChain *> duplicateFilter;
            for (vector<pair<MethodChain *, uint64_t>> result : results) {
                if (preMode) {
                    reverse(result.begin(), result.end());
                }
                bool first = true;
                printf("\t");
                
                rapidjson::Value links(rapidjson::kArrayType);
                for (pair<MethodChain *, uint64_t> entry : result) {
                    if (first) {
                        if (duplicateFilter.find(entry.first) != duplicateFilter.end()) {
                            break;
                        }
                        duplicateFilter.insert(entry.first);
                    }
                    
//                    printf("%s%s[%s %s]",
//                           first ? "" : " -> ",
//                           entry.first->prefix.c_str(),
//                           entry.first->className.c_str(),
//                           entry.first->methodName.c_str());
                    {
                        rapidjson::Value stringValue(rapidjson::kStringType);
                        string link = StringUtils::format("%s[%s %s]",
                                                          entry.first->prefix.c_str(),
                                                          entry.first->className.c_str(),
                                                          entry.first->methodName.c_str());
                        stringValue.SetString(link.c_str(), allocator);
                        links.PushBack(stringValue, allocator);
                    }
                    first = false;
                }
//                printf("\n");
                if (links.Size() > 0) {
                    allLinks.PushBack(links, allocator);
                }
            }
        }
        d.AddMember("success", success, allocator);
        d.AddMember("alllinks", allLinks, allocator);
        {
            rapidjson::Value stringValue(rapidjson::kStringType);
            stringValue.SetString(message.c_str(), allocator);
            d.AddMember("message", stringValue, allocator);
        }
        
        rapidjson::StringBuffer strbuf;
        rapidjson::Writer<rapidjson::StringBuffer> writer(strbuf);
        d.Accept(writer);
        res.set_content(strbuf.GetString(), "application/json");
    });
    
    printf("  [*] listening on http://%s:%u\n", host.c_str(), port);
    svr.listen(host.c_str(), port);
    printf("  [*] server closed\n");
    return 0;
}

bool ObjcMsgXREFServerGenerator::loadMethodChains() {
    sel2chain = ObjcMethodChainSerializationManager::loadMethodChain(inputPath);
    if (sel2chain.empty()) {
        return false;
    }
    
    printf("\t[+] load storage from disk succeeded!\n");
    return true;
}

static void findAllPath(MethodChain *current, vector<pair<MethodChain *, uint64_t>> result, vector<vector<pair<MethodChain *, uint64_t>>> &results) {
    if (current->prevMethods.size() == 0) {
        results.push_back(result);
        return;
    }
    
    // works in call-loop
    bool noDeeperCall = true;
    for (auto it = current->prevMethods.begin(); it != current->prevMethods.end(); it++) {
        if (std::find(result.begin(), result.end(), *it) != result.end()) {
            continue;
        }
        result.push_back(*it);
        noDeeperCall = false;
        findAllPath(it->first, result, results);
        result.pop_back();
    }
    
    // if there is a call-loop, it will be cut by return
    // we need to add result to results manully
    if (noDeeperCall) {
        results.push_back(result);
    }
}

static void findAllPathNext(MethodChain *current, vector<pair<MethodChain *, uint64_t>> result, vector<vector<pair<MethodChain *, uint64_t>>> &results, int maxDepth) {
    if (current->nextMethods.size() == 0 || result.size() >= maxDepth) {
        results.push_back(result);
        return;
    }
    for (auto it = current->nextMethods.begin(); it != current->nextMethods.end(); it++) {
        if (std::find(result.begin(), result.end(), *it) != result.end()) {
            continue;
        }
        result.push_back(*it);
        findAllPathNext(it->first, result, results, maxDepth);
        result.pop_back();
    }
}

// minifier
// http://minifycode.com/html-minifier
__attribute__ ((visibility ("hidden")))
const char *_objc_msg_xref_pageData = "<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'><title>iblessing server</title><link rel='stylesheet' href='https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/4.5.0/css/bootstrap.min.css'></link></head><body><h3 style='margin-top: 8px; margin-left: 16px;'>iblessing objc_msgSend XREF Search Center</h3><div style='margin-top: 8px; margin-left: 16px; margin-right: 16px;'><div class='input-group mb-3'> <input id='input' type='text' class='form-control' placeholder='Please input an objc-method, such as -[foo bar]' aria-label='Objc Method' aria-describedby='basic-addon2'><div class='input-group-append'> <button onclick='onSearch()' class='btn btn-outline-secondary' type='button'>Search</button></div></div></div><div style='margin-left: 16px;' id='anchor'></div> <script src='https://cdnjs.cloudflare.com/ajax/libs/d3/5.16.0/d3.min.js'></script> <script>function onSearch(){document.getElementById('anchor').innerHTML='';let value=document.getElementById('input').value;if(!value){alert('Error: please input a method');return;} fetch('/method?mode=pre&sel='+encodeURIComponent(value)).then(res=>res.json()).then(responseData=>{if(!responseData.success){alert('Error: '+responseData.message);return;} let links=responseData.alllinks;if(links.length===0){document.getElementById('anchor').innerText='No results for '+value;return;} let data=produceDataFromLinks(links);drawChartByData(data);}).catch(e=>{console.log('error',e);alert('Error: '+JSON.stringify(e));});} function produceDataFromLinks(links){let data={'name':'*','children':[]};links.forEach(link=>{let subdata=undefined;link.forEach(item=>{if(!subdata){subdata={'name':item,'children':[]};data.children.push(subdata);}else{let child={'name':item,'children':[]};subdata.children.push(child);subdata=child;}});});return data;} function drawChartByData(data){let i=0;var root=d3.hierarchy(data).eachBefore(d=>d.index=i++);const nodeSize=17;const nodes=root.descendants();const svg=d3.select('#anchor').append('svg').attr('viewBox',[-nodeSize/2,-nodeSize*3/2,1000,(nodes.length+1)*nodeSize]).attr('font-family','sans-serif').attr('font-size',10).style('overflow','visible');const link=svg.append('g').attr('fill','none').attr('stroke','#999').selectAll('path').data(root.links()).join('path').attr('d',d=>`M${d.source.depth*nodeSize},${d.source.index*nodeSize} V${d.target.index*nodeSize} h${nodeSize}`);const node=svg.append('g').selectAll('g').data(nodes).join('g').attr('transform',d=>`translate(0,${d.index*nodeSize})`);node.append('circle').attr('cx',d=>d.depth*nodeSize).attr('r',2.5).attr('fill',d=>d.children?null:'#999');node.append('text').attr('dy','0.32em').attr('x',d=>d.depth*nodeSize+6).text(d=>d.data.name);node.append('title').text(d=>d.ancestors().reverse().map(d=>d.data.name).join('/'));}</script> </body></html>";
