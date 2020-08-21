           ☠️
           ██╗██████╗ ██╗     ███████╗███████╗███████╗██╗███╗   ██╗ ██████╗
           ██║██╔══██╗██║     ██╔════╝██╔════╝██╔════╝██║████╗  ██║██╔════╝
           ██║██████╔╝██║     █████╗  ███████╗███████╗██║██╔██╗ ██║██║  ███╗
           ██║██╔══██╗██║     ██╔══╝  ╚════██║╚════██║██║██║╚██╗██║██║   ██║
           ██║██████╔╝███████╗███████╗███████║███████║██║██║ ╚████║╚██████╔╝
           ╚═╝╚═════╝ ╚══════╝╚══════╝╚══════╝╚══════╝╚═╝╚═╝  ╚═══╝ ╚═════╝

[![Build Status](https://travis-ci.org/aquynh/capstone.svg?branch=master)](https://travis-ci.org/Soulghost/iblessing)
[![Releases](https://img.shields.io/github/v/release/Soulghost/iblessing?include_prereleases)](https://github.com/Soulghost/iblessing/releases)

# iblessing
- `iblessing` is an iOS security exploiting toolkit, it mainly includes **application information collection**, **static analysis** and **dynamic analysis**.
- `iblessing` is based on [unicorn engine](https://github.com/unicorn-engine/unicorn) and [capstone engine](https://github.com/aquynh/capstone).

# Features
- [x] 🔥 Cross-platform: Tested on macOS and Ubuntu.
- [x] iOS App static info extract, including metadata, deeplinks, urls, etc.
- [x] Mach-O parser and dyld symbol bind simulator
- [x] Objective-C class realizing and parsing
- [x] Scanners making dynamic analysis for arm64 assembly code and find key information or attack surface
- [x] Scanners using unicorn to partially simulate Mach-O arm64 code execution and find some features
- [x] Generators that can provide secondary processing on scanner's report to start a query server, or generate script for IDA

- Super objc_msgSend xrefs scanner 😄
    - [x] objc methods and subs (such as blocks) emulation to generate xrefs like flare-emu
    - [x] objc function wrapper detect and ida usercall generate
    - [x] objc_msgSend sub functions analysis
    - [x] objc block to objc_msgSend xrefs in args and capture list
    - [x] report format including json, etc.
    
- [ ] Diagnostic logs
- [ ] Tests
- [ ] More flexible scanner infrastructure for new scanner plugins
- [ ] Swift class and method parsing
- [ ] More scanners and generators
- [ ] Cross-platform

# Support 
In case you need support regarding iblessing or anything associated with it, you can:
- create an issue and provide necessary information
- contact [Sou1gh0st](https://twitter.com/Sou1gh0st) on Twitter 
- send mail to xiuyutong1994#163.com 
- send mail to xiuyutong1994#gmail.com

# Changelog
- 2020.08.11 - Now iblessing is a cross-platform tool, support both macOS and Linux 😆
- 2020.08.08 - Improve objc_msgSend xref scanner, add sub xref supoort, including block arguments and capture list
- 2020.07.30 - Improve symbol-wrapper scanner, and add ida scripts for symbol wrapper rename and prototype modification
- 2020.07.21 - First release 

# Get started
⚠️⚠️⚠️ **Sometimes unicorn will crash on start when doing huge memory mapping, you can try to run it again, if it still can't work, please contact me or create an issue, thanks.**
1. You can download the [pre-released iblessing binary](https://github.com/Soulghost/iblessing/releases) and enjoy it.
2. run chmod +x for the binary
3. For more tutorails, please check the [Documentation & Help](https://github.com/Soulghost/iblessing#documentation--help) below.

# How to Build
## CMake
- Platform: macOS, Linux

To get started compiling iblessing, please follow the steps below:
```
git clone --recursive -j4 https://github.com/Soulghost/iblessing
cd iblessing
./compile-cmake.sh
```

## XcodeBuild
- Platform: macOS

To get started compiling iblessing, please follow the steps below:
```
git clone --recursive -j4 https://github.com/Soulghost/iblessing
cd iblessing
./compile.sh
```

## Shortcuts
- [Basic Concepts](https://github.com/Soulghost/iblessing#basic-concepts)
- Scanners
  - [Scan for AppInfos](https://github.com/Soulghost/iblessing#scan-for-appinfos)
  - [Scan for Class XREFs](https://github.com/Soulghost/iblessing#scan-for-class-xrefs)
  - [Scan for All objc_msgSend XREFs](https://github.com/Soulghost/iblessing#scan-for-all-objc_msgsend-xrefs)
  - :new: [Scan for Simple Symbol Wrappers](https://github.com/Soulghost/iblessing/blob/features/anti_wrapper/README.md#scan-for-symbol-wrappers)
 
- Generators
  - [Generate objc_msgSend Xrefs Query Server](https://github.com/Soulghost/iblessing#generate-objc_msgsend-xrefs-query-server)
  - [Generate IDA Scripts for objc_msgSend xrefs](https://github.com/Soulghost/iblessing#generate-ida-scripts-for-objc_msgsend-xrefs)
  - :new: [Generate IDA Scripts for objc function wrapper rename and prototype modification](https://github.com/Soulghost/iblessing/blob/features/anti_wrapper/README.md#genereate-ida-script-for-objc-runtime-function-rename-and-prototype-modification)

***If there are any errors, you can manully compile capstone and unicorn, then drag libcapstone.a and libunicorn.a to the Xcode project's vendor/libs.***

If all of this run successfully, you can find the binary in build directory:
```
> ls ./build
iblessing

> file ./build/iblessing
./build/iblessing: Mach-O 64-bit executable x86_64
```

# Documentation & Help
## Preview
```
$ iblessing -h

           ☠️
           ██╗██████╗ ██╗     ███████╗███████╗███████╗██╗███╗   ██╗ ██████╗
           ██║██╔══██╗██║     ██╔════╝██╔════╝██╔════╝██║████╗  ██║██╔════╝
           ██║██████╔╝██║     █████╗  ███████╗███████╗██║██╔██╗ ██║██║  ███╗
           ██║██╔══██╗██║     ██╔══╝  ╚════██║╚════██║██║██║╚██╗██║██║   ██║
           ██║██████╔╝███████╗███████╗███████║███████║██║██║ ╚████║╚██████╔╝
           ╚═╝╚═════╝ ╚══════╝╚══════╝╚══════╝╚══════╝╚═╝╚═╝  ╚═══╝ ╚═════╝

[***] iblessing iOS Security Exploiting Toolkit Beta 0.1.1 (http://blog.asm.im)
[***] Author: Soulghost (高级页面仔) @ (https://github.com/Soulghost)

Usage: iblessing [options...]
Options:
    -m, --mode             mode selection:
                                * scan: use scanner
                                * generator: use generator
    -i, --identifier       choose module by identifier:
                                * <scanner-id>: use specific scanner
                                * <generator-id>: use specific generator
    -f, --file             input file path
    -o, --output           output file path
    -l, --list             list available scanners
    -d, --data             extra data
    -h, --help             Shows this page
```

## Basic Concepts
### Scanner
A scanner is a component used to output analysis report through static and dynamic analysis of binary files, for example, the objc-msg-xref scanner can dynamiclly analyze most objc_msgSend cross references.

```
[*] Scanner List:
    - app-info: extract app infos
    - objc-class-xref: scan for class xrefs
    - objc-msg-xref: generate objc_msgSend xrefs record
    - predicate: scan for NSPredicate xrefs and sql injection surfaces
    - symbol-wrapper: detect symbol wrappers
```

### Generator
A generator is a component that performs secondary processing on the report generated by the scanner, for example, it can generate IDA scripts based on the the objc-msg-xref scanner's cross references report.

```
[*] Generator List:
    - ida-objc-msg-xref: generator ida scripts to add objc_msgSend xrefs from objc-msg-xref scanner's report
    - objc-msg-xref-server: server to query objc-msg xrefs
    - objc-msg-xref-statistic: statistics among objc-msg-send reports
```

## Basic Usage
### Scan for AppInfos
```
> iblessing -m scan -i app-info -f <path-to-app-bundle>
```

Let's take WeChat as an example:
```
> iblessing -m scan -i app-info -f WeChat.app
[*] set output path to /opt/one-btn/tmp/apps/WeChat/Payload
[*] input file is WeChat.app
[*] start App Info Scanner
[+] find default plist file Info.plist!
[*] find version info: Name: 微信(WeChat)
Version: 7.0.14(18E226)
ExecutableName: WeChat
[*] Bundle Identifier: com.tencent.xin
[*] the app allows HTTP requests **without** exception domains!
[+] find app deeplinks
 |-- wechat://
 |-- weixin://
 |-- fb290293790992170://
 |-- weixinapp://
 |-- prefs://
 |-- wexinVideoAPI://
 |-- QQ41C152CF://
 |-- wx703://
 |-- weixinULAPI://
[*] find app callout whitelist
 |-- qqnews://
 |-- weixinbeta://
 |-- qqnewshd://
 |-- qqmail://
 |-- whatsapp://
 |-- wxwork://
 |-- wxworklocal://
 |-- wxcphonebook://
 |-- mttbrowser://
 |-- mqqapi://
 |-- mqzonev2://
 |-- qqmusic://
 |-- tenvideo2://
 ...
[+] find 507403 string literals in binary
[*] process with string literals, this maybe take some time
[+] find self deeplinks URLs:
 |-- weixin://opennativeurl/devicerankview
 |-- weixin://dl/offlinepay/?appid=%@
 |-- weixin://opennativeurl/rankmyhomepage
 ...
 [+] find other deeplinks URLs:
 |-- wxpay://f2f/f2fdetail
 |-- file://%@?lang=%@&fontRatio=%.2f&scene=%u&version=%u&type=%llu&%@=%d&qqFaceFolderPath=%@&platform=iOS&netType=%@&query=%@&searchId=%@&isHomePage=%d&isWeAppMore=%d&subType=%u&extParams=%@&%@=%@&%@=%@
 ...
 [*] write report to path /opt/one-btn/tmp/apps/WeChat/Payload/WeChat.app_info.iblessing.txt
 
> ls -alh 
-rw-r--r--@ 1 soulghost  wheel    29K Jul 23 14:01 WeChat.app_info.iblessing.txt
```

### Scan for Class XREFs
***Notice: ARM64 Binaries Only***
```
iblessing -m scan -i objc-class-xref -f <path-to-binary> -d 'classes=<classname_to_scan>,<classname_to_scan>,...'
```

```
> restore-symbol WeChat -o WeChat.restored
> iblessing -m scan -i objc-class-xref -f WeChat.restored -d 'classes=NSPredicate'
[*] set output path to /opt/one-btn/tmp/apps/WeChat/Payload
[*] input file is WeChat
[+] detect mach-o header 64
[+] detect litten-endian
[*] start Objc Class Xref Scanner
  [*] try to find _OBJC_CLASS_$_NSPredicate
  [*] Step 1. locate class refs
	[+] find _OBJC_CLASS_$_NSPredicate at 0x108eb81d8
  [*] Step 2. find __TEXT,__text
	[+] find __TEXT,__text at 0x4000
  [*] Step 3. scan in __text
	[*] start disassembler at 0x100004000
	[*] \ 0x1002e1a50/0x1069d9874 (2.71%)	[+] find _OBJC_CLASS_$_NSPredicate ref at 0x1002e1a54
           ...
  [*] Step 4. symbolicate ref addresses
           [+] _OBJC_CLASS_$_NSPredicate -|
           [+] find _OBJC_CLASS_$_NSPredicate ref -[WCWatchNotificationMgr addYoCount:contact:type:] at 0x1002e1a54
           [+] find _OBJC_CLASS_$_NSPredicate ref -[NotificationActionsMgr handleSendMsgResp:] at 0x1003e0e28
           [+] find _OBJC_CLASS_$_NSPredicate ref -[FLEXClassesTableViewController searchBar:textDidChange:] at 0x1004a090c
           [+] find _OBJC_CLASS_$_NSPredicate ref +[GameCenterUtil parameterValueForKey:fromQueryItems:] at 0x1005a823c
           [+] find _OBJC_CLASS_$_NSPredicate ref +[GameCenterUtil getNavigationBarColorForUrl:defaultColor:] at 0x1005a8cd8
           ...
```

### Scan for All objc_msgSend XREFs
***Notice: ARM64 Binaries Only***

#### Simple Mode
```
iblessing -m scan -i objc-msg-xref -f <path-to-binary>
```

#### Anti-Wrapper Mode
```
iblessing -m scan -i objc-msg-xref -f WeChat -d 'antiWrapper=1'
```
The anti-wrapper mode will detect objc_msgSend wrappers and make transforms, such as:
```arm
; __int64 __usercall objc_msgSend_X0_X22_X20@<X0>(void *obj@<X0>, const char *sel@<X22>, id anyObj@<X20>, ...)
objc_msgSend_X0_X22_X20:
MOV             X1, X22
MOV             X2, X20
B               objc_msgSend
```

#### Usage Example:
```
> iblessing -m scan -i objc-msg-xref -f WeChat -d 'antiWrapper=1'
[*] set output path to /opt/one-btn/tmp/apps/WeChat/Payload
[*] input file is WeChat
[+] detect mach-o header 64
[+] detect litten-endian

[*] !!! Notice: enter anti-wrapper mode, start anti-wrapper scanner
[*] start Symbol Wrapper Scanner
  [*] try to find wrappers for_objc_msgSend
  [*] Step1. find __TEXT,__text
	[+] find __TEXT,__text at 0x100004000
	[+] mapping text segment 0x100000000 ~ 0x107cb0000 to unicorn engine
  [*] Step 2. scan in __text
	[*] start disassembler at 0x100004000
	[*] / 0x1069d986c/0x1069d9874 (100.00%)
	[*] reach to end of __text, stop
  [+] anti-wrapper finished
  
[*] start ObjcMethodXrefScanner Exploit Scanner
  [*] Step 1. realize all app classes
	[*] realize classes 14631/14631 (100.00%)
	[+] get 667318 methods to analyze
  [*] Step 2. dyld load non-lazy symbols
  [*] Step 3. track all calls
	[*] progress: 667318 / 667318 (100.00%)
  [*] Step 4. serialize call chains to file
  [*] saved to /opt/one-btn/tmp/apps/WeChat/Payload/WeChat_method-xrefs.iblessing.txt
  
> ls -alh WeChat_method-xrefs.iblessing.txt
-rw-r--r--  1 soulghost  wheel    63M Jul 23 14:46 WeChat_method-xrefs.iblessing.txt 

> head WeChat_method-xrefs.iblessing.txt
iblessing methodchains,ver:0.2;
chainId,sel,prefix,className,methodName,prevMethods,nextMethods
182360,0x1008a0ab8,+[A8KeyControl initialize],+,A8KeyControl,initialize,[],[4429#0x1008a1064@4376#0x1008a1050@13769#0x1008a10d0]
182343,0x1008a0ad0,+[A8KeyControl_QueryStringTransferCookie initialize],+,A8KeyControl_QueryStringTransferCookie,initialize,[],[4429#0x1008a1064@4376#0x1008a1050@13769#0x1008a10d0]
145393,0x1008c2220,+[A8KeyResultCookieWriter initWithDomain:weakWebView:andCompleteBlock:],+,A8KeyResultCookieWriter,initWithDomain:weakWebView:andCompleteBlock:,[145386#0x10036367c],[]
145396,0x1008c3df8,+[A8KeyResultCookieWriter setA8KeyCookieExpireTime:],+,A8KeyResultCookieWriter,setA8KeyCookieExpireTime:,[145386#0x1003636e8],[]
145397,0x1008c27e8,+[A8KeyResultCookieWriter writeCompleteMarkerCookieValue:forKey:],+,A8KeyResultCookieWriter,writeCompleteMarkerCookieValue:forKey:,[145386#0x10036380c],[]
253456,0x0,+[AAOperationReq init],+,AAOperationReq,init,[253455#0x1039a9d30],[]
253457,0x0,+[AAOperationReq setBaseRequest:],+,AAOperationReq,setBaseRequest:,[253455#0x1039a9d8c],[]
186847,0x0,+[AAOperationRes length],+,AAOperationRes,length,[186845#0x10342aa54],[]
```

The report can be used by the generators, now let's go.

### Generate objc_msgSend Xrefs Query Server
You can start a server through iblessing's objc-msg-xref-server generator to query all objc_msgSend xrefs.
```
iblessing -m generator -i objc-msg-xref-server -f <path-to-report-generated-by-objc-msg-xref-scanner>
```

#### Specify the Listening Host and Port
The default listening address is 127.0.0.1:2345, you can specify it by -d option.
```
iblessing -m generator -i objc-msg-xref-server -f WeChat_method-xrefs.iblessing.txt -d 'host=0.0.0.0;port=12345'
```

#### Usage Example
***Notice: the objc-msg-xref is based on unicorn, to speed up the analyze, we do not follow any calls, so the result is partially missing.***
```
> iblessing -m generator -i objc-msg-xref-server -f WeChat_method-xrefs.iblessing.txt
[*] set output path to /opt/one-btn/tmp/apps/WeChat/Payload
[*] input file is WeChat_method-xrefs.iblessing.txt
[*] start ObjcMsgXREFServerGenerator
  [*] load method-chain db for version iblessing methodchains,ver:0.2;
  [*] table keys chainId,sel,prefix,className,methodName,prevMethods,nextMethods
	[-] bad line 104467,0x0,+[TPLock P,	],+,TPLock,P,	,[104426#0x1043b9904],[]
	[-] bad line 114905,0x0,?[0x108ce1578 (,],?,0x108ce1578,(,,[114900#0x1011e8c68],[]
	[-] bad line 104464,0x0,?[? P,	],?,?,P,	,[104426#0x1043b98a8],[]
	[-] bad line 139234,0x0,?[? X
	[-] bad line ],?,?,X
	[-] bad line ,[139205#0x1013c222c],[]
	[+] load storage from disk succeeded!
  [*] listening on http://127.0.0.1:2345
```
Next you can open `http://127.0.0.1:2345` with a browser to query any objc_msgSend xrefs you like:
![](https://github.com/Soulghost/iblessing/blob/master/resource/images/objc_msgSend_xref_server.png?raw=true)

### Generate IDA Scripts for objc_msgSend xrefs
You can add objc_msgSend xrefs generated from objc-msg-xref scanner to make your reverse engineering journey more faster and comfortable.
```
iblessing -m generator -i ida-objc-msg-xref -f <path-to-report-generated-by-objc-msg-xref-scanner>
```

#### Usage Example
***Notice: the objc-msg-xref is based on unicorn, to speed up the analyze, we do not follow any calls, so the result is partially missing.***
```
> iblessing -m generator -i ida-objc-msg-xref -f WeChat_method-xrefs.iblessing.txt
[*] set output path to /opt/one-btn/tmp/apps/WeChat/Payload
[*] input file is WeChat_method-xrefs.iblessing.txt
[*] start IDAObjMsgXREFGenerator
  [*] load method-chain db for version iblessing methodchains,ver:0.2;
  [*] table keys chainId,sel,prefix,className,methodName,prevMethods,nextMethods
	[-] bad line 104467,0x0,+[TPLock P,	],+,TPLock,P,	,[104426#0x1043b9904],[]
	[-] bad line 114905,0x0,?[0x108ce1578 (,],?,0x108ce1578,(,,[114900#0x1011e8c68],[]
	[-] bad line 104464,0x0,?[? P,	],?,?,P,	,[104426#0x1043b98a8],[]
	[-] bad line 139234,0x0,?[? X
	[-] bad line ],?,?,X
	[-] bad line ,[139205#0x1013c222c],[]
	 [+] load storage from disk succeeded!
  [*] Generating XREF Scripts ...
  [*] saved to /opt/one-btn/tmp/apps/WeChat/Payload/WeChat_method-xrefs.iblessing.txt_ida_objc_msg_xrefs.iblessing.py
  
> ls -alh WeChat_method-xrefs.iblessing.txt_ida_objc_msg_xrefs.iblessing.py
-rw-r--r--  1 soulghost  wheel    23M Jul 23 16:16 WeChat_method-xrefs.iblessing.txt_ida_objc_msg_xrefs.iblessing.py

> head WeChat_method-xrefs.iblessing.txt_ida_objc_msg_xrefs.iblessing.py
def add_objc_xrefs():
    ida_xref.add_cref(0x10036367c, 0x1008c2220, XREF_USER)
    ida_xref.add_cref(0x1003636e8, 0x1008c3df8, XREF_USER)
    ida_xref.add_cref(0x10036380c, 0x1008c27e8, XREF_USER)
    ida_xref.add_cref(0x103add16c, 0x700006e187a8, XREF_USER)
    ida_xref.add_cref(0x102cbee0c, 0x101143ee8, XREF_USER)
    ida_xref.add_cref(0x10085c92c, 0x1005e9360, XREF_USER)
    ida_xref.add_cref(0x10085c8bc, 0x1005e9274, XREF_USER)
    ida_xref.add_cref(0x10085c8dc, 0x1005e92bc, XREF_USER)
    ida_xref.add_cref(0x10085c8cc, 0x1005e9298, XREF_USER)
```

Next open your IDA -> File -> Script File and load the script, this step may take a long time. And when it is done, you can find many xrefs for objc method:
![](https://github.com/Soulghost/iblessing/blob/master/resource/images/ida_objc_msgSend_xrefs.png?raw=true)

### Scan for symbol wrappers
A Mach-O file may contain multiple wrappers of commonly used dynamic library imported symbols, such as:
```arm
__text:00000001003842D8 sub_1003842CC                           ; CODE XREF: -[BDARVLynxTracker eventV3:params:adExtraData:]+168↑p
__text:00000001003842D8                                         ; -[BDARVLynxTracker eventV3:params:adExtraData:]+214↑p ...
__text:00000001003842D8                 MOV             X1, X27
__text:00000001003842DC                 MOV             X2, X19
__text:00000001003842E0                 B               objc_msgSend
```

We can convert the wrapper by usercall:
```arm
__text:00000001003842CC ; id __usercall objc_msgSend_61@<X0>(id@<X23>, const char *@<X28>, ...)
__text:00000001003842CC _objc_msgSend_61                        ; CODE XREF: -[BDARVLynxTracker eventV3:params:adExtraData:]+2CC↑p
__text:00000001003842CC                                         ; -[BDARVLynxTracker eventV3:params:adExtraData:]+320↑p ...
__text:00000001003842CC                 MOV             X0, X23
__text:00000001003842D0                 MOV             X1, X28
__text:00000001003842D4                 B               objc_msgSend
```

The scanner can generate a report to record all wrappers, then you can use `ida-symbol-wrapper-naming` generator to generate ida scripts and implement this wrapper rename and prototype change.

#### How to Use
```
iblessing -m scan -i symbol-wrapper -f <path-to-binary> -d 'symbols=_objc_msgSend,_objc_retain,_objc_release'
iblessing -m scan -i symbol-wrapper -f <path-to-binary> -d 'symbols=*'
```

#### Usage Example
We will take TikTok China as an example:
```
> iblessing -m scan -i symbol-wrapper -f /opt/one-btn/tmp/apps/抖音短视频/Payload/Aweme -d 'symbols=*'
[*] set output path to /Users/soulghost/Desktop/git/iblessing-public/iblessing/build/Debug
[*] input file is /opt/one-btn/tmp/apps/抖音短视频/Payload/Aweme
[+] detect mach-o header 64
[+] detect litten-endian
[*] start Symbol Wrapper Scanner
  [*] try to find wrappers for_objc_autoreleaseReturnValue, _objc_msgSend, _objc_release, _objc_releaseAndReturn, _objc_retain, _objc_retainAutorelease, _objc_retainAutoreleaseAndReturn, _objc_retainAutoreleaseReturnValue, _objc_retainAutoreleasedReturnValue
  [*] Step1. find __TEXT,__text
	[+] find __TEXT,__text at 0x100004000
	[+] mapping text segment 0x100000000 ~ 0x106da0000 to unicorn engine
  [*] Step 2. scan in __text
	[*] start disassembler at 0x100004000
	[*] / 0x106b68a54/0x106b68a58 (100.00%)
	[*] reach to end of __text, stop

  [*] Step 3. serialize wrapper graph to file
	[*] saved to /Users/soulghost/Desktop/git/iblessing-public/iblessing/build/Debug/Aweme_wrapper-graph.iblessing.txt

> head Aweme_wrapper-graph.iblessing.txt
iblessing symbol-wrappers,ver:0.1;
wrapperId;address;name;prototype
0;0x100022190;_objc_retainAutoreleasedReturnValue;id __usercall f@<x0>(id@<x0>)
1;0x100022198;_objc_retainAutoreleasedReturnValue;id __usercall f@<x0>(id@<x0>)
2;0x1000221a0;_objc_release;id __usercall f@<x0>(id@<x22>)
3;0x1000221a8;_objc_msgSend;id __usercall f@<x0>(id@<x0>, const char*@<x20>, ...)
4;0x100022448;_objc_release;id __usercall f@<x0>(id@<x21>)
5;0x10009c19c;_objc_autoreleaseReturnValue;id __usercall f@<x0>(id@<x0>)
6;0x1000b6f94;_objc_msgSend;id __usercall f@<x0>(id@<x0>, const char*@<x1>, ...)
7;0x100100248;_objc_autoreleaseReturnValue;id __usercall f@<x0>(id@<x0>)
```

Next, we can generate ida scripts from this report.

### Genereate IDA Script for Objc Runtime Function Rename and Prototype Modification 
```
iblessing -m generator -i ida-symbol-wrapper-naming -f <path-to-report-from-symbol-wrapper>
```

#### Usage Example
```
> iblessing -m generator -i ida-symbol-wrapper-naming -f Aweme_wrapper-graph.iblessing.txt
[*] set output path to /Users/soulghost/Desktop/git/iblessing-public/iblessing/build/Debug
[*] input file is Aweme_wrapper-graph.iblessing.txt
[*] start IDAObjMsgXREFGenerator
  [*] load symbol-wrappers db for version iblessing symbol-wrappers,ver:0.1;
  [*] table keys wrapperId;address;name;prototype
  [*] Generating Naming Scripts ...
  [*] saved to /Users/soulghost/Desktop/git/iblessing-public/iblessing/build/Debug/Aweme_wrapper-graph.iblessing.txt_ida_symbol_wrapper_naming.iblessing.py
  
> head Aweme_wrapper-graph.iblessing.txt_ida_symbol_wrapper_naming.iblessing.py
def namingWrappers():
    idc.set_name(0x100022190, '_objc_retainAutoreleasedReturnValue', ida_name.SN_FORCE)
    idc.apply_type(0x100022190, idc.parse_decl('id __usercall f@<x0>(id@<x0>)', idc.PT_SILENT))
    idc.set_name(0x100022198, '_objc_retainAutoreleasedReturnValue', ida_name.SN_FORCE)
    idc.apply_type(0x100022198, idc.parse_decl('id __usercall f@<x0>(id@<x0>)', idc.PT_SILENT))
    idc.set_name(0x1000221a0, '_objc_release', ida_name.SN_FORCE)
    idc.apply_type(0x1000221a0, idc.parse_decl('id __usercall f@<x0>(id@<x22>)', idc.PT_SILENT))
    idc.set_name(0x1000221a8, '_objc_msgSend', ida_name.SN_FORCE)
    idc.apply_type(0x1000221a8, idc.parse_decl('id __usercall f@<x0>(id@<x0>, const char*@<x20>, ...)', idc.PT_SILENT))
    idc.set_name(0x100022448, '_objc_release', ida_name.SN_FORCE)
```

Next open your IDA -> File -> Script File and load the script, this step may take a long time. And when it is done, You can observe some decompiled code changes:
![](https://github.com/Soulghost/iblessing/blob/features/anti_wrapper/resource/images/ida_wrapped_call_before.png?raw=true)

:arrow_down: :arrow_down: :arrow_down:

![](https://github.com/Soulghost/iblessing/blob/features/anti_wrapper/resource/images/ida_wrapped_call_after.png?raw=true)

# To be continued
