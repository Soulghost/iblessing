           ☠️
           ██╗██████╗ ██╗     ███████╗███████╗███████╗██╗███╗   ██╗ ██████╗
           ██║██╔══██╗██║     ██╔════╝██╔════╝██╔════╝██║████╗  ██║██╔════╝
           ██║██████╔╝██║     █████╗  ███████╗███████╗██║██╔██╗ ██║██║  ███╗
           ██║██╔══██╗██║     ██╔══╝  ╚════██║╚════██║██║██║╚██╗██║██║   ██║
           ██║██████╔╝███████╗███████╗███████║███████║██║██║ ╚████║╚██████╔╝
           ╚═╝╚═════╝ ╚══════╝╚══════╝╚══════╝╚══════╝╚═╝╚═╝  ╚═══╝ ╚═════╝

# iblessing
`iblessing` is an iOS security exploiting toolkit, it mainly includes **application information collection**, **static analysis** and **dynamic analysis**.
`iblessing` is based on [unicorn engine](https://github.com/unicorn-engine/unicorn) and [capstone engine](https://github.com/aquynh/capstone).

# How to Compile
To get started compiling iblessing, please follow the steps below:
```bash
git clone https://github.com/Soulghost/iblessing
cd iblessing
sh compile.sh
```

If all of this run successfully, you can find the binary in build directory:
```bash
> ls ./build
iblessing

> file ./build/iblessing
./build/iblessing: Mach-O 64-bit executable x86_64
```

# Documentation & Help
## Preview
```bash
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
TODO

### Generator
TODO
