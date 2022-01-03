# mem regions
0x300000000 - 0x3f..   stack
0x400000000 - 0x4f..   mmap
0x500000000 - 0x5f..   host alloc
0x600000000 (1 page)   common trampolines (nop, magic return)
0x700000000 - 0x7f..   svc trampoline
0x800000000 - 0x8f..   dummy PAGE_ZERO
0x900000000 - 0x96..   executable (slide = 0x800000000)
0x980000000 - 0x9f1cd3fff sharedcache (slide = 0x800000000)
0xfffff0000 - 0xfffffffff kernel common page