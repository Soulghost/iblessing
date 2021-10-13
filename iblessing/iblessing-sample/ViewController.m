//
//  ViewController.m
//  iblessing-sample
//
//  Created by soulghost on 2020/7/25.
//  Copyright © 2020 soulghost. All rights reserved.
//

#import "ViewController.h"

void test_entry(void) {
    int a = 100;
    int b = 200;
    printf("xxx %d\n", a + b);
}

uint64_t test_malloc(void) {
    void *addr = malloc(1024);
    void *addr2 = malloc(2048);
    void *addr3 = malloc(4096);
    memset(addr, 0x41, 1024);
    memset(addr2, 0x42, 2048);
    memset(addr3, 0x43, 4096);
    printf("malloc addr %p %p %p\n", addr, addr2, addr3);
//    free(addr);
//    free(addr2);
//    free(addr3);
    return addr;
}

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    test_entry();
}


@end
