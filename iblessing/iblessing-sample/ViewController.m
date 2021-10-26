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
    for (int i = 0; i < 100; i++) {
        void *addr = malloc(i);
        memset(addr, 0x41, i);
        printf("xx malloc(%d) addr %p\n", i, addr);
        free(addr);
    }

    void *addr = malloc(0x10000);
    free(addr);
    addr = malloc(16);
    free(addr);
    return 233;
}

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    test_entry();
}


@end
