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
    void *tiny = malloc(0x10);
    void *small = malloc(0x400);
    void *large = malloc(0x10000);
    free(tiny);
    free(small);
    free(large);
    printf("my malloc chunks %p %p %p\n", tiny, small, large);
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
