//
//  ViewController.m
//  iblessing-sample
//
//  Created by soulghost on 2020/7/25.
//  Copyright © 2020 soulghost. All rights reserved.
//

#import "ViewController.h"
#import <objc/runtime.h>

void test_entry(void) {
    int a = 100;
    int b = 200;
    printf("xxx %d\n", a + b);
}

void listClasses(void) {
    int count = objc_getClassList(NULL, 0);
    printf("[*] current class count %d\n", count);
    
    __unsafe_unretained Class *classes = (__unsafe_unretained Class *)malloc(sizeof(Class) * count);
    objc_getClassList(classes, count);

    for (int i = 0; i < count; i++) {
        __unsafe_unretained Class clazz = classes[i];
        const char *className = class_getName(clazz);
        __unsafe_unretained Class superclass = class_getSuperclass(clazz);
        printf("[*] found class: %s", className);
        while (superclass != NULL) {
            printf(" -> %s", class_getName(superclass));
            superclass = class_getSuperclass(superclass);
        }
        printf(" at %p\n", clazz);
    }

    free(classes);
}

void testObjc() {
    NSMutableDictionary *md = [NSMutableDictionary new];
    printf("allocate dict at %p\n", md);
    [md setObject:@"xxx" forKey:@"yyy"];
    [md setObject:@"hahaha" forKey:@"zzz"];
    [md enumerateKeysAndObjectsUsingBlock:^(id  _Nonnull key, id  _Nonnull obj, BOOL * _Nonnull stop) {
        printf("dict key %s, value %s\n", [key UTF8String], [[obj description] UTF8String]);
    }];
    NSLog(@"dict contents %s\n", md);
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
