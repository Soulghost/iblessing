//
//  ViewController.m
//  iblessing-sample
//
//  Created by soulghost on 2020/7/25.
//  Copyright © 2020 soulghost. All rights reserved.
//

#import "ViewController.h"
#import <objc/runtime.h>
#include "xpc.h"
#include <sys/sysctl.h>

void test_entry(void) {
    int a = 100;
    int b = 200;
    printf("xxx %d\n", a + b);
}

void testNSLog(void) {
    NSLog(@"=============================<<<<>");
}

void testNetwork(void) {
    NSURLSession *sess = [NSURLSession sharedSession];
    printf("[~] the session is %p, %s\n", sess, sess.description.UTF8String);
}

void testXPC(void) {
    printf("[+] prepare for connect to com.apple.audio.AudioFileServer\n");
    static xpc_connection_t conn;
    conn = xpc_connection_create_mach_service("com.apple.audio.AudioFileServer", NULL, XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);
    xpc_connection_set_event_handler(conn, ^(xpc_object_t object) {
        printf("[*] connect result %p %s\n", object, xpc_copy_description(object));
    });
    xpc_connection_resume(conn);
    
    xpc_object_t req = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_uint64(req, "type", 'read');
    xpc_dictionary_set_uint64(req, "numbytes", 1);
    xpc_dictionary_set_uint64(req, "numpackets", 1);
    xpc_dictionary_set_int64(req, "startingPacket", 1);
    xpc_object_t reply = xpc_connection_send_message_with_reply_sync(conn, req);
    
    printf("[+] reply desc %s\n", xpc_copy_description(reply));
    NSLog(@"[+] reply desc %s\n", xpc_copy_description(reply));
    
    xpc_dictionary_apply(reply, ^bool(const char *key, xpc_object_t value) {
        if (strcmp(key, "status") == 0) {
            int64_t val = xpc_int64_get_value(value);
            val = CFSwapInt64(val) >> 32;
            char *str = (char *)malloc(sizeof(int64_t) + 1);
            memcpy(str, &val, sizeof(int64_t));
            str[sizeof(int64_t)] = '\0';
            printf("[+] status: %s\n", str);
            free(str);
        } else {
            printf("\t[+] %s -> %s\n", key, xpc_copy_description(value));
        }
        
        return true;
    });
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

void testDispatchOnce() {
    static dispatch_once_t onceToken;
    printf("enter dispatch_once call %p\n", &onceToken);
    dispatch_once(&onceToken, ^{
        printf("I should only be called once\n");
    });
    printf("end of dispatch once call\n");
}

void testDispatchSync() {
    printf("1. before async call\n");
    dispatch_async(dispatch_get_global_queue(0, 0), ^{
        printf("3. got async call\n");
    });
    printf("2. wait for async call\n");
}

void testDispatchAfter() {
    printf("register for 0.5s delay\n");
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        printf("after 0.5s I'm called\n");
    });
    printf("wait for ~0.5s before I'm called\n");
}

void testObjc() {
    NSMutableDictionary *md = [NSMutableDictionary new];
    printf("allocate dict at %p\n", md);
    [md setObject:@"xxx" forKey:@"yyy"];
    [md setObject:@"hahaha" forKey:@"zzz"];
    [md enumerateKeysAndObjectsUsingBlock:^(id  _Nonnull key, id  _Nonnull obj, BOOL * _Nonnull stop) {
        printf("dict key %s, value %s\n", [key UTF8String], [[obj description] UTF8String]);
    }];
    NSLog(@"dict contents %@\n", md);
}

uint64_t test_malloc(void) {
    for (int i = 0; i < 100; i++) {
        void *tiny = malloc(0x10);
        memset(tiny, 0xAA, 0x10);
        free(tiny);
        void *small = malloc(0x400);
        memset(small, 0xBB, 0x400);
        free(small);
        printf("alloc and free chunks tiny %p, small %p\n", tiny, small);
    }
    
//    void *large = malloc(0x10000);
//    free(large);
//    printf("my malloc chunks %p %p %p\n", tiny, small, large);
    return 233;
}

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    
    const char *name = strdup("kern.osvariant_status");
    uint64_t oldp;
    uint64_t oldlenp = 0x8;
    int ret = sysctlbyname(name, &oldp, (size_t *)&oldlenp, NULL, NULL);
    
    test_entry();
}


@end
