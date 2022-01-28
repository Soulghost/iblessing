//
//  ViewController.m
//  TestXPC
//
//  Created by soulghost on 2020/6/11.
//  Copyright © 2020 soulghost. All rights reserved.
//

#import "ViewController.h"
#import "XPCService.h"
#import "XPCServiceProtocol.h"

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];

    setuid(0);
    // Do any additional setup after loading the view.
    NSXPCConnection *connection;
    id<XPCServiceProtocol> service;
    connection = [[NSXPCConnection alloc]initWithServiceName:@"com.soulghost.TestXPC"];
    connection.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(XPCServiceProtocol)];
    connection.interruptionHandler = ^{
        NSLog(@"interruption");
    };
    connection.invalidationHandler = ^{
        NSLog(@"invalidation");
    };
    [connection resume];
    service = [connection remoteObjectProxyWithErrorHandler:^(NSError * _Nonnull error) {
        NSLog(@"%@",error);
    }];
    [service upperCaseString:@"heyyyy" withReply:^(NSString *result) {
        NSLog(@"%@",result);
    }];
}


- (void)setRepresentedObject:(id)representedObject {
    [super setRepresentedObject:representedObject];
    // Update the view, if already loaded.
}


@end
