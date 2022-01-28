//
//  XPCService.m
//  XPCService
//
//  Created by soulghost on 2020/6/10.
//  Copyright © 2020 soulghost. All rights reserved.
//

#import "XPCService.h"

@implementation XPCService

// This implements the example protocol. Replace the body of this class with the implementation of this service's protocol.
- (void)upperCaseString:(NSString *)aString withReply:(void (^)(NSString *))reply {
    NSString *response = [aString uppercaseString];
    reply(response);
}

@end
