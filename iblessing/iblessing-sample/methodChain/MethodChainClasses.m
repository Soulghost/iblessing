//
//  MethodChainClasses.m
//  iblessing-sample
//
//  Created by soulghost on 2020/7/25.
//  Copyright © 2020 soulghost. All rights reserved.
//

#import "MethodChainClasses.h"

@implementation IBSRoot

+ (void)rootClassMethodWithParamsA:(id)a b:(int)b c:(Class)c {
    
}

- (void)rootClassInstanceMethodWithParamsD:(id)a e:(int)s f:(id)t {
    
}

@end


@implementation IBSCallTester

+ (void)testPrimaryCallToRootClassMethodAncestor {
    [IBSRoot rootClassMethodWithParamsA:nil b:1 c:[IBSRoot class]];
}

+ (void)testReflectionCallToRootClassMethodAncestor {
    [NSClassFromString(@"IBSRoot") rootClassMethodWithParamsA:nil b:1 c:[IBSRoot class]];
}

+ (void)testInstanceCallToRootClassMethodAncestor {
    [[[[IBSRoot alloc] init] class] rootClassMethodWithParamsA:nil b:1 c:[IBSRoot class]];
}

- (void)testSelfCall {
    [self selfCallChain1];
}

- (void)selfCallChain1 {
    [self selfCallChain2];
}

- (void)selfCallChain2 {
    [self selfCallChain3];
}

- (void)selfCallChain3 {
    NSLog(@"self call end");
}

- (void)testLoop {
    [self testLoop];
}

- (void)testIvarCall {
    [self.root rootClassInstanceMethodWithParamsD:nil e:1 f:nil];
}

- (void)testAllocateCall {
    IBSRoot *root = [[IBSRoot alloc] init];
    [root rootClassInstanceMethodWithParamsD:nil e:1 f:nil];
}

@end
