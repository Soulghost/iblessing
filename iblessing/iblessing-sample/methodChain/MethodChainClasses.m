//
//  MethodChainClasses.m
//  iblessing-sample
//
//  Created by soulghost on 2020/7/25.
//  Copyright © 2020 soulghost. All rights reserved.
//

#import "MethodChainClasses.h"

@implementation IBSRoot

+ (void)rootClassMethodCallFromPrimary {
    
}

+ (void)rootClassMethodCallFromReflection {
    
}

+ (void)rootClassMethodCallFromInstanceClass {
    
}

- (void)rootInstanceMethodCallFromIvar {
    
}

- (void)rootInstanceMethodCallFromAllocate {
    
}

@end


@implementation IBSCallTester

+ (void)testPrimaryCallToRootClassMethodAncestor {
    [IBSRoot rootClassMethodCallFromPrimary];
}

+ (void)testReflectionCallToRootClassMethodAncestor {
    [NSClassFromString(@"IBSRoot") rootClassMethodCallFromReflection];
}

+ (void)testInstanceCallToRootClassMethodAncestor {
    [[[[IBSRoot alloc] init] class] rootClassMethodCallFromInstanceClass];
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

- (void)testAllocateCall {
    IBSRoot *root = [[IBSRoot alloc] init];
    [root rootInstanceMethodCallFromAllocate];
}

- (void)testIvarCall {
    [self.root rootInstanceMethodCallFromIvar];
}

@end
